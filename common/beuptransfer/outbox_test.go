package beuptransfer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
)

var testEpoch = strings.Repeat("1", 32)
var testCredential = strings.Repeat("a", 64)
var ctx = context.Background()

type memoryStore struct {
	data          []byte
	fail          bool
	writeThenFail bool
}

func (s *memoryStore) Load() ([]byte, error) { return append([]byte{}, s.data...), nil }
func (s *memoryStore) Save(b []byte) error {
	if s.fail {
		if s.writeThenFail {
			s.data = append([]byte{}, b...)
		}
		return errors.New("injected fsync failure")
	}
	s.data = append([]byte{}, b...)
	return nil
}

type receiver struct {
	batches                       map[string]string
	up, down, calls               int64
	lostResponse, offline, badAck bool
	hook                          func()
}

func (r *receiver) Commit(_ context.Context, b Batch) (Ack, error) {
	r.calls++
	if r.offline {
		return Ack{}, errors.New("offline")
	}
	if r.batches == nil {
		r.batches = map[string]string{}
	}
	key := fmt.Sprintf("%s:%s:%d", b.Scope, b.Epoch, b.Sequence)
	if old, ok := r.batches[key]; ok {
		if old != b.Digest {
			return Ack{}, errors.New("payload conflict")
		}
	} else {
		r.batches[key] = b.Digest
		for _, e := range b.Entries {
			r.up += e.Upload
			r.down += e.Download
		}
	}
	if r.hook != nil {
		r.hook()
	}
	if r.lostResponse {
		r.lostResponse = false
		return Ack{}, errors.New("SQL committed, response lost")
	}
	a := ackFor(b)
	if r.badAck {
		a.Digest = strings.Repeat("b", 64)
	}
	return a, nil
}
func setup(t *testing.T) (*Outbox, *memoryStore, *receiver) {
	t.Helper()
	s := &memoryStore{}
	r := &receiver{}
	o, e := Open(s, r, "vless_42", testEpoch)
	if e != nil {
		t.Fatal(e)
	}
	return o, s, r
}
func total(up, down int64) []Sample { return []Sample{{12, testCredential, up, down}} }

func TestLostResponseRetainsExactBatchAndReplaysOnce(t *testing.T) {
	o, s, r := setup(t)
	r.lostResponse = true
	if _, e := o.Flush(ctx, total(17, 23)); e == nil {
		t.Fatal("expected lost response")
	}
	if r.up != 17 || o.state.Pending == nil {
		t.Fatal("batch not retained")
	}
	o, e := Open(s, r, "vless_42", testEpoch)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = o.Replay(ctx); e != nil {
		t.Fatal(e)
	}
	if r.up != 17 || r.down != 23 || o.state.Pending != nil {
		t.Fatal("replay double counted")
	}
	if _, e = o.Flush(ctx, total(20, 30)); e != nil {
		t.Fatal(e)
	}
	if r.up != 20 || r.down != 30 {
		t.Fatal("subsequent delta incorrect")
	}
}
func TestOfflinePersistsBeforeFirstNetworkAttempt(t *testing.T) {
	o, s, r := setup(t)
	r.offline = true
	if _, e := o.Flush(ctx, total(17, 23)); e == nil {
		t.Fatal("offline accepted")
	}
	var j journal
	if e := json.Unmarshal(s.data, &j); e != nil || j.Pending == nil {
		t.Fatal("write ahead missing")
	}
	r.offline = false
	if _, e := o.Replay(ctx); e != nil {
		t.Fatal(e)
	}
	if r.up != 17 {
		t.Fatal("pending lost")
	}
}
func TestSaveFailureBeforeSendCannotDropCounters(t *testing.T) {
	o, s, r := setup(t)
	s.fail = true
	if _, e := o.Flush(ctx, total(17, 23)); !errors.Is(e, ErrUncertain) {
		t.Fatal(e)
	}
	if r.calls != 0 {
		t.Fatal("sent before durable write")
	}
	if _, e := o.Flush(ctx, total(30, 40)); !errors.Is(e, ErrUncertain) {
		t.Fatal("uncertain writer continued")
	}
	s.fail = false
	o, e := Open(s, r, "vless_42", testEpoch)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = o.Flush(ctx, total(30, 40)); e != nil {
		t.Fatal(e)
	}
	if r.up != 30 || r.down != 40 {
		t.Fatal("live cumulative counters lost")
	}
}
func TestUncertainWriteAfterRenameReopensPersistedBatch(t *testing.T) {
	o, s, r := setup(t)
	s.fail = true
	s.writeThenFail = true
	if _, e := o.Flush(ctx, total(9, 8)); !errors.Is(e, ErrUncertain) {
		t.Fatal(e)
	}
	if r.calls != 0 {
		t.Fatal("sent uncertain batch")
	}
	s.fail = false
	o, e := Open(s, r, "vless_42", testEpoch)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = o.Replay(ctx); e != nil {
		t.Fatal(e)
	}
	if r.up != 9 {
		t.Fatal("persisted batch missing")
	}
}
func TestCommitFollowedByJournalFailureRetriesWithoutDuplication(t *testing.T) {
	o, s, r := setup(t)
	r.hook = func() { s.fail = true }
	if _, e := o.Flush(ctx, total(5, 6)); !errors.Is(e, ErrUncertain) {
		t.Fatal(e)
	}
	r.hook = nil
	s.fail = false
	o, e := Open(s, r, "vless_42", testEpoch)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = o.Replay(ctx); e != nil {
		t.Fatal(e)
	}
	if r.up != 5 || r.down != 6 {
		t.Fatal("SQL acknowledgement replay double counted")
	}
}
func TestAcknowledgementBoundToScopeGenerationSequenceAndDigest(t *testing.T) {
	o, _, r := setup(t)
	r.badAck = true
	if _, e := o.Flush(ctx, total(1, 2)); e == nil {
		t.Fatal("wrong acknowledgement accepted")
	}
	if o.state.Pending == nil || o.state.Next != 1 {
		t.Fatal("wrong acknowledgement consumed batch")
	}
	r.badAck = false
	if _, e := o.Replay(ctx); e != nil {
		t.Fatal(e)
	}
	if r.up != 1 {
		t.Fatal("retry double counted")
	}
}
func TestCounterResetAndDisappearanceBlock(t *testing.T) {
	o, _, _ := setup(t)
	if _, e := o.Flush(ctx, total(7, 8)); e != nil {
		t.Fatal(e)
	}
	if _, e := o.Flush(ctx, total(6, 8)); !errors.Is(e, ErrEpoch) {
		t.Fatal(e)
	}
	if _, e := o.Flush(ctx, nil); e == nil {
		t.Fatal("retired counter silently discarded")
	}
}
func TestGenerationChangeRequiresReconciliation(t *testing.T) {
	o, s, r := setup(t)
	if _, e := o.Flush(ctx, total(1, 2)); e != nil {
		t.Fatal(e)
	}
	if _, e := Open(s, r, "vless_42", strings.Repeat("2", 32)); !errors.Is(e, ErrEpoch) {
		t.Fatal(e)
	}
}
func TestInvalidSnapshotsRejectedBeforeSend(t *testing.T) {
	for _, rows := range [][]Sample{{{0, testCredential, 1, 2}}, {{12, "raw-secret", 1, 2}}, {{12, testCredential, -1, 2}}, {{12, testCredential, 1, 2}, {12, testCredential, 1, 2}}} {
		o, _, r := setup(t)
		if _, e := o.Flush(ctx, rows); e == nil {
			t.Fatal("invalid sample accepted")
		}
		if r.calls != 0 {
			t.Fatal("invalid sample sent")
		}
	}
}
func TestJournalRejectsTruncatedTrailingUnknownAndAlteredBatch(t *testing.T) {
	o, s, r := setup(t)
	r.offline = true
	_, _ = o.Flush(ctx, total(1, 2))
	good := append([]byte{}, s.data...)
	for _, b := range [][]byte{[]byte("{"), append(append([]byte{}, good...), []byte("{}")...), []byte(strings.Replace(string(good), `"version":1`, `"unexpected":1,"version":1`, 1)), []byte(strings.Replace(string(good), `"upload":1`, `"upload":2`, 1))} {
		s.data = b
		if _, e := Open(s, r, "vless_42", testEpoch); e == nil {
			t.Fatal("corrupt journal accepted")
		}
	}
}
func TestCumulativeFlushConcurrentSameSnapshotIsCountedOnce(t *testing.T) {
	o, _, r := setup(t)
	var wg sync.WaitGroup
	errs := make(chan error, 20)
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _, e := o.Flush(ctx, total(99, 100)); errs <- e }()
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		if e != nil {
			t.Fatal(e)
		}
	}
	if r.up != 99 || r.down != 100 || len(r.batches) != 20 {
		t.Fatal("concurrent zero barriers double counted")
	}
}
func TestCountersAreNotAliasedToCaller(t *testing.T) {
	o, _, r := setup(t)
	rows := total(3, 4)
	if _, e := o.Flush(ctx, rows); e != nil {
		t.Fatal(e)
	}
	rows[0].Upload = 999
	if _, e := o.Flush(ctx, total(5, 6)); e != nil {
		t.Fatal(e)
	}
	if r.up != 5 {
		t.Fatal("caller mutated committed counters")
	}
}

type adapter struct {
	status     FenceStatus
	rows       []Sample
	calls      int
	fenceError bool
}

func (a *adapter) Fence(_ context.Context, i Identity) error {
	a.calls++
	if a.fenceError {
		return errors.New("fence unavailable")
	}
	a.status.RejectNew = true
	return nil
}
func (a *adapter) Inspect(context.Context, Identity) (FenceStatus, error) { return a.status, nil }
func (a *adapter) Snapshot(context.Context) ([]Sample, error) {
	return append([]Sample{}, a.rows...), nil
}
func driver() (*adapter, DrainRequest) {
	id := Identity{12, testCredential}
	return &adapter{status: FenceStatus{testEpoch, id, false, 0, true, 2}, rows: total(70, 80)}, DrainRequest{strings.Repeat("3", 32), id}
}
func TestDrainWaitsForHandlerCompletionAndAcknowledgedFinalUsage(t *testing.T) {
	o, _, r := setup(t)
	a, req := driver()
	a.status.Outstanding = 1
	if _, e := o.Drain(ctx, req, a); !errors.Is(e, ErrPending) {
		t.Fatal(e)
	}
	if r.calls != 0 || len(o.state.Drains) != 1 {
		t.Fatal("drain prematurely sent usage or lost fence")
	}
	a.status.Outstanding = 0
	r.lostResponse = true
	if _, e := o.Drain(ctx, req, a); e == nil {
		t.Fatal("unacknowledged drain completed")
	}
	if o.state.Drains[req.ID].Proof != nil {
		t.Fatal("proof before receipt")
	}
	p, e := o.Drain(ctx, req, a)
	if e != nil {
		t.Fatal(e)
	}
	if p.Final.Upload != 70 || p.Final.Download != 80 || r.up != 70 || r.down != 80 {
		t.Fatal("final counters incorrect")
	}
	before := r.calls
	p2, e := o.Drain(ctx, req, a)
	if e != nil || *p2 != *p || r.calls != before {
		t.Fatal("completed drain replay changed")
	}
}
func TestDrainPersistsHoldBeforeDisconnect(t *testing.T) {
	o, s, _ := setup(t)
	a, req := driver()
	s.fail = true
	if _, e := o.Drain(ctx, req, a); !errors.Is(e, ErrUncertain) {
		t.Fatal(e)
	}
	if a.calls != 0 {
		t.Fatal("disconnected before durable hold")
	}
}
func TestFenceFailureRemainsPendingAcrossReopen(t *testing.T) {
	o, s, r := setup(t)
	a, req := driver()
	a.fenceError = true
	if _, e := o.Drain(ctx, req, a); e == nil {
		t.Fatal("failed fence completed")
	}
	o, e := Open(s, r, "vless_42", testEpoch)
	if e != nil {
		t.Fatal(e)
	}
	if len(o.state.Drains) != 1 {
		t.Fatal("hold lost")
	}
	a.fenceError = false
	if e := o.RestoreFences(ctx, a); e != nil || a.calls != 2 {
		t.Fatal("hold not restored before service")
	}
}
func TestDrainRejectsIdentityCoverageRestartAndMissingCounter(t *testing.T) {
	for _, mutate := range []func(*adapter){func(a *adapter) { a.status.Identity.UID++ }, func(a *adapter) { a.status.TrackingReady = false }, func(a *adapter) { a.status.Bindings = 0 }, func(a *adapter) { a.status.Epoch = strings.Repeat("4", 32) }, func(a *adapter) { a.rows = nil }, func(a *adapter) { a.status.Outstanding = -1 }} {
		o, _, _ := setup(t)
		a, req := driver()
		mutate(a)
		if _, e := o.Drain(ctx, req, a); e == nil {
			t.Fatal("ineligible drain completed")
		}
	}
}
func TestDrainRejectsChangedReplayOrSecondTransfer(t *testing.T) {
	o, _, _ := setup(t)
	a, req := driver()
	a.status.Outstanding = 1
	_, _ = o.Drain(ctx, req, a)
	changed := req
	changed.Identity.UID++
	if _, e := o.Drain(ctx, changed, a); e == nil {
		t.Fatal("rebound transfer accepted")
	}
	changed = req
	changed.ID = strings.Repeat("4", 32)
	if _, e := o.Drain(ctx, changed, a); e == nil {
		t.Fatal("second transfer accepted")
	}
}
func TestDrainRechecksCoverageAfterNetworkRoundtrip(t *testing.T) {
	o, _, r := setup(t)
	a, req := driver()
	r.hook = func() { a.status.TrackingReady = false }
	if _, e := o.Drain(ctx, req, a); !errors.Is(e, ErrPending) {
		t.Fatal(e)
	}
	if o.state.Drains[req.ID].Proof != nil {
		t.Fatal("stale proof published")
	}
}

func TestDrainRejectsTailGrowthAfterReportedZeroHandlers(t *testing.T) {
	o, _, r := setup(t)
	a, req := driver()
	r.hook = func() { a.rows[0].Upload++ }
	if _, e := o.Drain(ctx, req, a); !errors.Is(e, ErrPending) {
		t.Fatal(e)
	}
	if o.state.Drains[req.ID].Proof != nil {
		t.Fatal("growing tail was treated as final")
	}
	r.hook = nil
	if _, e := o.Drain(ctx, req, a); e != nil {
		t.Fatal(e)
	}
	if r.up != 71 {
		t.Fatal("late byte lost")
	}
}

func TestLateBytesAfterFinalProofCannotBeAcknowledgedOrReplayed(t *testing.T) {
	o, _, r := setup(t)
	a, req := driver()
	if _, e := o.Drain(ctx, req, a); e != nil {
		t.Fatal(e)
	}
	committed := r.calls
	a.rows[0].Upload++
	if _, e := o.Drain(ctx, req, a); !errors.Is(e, ErrPending) {
		t.Fatal("stale proof replayed", e)
	}
	if _, e := o.Flush(ctx, a.rows); !errors.Is(e, ErrPending) {
		t.Fatal("late traffic charged after final proof", e)
	}
	if r.calls != committed {
		t.Fatal("late batch reached receiver")
	}
}
