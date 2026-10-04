package beuptransfer

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"strings"
	"sync"
	"testing"

	"github.com/InazumaV/V2bX/common/beupguard"
)

type sessionCounters struct {
	mu   sync.Mutex
	rows []Sample
}

func (c *sessionCounters) snapshot(context.Context) ([]Sample, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]Sample{}, c.rows...), nil
}
func (c *sessionCounters) put(rows []Sample) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.rows = append([]Sample{}, rows...)
}
func sessionAdapter(t *testing.T) (*GuardAdapter, *sessionCounters) {
	t.Helper()
	c := &sessionCounters{}
	a, err := NewGuardAdapter("session-test", testEpoch, c.snapshot)
	if err != nil {
		t.Fatal(err)
	}
	return a, c
}
func addSessionUser(t *testing.T, a *GuardAdapter, c *sessionCounters, u, d int64) Identity {
	t.Helper()
	if err := a.Bind("one", 12, "synthetic-only"); err != nil {
		t.Fatal(err)
	}
	id := Identity{12, beupguard.CredentialDigest("synthetic-only")}
	c.put([]Sample{{id.UID, id.Credential, u, d}})
	return id
}

func TestCleanCounterRestartCarriesAcknowledgedTail(t *testing.T) {
	o, store, receiver := setup(t)
	a, c := sessionAdapter(t)
	s, err := o.BeginCounterSession(ctx, strings.Repeat("2", 32), a)
	if err != nil {
		t.Fatal(err)
	}
	id := addSessionUser(t, a, c, 20, 30)
	var release func()
	release, err = a.Track("one", func() { c.put([]Sample{{id.UID, id.Credential, 25, 37}}); release() })
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Seal(ctx); err != nil {
		t.Fatal(err)
	}
	if receiver.up != 25 || receiver.down != 37 || !o.state.Session.Sealed {
		t.Fatal("tail not settled before seal")
	}
	if _, err = s.Snapshot(ctx); !errors.Is(err, ErrEpoch) {
		t.Fatal("sealed process still usable", err)
	}
	if _, err = o.Flush(ctx, nil); !errors.Is(err, ErrEpoch) {
		t.Fatal("sealed outbox still accepted traffic")
	}
	if _, err = a.Track("one", func() {}); err == nil {
		t.Fatal("shutdown still admits connections")
	}
	if err = a.Bind("two", 13, "new"); err == nil {
		t.Fatal("shutdown still admits bindings")
	}
	o, err = Open(store, receiver, "vless_42", testEpoch)
	if err != nil {
		t.Fatal(err)
	}
	newAdapter, newCounters := sessionAdapter(t)
	resumed, err := o.BeginCounterSession(ctx, strings.Repeat("3", 32), newAdapter)
	if err != nil {
		t.Fatal(err)
	}
	addSessionUser(t, newAdapter, newCounters, 10, 12)
	rows, err := resumed.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].Upload != 35 || rows[0].Download != 49 {
		t.Fatal("counter base missing", rows)
	}
	if _, err = o.Flush(ctx, rows); err != nil {
		t.Fatal(err)
	}
	if receiver.up != 35 || receiver.down != 49 {
		t.Fatal("reboot billed base twice")
	}
	if err = resumed.Seal(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestUnsealedRestartCannotInventCleanGeneration(t *testing.T) {
	for _, mode := range []string{"idle", "active", "pending"} {
		t.Run(mode, func(t *testing.T) {
			o, store, receiver := setup(t)
			a, c := sessionAdapter(t)
			s, err := o.BeginCounterSession(ctx, strings.Repeat("2", 32), a)
			if err != nil {
				t.Fatal(err)
			}
			if mode != "idle" {
				addSessionUser(t, a, c, 20, 30)
				rows, _ := s.Snapshot(ctx)
				receiver.offline = mode == "pending"
				_, _ = o.Flush(ctx, rows)
			}
			o, err = Open(store, receiver, "vless_42", testEpoch)
			if err != nil {
				t.Fatal(err)
			}
			fresh, _ := sessionAdapter(t)
			if _, err = o.BeginCounterSession(ctx, strings.Repeat("3", 32), fresh); !errors.Is(err, ErrEpoch) {
				t.Fatal("dirty generation automatically reset", err)
			}
			if mode == "pending" {
				receiver.offline = false
				if _, err = o.Replay(ctx); err != nil {
					t.Fatal(err)
				}
				if receiver.up != 20 || receiver.down != 30 {
					t.Fatal("persisted pending lost")
				}
				if _, err = o.BeginCounterSession(ctx, strings.Repeat("3", 32), fresh); !errors.Is(err, ErrEpoch) {
					t.Fatal("replay falsely proved unpersisted tail")
				}
			}
		})
	}
}

func TestSealRetryAfterLostResponseDoesNotDoubleBill(t *testing.T) {
	o, _, receiver := setup(t)
	a, c := sessionAdapter(t)
	s, _ := o.BeginCounterSession(ctx, strings.Repeat("2", 32), a)
	addSessionUser(t, a, c, 70, 80)
	receiver.lostResponse = true
	if err := s.Seal(ctx); err == nil || o.state.Session.Sealed || o.state.Pending == nil {
		t.Fatal("lost response marked closed")
	}
	if err := s.Seal(ctx); err != nil {
		t.Fatal(err)
	}
	if receiver.up != 70 || receiver.down != 80 {
		t.Fatal("seal retry double billed")
	}
}

func TestSealRequiresCompleteCoverageAndReleasedHandlers(t *testing.T) {
	for _, mode := range []string{"incomplete", "outstanding", "late-tail", "disk-failure"} {
		t.Run(mode, func(t *testing.T) {
			o, store, receiver := setup(t)
			a, c := sessionAdapter(t)
			s, _ := o.BeginCounterSession(ctx, strings.Repeat("2", 32), a)
			id := addSessionUser(t, a, c, 10, 20)
			switch mode {
			case "incomplete":
				a.NoteIdentityCoverageFailure("one")
			case "outstanding":
				_, _ = a.Track("one", func() {})
			case "late-tail":
				receiver.hook = func() { c.put([]Sample{{id.UID, id.Credential, 11, 21}}) }
			case "disk-failure":
				store.fail = true
			}
			if err := s.Seal(ctx); err == nil || o.state.Session.Sealed {
				t.Fatal("incomplete shutdown marked sealed")
			}
		})
	}
}

func TestRestartRetainsRemovedCountersAndMigrationHold(t *testing.T) {
	o, store, receiver := setup(t)
	a, c := sessionAdapter(t)
	s, _ := o.BeginCounterSession(ctx, strings.Repeat("2", 32), a)
	id := addSessionUser(t, a, c, 10, 20)
	req := DrainRequest{strings.Repeat("d", 32), id}
	if _, err := o.Drain(ctx, req, s); err != nil {
		t.Fatal(err)
	}
	if err := s.Seal(ctx); err != nil {
		t.Fatal(err)
	}
	o, err := Open(store, receiver, "vless_42", testEpoch)
	if err != nil {
		t.Fatal(err)
	}
	a, c = sessionAdapter(t)
	resumed, err := o.BeginCounterSession(ctx, strings.Repeat("3", 32), a)
	if err != nil {
		t.Fatal(err)
	}
	status, err := resumed.Inspect(ctx, id)
	if err != nil || status.Bindings != 1 || !status.RejectNew || !status.TrackingReady || status.Outstanding != 0 {
		t.Fatal("retired proof lost", status, err)
	}
	if _, err = o.Drain(ctx, req, resumed); err != nil {
		t.Fatal("old proof not preserved", err)
	}
	addSessionUser(t, a, c, 0, 0)
	if _, err = a.Track("one", func() {}); err == nil {
		t.Fatal("old migration credential readmitted")
	}
}

func TestSessionRejectsLegacyStateAndTamperedSeal(t *testing.T) {
	o, store, receiver := setup(t)
	_, _ = o.Flush(ctx, total(1, 2))
	a, _ := sessionAdapter(t)
	if _, err := o.BeginCounterSession(ctx, strings.Repeat("2", 32), a); !errors.Is(err, ErrEpoch) {
		t.Fatal("existing unmanaged counters adopted")
	}
	for _, mode := range []string{"invalid-process", "base-regressed", "sealed-pending"} {
		t.Run(mode, func(t *testing.T) {
			j := clone(o.state)
			j.Session = &counterSession{Process: strings.Repeat("2", 32), Base: []Sample{}, Sealed: true}
			switch mode {
			case "invalid-process":
				j.Session.Process = "invalid"
			case "base-regressed":
				j.Session.Base = total(100, 200)
			case "sealed-pending":
				j.Pending = &pendingBatch{}
			}
			store.data, _ = json.Marshal(j)
			if _, err := Open(store, receiver, "vless_42", testEpoch); err == nil {
				t.Fatal("forged seal accepted")
			}
		})
	}
}

func TestSessionOverflowAndLiveCutoverRejected(t *testing.T) {
	o, _, _ := setup(t)
	a, c := sessionAdapter(t)
	id := addSessionUser(t, a, c, 0, 0)
	if _, err := o.BeginCounterSession(ctx, strings.Repeat("2", 32), a); err == nil {
		t.Fatal("live bindings adopted")
	}
	s := &CounterSession{inner: a, base: []Sample{{id.UID, id.Credential, math.MaxInt64, 0}}}
	c.put([]Sample{{id.UID, id.Credential, 1, 0}})
	if _, err := s.Snapshot(ctx); err == nil {
		t.Fatal("counter overflow accepted")
	}
}
