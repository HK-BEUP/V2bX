package beupguard

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"
)

type memoryStore struct {
	j               Journal
	err             bool
	commitThenError bool
	wait, entered   chan struct{}
}

func (s *memoryStore) Load() (Journal, error) {
	return Journal{s.j.Version, s.j.Node, append([]Record(nil), s.j.Records...)}, nil
}
func (s *memoryStore) Save(n int, j Journal) error {
	if s.entered != nil {
		close(s.entered)
		<-s.wait
	}
	if len(s.j.Records) != n {
		return errors.New("CAS mismatch")
	}
	if !s.err || s.commitThenError {
		s.j = Journal{j.Version, j.Node, append([]Record(nil), j.Records...)}
	}
	if s.err {
		return errors.New("synthetic persistence failure")
	}
	return nil
}

type controllerFixture struct {
	c     *Controller
	g     *Guard
	s     *memoryStore
	key   ed25519.PrivateKey
	now   time.Time
	stamp BootStamp
	l     Lease
}

func controllerSetup(t *testing.T) *controllerFixture {
	t.Helper()
	_, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	f := &controllerFixture{key: key, now: time.Unix(1800000000, 0), stamp: BootStamp{"synthetic-boot", int64(time.Hour)}, s: &memoryStore{j: Journal{Version: 1, Node: "synthetic-jp", Records: []Record{}}}}
	f.l = Lease{ID: fmt.Sprintf("%032x", 1), Identity: Identity{2, CredentialDigest("synthetic-target")}, StartedAt: f.now.Unix(), ExpiresAt: f.now.Unix() + 600}
	f.restart(t)
	return f
}
func (f *controllerFixture) restart(t *testing.T) {
	t.Helper()
	f.g = New(1000, func() time.Time { return f.now })
	c, e := OpenController(f.g, "synthetic-jp", f.key.Public().(ed25519.PublicKey), f.s, func() time.Time { return f.now }, func() (BootStamp, error) { return f.stamp, nil })
	if e != nil {
		t.Fatal(e)
	}
	f.c = c
	f.g.Bind("a", "target", 2, "synthetic-target")
	f.g.Bind("b", "target", 2, "synthetic-target")
	f.g.Bind("a", "other", 3, "synthetic-other")
}
func (f *controllerFixture) advance(seconds int64) {
	f.now = f.now.Add(time.Duration(seconds) * time.Second)
	f.stamp.Nanos += int64(time.Duration(seconds) * time.Second)
}
func signed(key ed25519.PrivateKey, c Command) Envelope {
	b, _ := json.Marshal(c)
	return Envelope{base64.StdEncoding.EncodeToString(b), hex.EncodeToString(ed25519.Sign(key, append([]byte(CommandDomain), b...)))}
}
func (f *controllerFixture) command(n uint64, op string, l Lease) Envelope {
	return signed(f.key, Command{1, "synthetic-jp", n, f.now.Unix(), f.now.Unix() + 60, op, l})
}
func TestControllerSignedBlockAckWaitReleaseReplay(t *testing.T) {
	f := controllerSetup(t)
	done, _ := f.g.Track("a", "target", func() {})
	e := f.command(1, "block", f.l)
	a, err := f.c.Execute(e)
	if err != nil || !a.RejectNew || a.ExistingClosed || a.Outstanding != 1 || !a.IdentityBound {
		t.Fatalf("false ack: %+v %v", a, err)
	}
	done()
	a, err = f.c.Execute(e)
	if err != nil || !a.ExistingClosed || a.Outstanding != 0 || len(f.s.j.Records) != 1 {
		t.Fatal("duplicate changed lease", a, err)
	}
	if _, err = f.g.Track("b", "target", nil); err != ErrIsolated {
		t.Fatal(err)
	}
	if _, err = f.g.Track("a", "other", nil); err != nil {
		t.Fatal(err)
	}
	if _, err = f.c.Execute(f.command(2, "release", f.l)); err != nil {
		t.Fatal(err)
	}
	if a, err = f.c.Execute(e); err != nil || a.RejectNew || a.State != "ended" {
		t.Fatal("old block replayed", a, err)
	}
	f.restart(t)
	if _, err = f.g.Track("a", "target", nil); err != nil {
		t.Fatal("restart resurrected release", err)
	}
	if _, err = f.c.Execute(f.command(3, "release", f.l)); err == nil {
		t.Fatal("duplicate release sequence accepted")
	}
}
func TestControllerRejectsForgeryCrossNodeStaleConflictAndGap(t *testing.T) {
	for _, mutate := range []func(*controllerFixture, Command) Envelope{
		func(f *controllerFixture, c Command) Envelope {
			_, k, _ := ed25519.GenerateKey(rand.Reader)
			return signed(k, c)
		},
		func(f *controllerFixture, c Command) Envelope { c.Node = "other-node"; return signed(f.key, c) },
		func(f *controllerFixture, c Command) Envelope {
			c.IssuedAt -= 61
			c.NotAfter -= 61
			return signed(f.key, c)
		},
		func(f *controllerFixture, c Command) Envelope {
			c.IssuedAt += 30
			c.NotAfter += 30
			return signed(f.key, c)
		},
		func(f *controllerFixture, c Command) Envelope { c.Sequence = 2; return signed(f.key, c) },
		func(f *controllerFixture, c Command) Envelope { c.Lease.Identity.UID = 3; return signed(f.key, c) },
		func(f *controllerFixture, c Command) Envelope {
			c.Lease.Identity.Credential = CredentialDigest("rotated")
			return signed(f.key, c)
		},
		func(f *controllerFixture, c Command) Envelope { c.Lease.ExpiresAt++; return signed(f.key, c) },
		func(f *controllerFixture, c Command) Envelope { e := signed(f.key, c); e.Payload = "bad"; return e },
	} {
		f := controllerSetup(t)
		c := Command{1, "synthetic-jp", 1, f.now.Unix(), f.now.Unix() + 60, "block", f.l}
		if _, e := f.c.Execute(mutate(f, c)); e == nil || len(f.s.j.Records) != 0 || f.g.Stats().Leases != 0 {
			t.Fatal("invalid command affected account")
		}
	}
	f := controllerSetup(t)
	_, _ = f.c.Execute(f.command(1, "block", f.l))
	f.l.Manual = true
	f.l.ExpiresAt = 0
	if _, e := f.c.Execute(f.command(1, "block", f.l)); e == nil {
		t.Fatal("same sequence payload changed")
	}
}
func TestControllerRestartUsesRemainingBootTimeNotWallTime(t *testing.T) {
	f := controllerSetup(t)
	e := f.command(1, "block", f.l)
	_, err := f.c.Execute(e)
	if err != nil {
		t.Fatal(err)
	}
	f.advance(240)
	f.now = f.now.Add(-time.Hour) // Wall time moved; kernel boot time did not.
	f.restart(t)
	f.advance(359)
	if _, e := f.g.Track("a", "target", nil); e != ErrIsolated {
		t.Fatal("lost remaining hold", e)
	}
	f.advance(1)
	if _, e := f.g.Track("a", "target", nil); e != nil {
		t.Fatal("restarted 10m timer", e)
	}
	f.restart(t)
	if _, e := f.g.Track("a", "target", nil); e != nil {
		t.Fatal("resurrected expired hold", e)
	}
	a, err := f.c.Execute(e)
	if err != nil || a.RejectNew {
		t.Fatal(a, err)
	}
}
func TestControllerManualSurvivesRestartAndMachineReboot(t *testing.T) {
	f := controllerSetup(t)
	f.l.Manual = true
	f.l.ExpiresAt = 0
	if _, e := f.c.Execute(f.command(1, "block", f.l)); e != nil {
		t.Fatal(e)
	}
	f.advance(172800)
	f.stamp = BootStamp{"second-boot", int64(time.Minute)}
	f.restart(t)
	if _, e := f.g.Track("a", "target", nil); e != ErrIsolated {
		t.Fatal("manual hold lost", e)
	}
	if _, e := f.c.Execute(f.command(2, "release", f.l)); e != nil {
		t.Fatal(e)
	}
	f.restart(t)
	if _, e := f.g.Track("a", "target", nil); e != nil {
		t.Fatal(e)
	}
}
func TestControllerNewKernelBootRequiresTemporaryReconciliation(t *testing.T) {
	f := controllerSetup(t)
	original := f.command(1, "block", f.l)
	_, _ = f.c.Execute(original)
	f.stamp.ID = "different-boot"
	f.restart(t)
	a, e := f.c.Execute(original)
	if e != nil || a.State != "interrupted_by_reboot" || a.TrackingReady || !a.ReconciliationRequired || a.RejectNew {
		t.Fatal("unreconciled reboot concealed", a, e)
	}
	if _, e = f.g.Track("a", "other", nil); e != nil {
		t.Fatal("reboot affected other accounts", e)
	}
	l := f.l
	l.ID = fmt.Sprintf("%032x", 2)
	if _, e = f.c.Execute(f.command(2, "block", l)); e == nil {
		t.Fatal("new block before reconciliation")
	}
	a, e = f.c.Execute(f.command(2, "release", f.l))
	if e != nil || a.ReconciliationRequired || !a.TrackingReady {
		t.Fatal("signed reconciliation failed", a, e)
	}
	f.restart(t)
	if _, e = f.c.Execute(f.command(3, "block", l)); e != nil {
		t.Fatal("safe new event after reconciliation denied", e)
	}
}
func TestControllerUncertainCommitRequiresReloadAndPreservesIntent(t *testing.T) {
	for _, committed := range []bool{false, true} {
		f := controllerSetup(t)
		f.s.err = true
		f.s.commitThenError = committed
		e := f.command(1, "block", f.l)
		if _, err := f.c.Execute(e); err == nil {
			t.Fatal("uncertain write acknowledged")
		}
		if f.g.Stats().Leases != 0 {
			t.Fatal("applied before durable ack")
		}
		f.s.err = false
		if _, err := f.c.Execute(e); err == nil {
			t.Fatal("unsafe retry without recovery")
		}
		f.restart(t)
		if (f.g.Stats().Leases == 1) != committed {
			t.Fatal("durable intent not recovered")
		}
	}
}
func TestControllerSlowPersistenceDoesNotBlockTrafficOrMissNewSessions(t *testing.T) {
	f := controllerSetup(t)
	f.s.wait = make(chan struct{})
	f.s.entered = make(chan struct{})
	done := make(chan error, 1)
	go func() { _, e := f.c.Execute(f.command(1, "block", f.l)); done <- e }()
	<-f.s.entered
	var closed atomic.Int64
	tracked := make(chan error, 1)
	go func() { _, e := f.g.Track("a", "target", func() { closed.Add(1) }); tracked <- e }()
	select {
	case e := <-tracked:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(time.Second):
		t.Fatal("disk I/O stalled proxy lock")
	}
	if _, e := f.g.Track("a", "other", nil); e != nil {
		t.Fatal(e)
	}
	close(f.s.wait)
	if e := <-done; e != nil || closed.Load() != 1 {
		t.Fatal("connection opened during commit escaped", e, closed.Load())
	}
}
func TestControllerCorruptJournalFailsBeforeRestoringAnyHold(t *testing.T) {
	f := controllerSetup(t)
	_, _ = f.c.Execute(f.command(1, "block", f.l))
	f.s.j.Records[0].Envelope.Signature = "bad"
	g := New(100, nil)
	if _, e := OpenController(g, "synthetic-jp", f.key.Public().(ed25519.PublicKey), f.s, nil, func() (BootStamp, error) { return f.stamp, nil }); e == nil || g.Stats().Leases != 0 {
		t.Fatal("partial unverified restore")
	}
}
func TestControllerCapacityRefusesBlockButAllowsRelease(t *testing.T) {
	f := controllerSetup(t)
	_, _ = f.c.Execute(f.command(1, "block", f.l))
	f.g.capacityFailures.Add(1)
	a, e := f.c.Execute(f.command(2, "release", f.l))
	if e != nil || a.RejectNew || a.TrackingReady {
		t.Fatal(a, e)
	}
	l := f.l
	l.ID = fmt.Sprintf("%032x", 2)
	if _, e = f.c.Execute(f.command(3, "block", l)); e == nil {
		t.Fatal("untracked traffic accepted for enforcement")
	}
}

func TestControllerCoverageFailureCannotClaimClosedOrStartAnotherBlock(t *testing.T) {
	f := controllerSetup(t)
	e := f.command(1, "block", f.l)
	if _, err := f.c.Execute(e); err != nil {
		t.Fatal(err)
	}
	f.g.NoteCoverageFailure()
	a, err := f.c.Execute(e)
	if err != nil || a.TrackingReady || a.ExistingClosed {
		t.Fatal("incomplete coverage acknowledged", a, err)
	}
	if _, err = f.c.Execute(f.command(2, "release", f.l)); err != nil {
		t.Fatal("safety release rejected", err)
	}
	l := f.l
	l.ID = fmt.Sprintf("%032x", 2)
	if _, err = f.c.Execute(f.command(3, "block", l)); err == nil {
		t.Fatal("unknown coverage accepted")
	}
}

func TestControllerOldReleaseCannotRemoveOrMisreportNewerLease(t *testing.T) {
	f := controllerSetup(t)
	_, _ = f.c.Execute(f.command(1, "block", f.l))
	f.advance(601)
	l := f.l
	l.ID = fmt.Sprintf("%032x", 2)
	l.StartedAt = f.now.Unix()
	l.ExpiresAt = l.StartedAt + 600
	if _, e := f.c.Execute(f.command(2, "block", l)); e != nil {
		t.Fatal(e)
	}
	a, e := f.c.Execute(f.command(3, "release", f.l))
	if e != nil || a.State != "superseded" || a.CurrentLeaseID != l.ID || !a.RejectNew {
		t.Fatal("old release overwrote newer state", a, e)
	}
	if _, e = f.g.Track("a", "target", nil); e != ErrIsolated {
		t.Fatal("newer lease removed", e)
	}
}

func TestControllerClockRollbackStillAllowsSignedSafetyRelease(t *testing.T) {
	f := controllerSetup(t)
	f.l.Manual = true
	f.l.ExpiresAt = 0
	if _, e := f.c.Execute(f.command(1, "block", f.l)); e != nil {
		t.Fatal(e)
	}
	f.now = f.now.Add(-time.Hour)
	f.stamp.Nanos += int64(time.Second)
	if _, e := f.c.Execute(f.command(2, "release", f.l)); e != nil {
		t.Fatal("signed safety release unavailable on wall rollback", e)
	}
	f.restart(t)
	if _, e := f.g.Track("a", "target", nil); e != nil {
		t.Fatal("release lost after restart", e)
	}
	l := f.l
	l.ID = fmt.Sprintf("%032x", 2)
	l.StartedAt = f.now.Unix()
	if _, e := f.c.Execute(f.command(3, "block", l)); e == nil {
		t.Fatal("clock high-water reset by safety release")
	}
}
