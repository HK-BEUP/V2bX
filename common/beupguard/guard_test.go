package beupguard

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func fixture() (*Guard, *time.Time, Lease) {
	now := time.Unix(1800000000, 0)
	g := New(1000, func() time.Time { return now })
	g.Bind("a", "u", 2, "synthetic-uuid")
	g.Bind("b", "u2", 2, "synthetic-uuid")
	g.Bind("a", "other", 3, "other-uuid")
	l := Lease{ID: fmt.Sprintf("%032x", 1), Identity: Identity{2, CredentialDigest("synthetic-uuid")}, StartedAt: now.Unix(), ExpiresAt: now.Unix() + 600}
	return g, &now, l
}
func TestBlockAllBoundEntrypointsAndPreserveOtherAccount(t *testing.T) {
	g, _, l := fixture()
	var closed atomic.Int64
	for _, b := range []Binding{{"a", "u"}, {"b", "u2"}} {
		_, e := g.Track(b.Tag, b.Label, func() { closed.Add(1) })
		if e != nil {
			t.Fatal(e)
		}
	}
	_, _ = g.Track("a", "other", func() { t.Error("closed unrelated account") })
	n, e := g.Apply(l)
	if e != nil || n != 2 || closed.Load() != 2 {
		t.Fatalf("block %d %v", n, e)
	}
	if _, e = g.Track("b", "u2", nil); e != ErrIsolated {
		t.Fatal("new connection not rejected", e)
	}
	if _, e = g.Track("a", "other", nil); e != nil {
		t.Fatal("other account affected", e)
	}
}
func TestTemporaryExpiryAndDuplicateNoExtension(t *testing.T) {
	g, now, l := fixture()
	if _, e := g.Apply(l); e != nil {
		t.Fatal(e)
	}
	*now = now.Add(599 * time.Second)
	if _, e := g.Apply(l); e != nil {
		t.Fatal(e)
	}
	if _, e := g.Track("a", "u", nil); e != ErrIsolated {
		t.Fatal(e)
	}
	*now = now.Add(time.Second)
	if _, e := g.Track("a", "u", nil); e != nil {
		t.Fatal(e)
	}
	if _, e := g.Apply(l); e == nil {
		t.Fatal("resurrected expired lease")
	}
}
func TestManualHoldOnlyExplicitRelease(t *testing.T) {
	g, now, l := fixture()
	l.Manual = true
	l.ExpiresAt = 0
	if _, e := g.Apply(l); e != nil {
		t.Fatal(e)
	}
	*now = now.Add(48 * time.Hour)
	if _, e := g.Track("a", "u", nil); e != ErrIsolated {
		t.Fatal(e)
	}
	if e := g.Release(l.ID, Identity{3, l.Identity.Credential}); e == nil {
		t.Fatal("wrong uid release")
	}
	if e := g.Release(l.ID, l.Identity); e != nil {
		t.Fatal(e)
	}
	if _, e := g.Track("a", "u", nil); e != nil {
		t.Fatal(e)
	}
	if _, e := g.Apply(l); e == nil {
		t.Fatal("resurrected manually released lease")
	}
}
func TestCredentialRotationDoesNotBlockNewCredential(t *testing.T) {
	g, _, l := fixture()
	_, _ = g.Apply(l)
	g.Unbind("a", "u")
	g.Bind("a", "new", 2, "new-credential")
	if _, e := g.Track("a", "new", nil); e != nil {
		t.Fatal("rotated credential affected", e)
	}
	if _, e := g.Track("a", "u", nil); e != ErrIdentity {
		t.Fatal("unbound identity guessed")
	}
	changed := l
	changed.Identity.Credential = CredentialDigest("new-credential")
	if _, e := g.Apply(changed); e == nil {
		t.Fatal("lease identity changed")
	}
}
func TestValidation(t *testing.T) {
	for _, change := range []func(*Lease){func(l *Lease) { l.ID = "bad" }, func(l *Lease) { l.Identity.UID = 0 }, func(l *Lease) { l.Identity.Credential = "bad" }, func(l *Lease) { l.ExpiresAt++ }, func(l *Lease) { l.StartedAt += 20 }, func(l *Lease) { l.Manual = true }} {
		g, _, l := fixture()
		change(&l)
		if _, e := g.Apply(l); e == nil {
			t.Fatal("invalid lease accepted")
		}
	}
}
func TestTrackBlockRaceDoesNotLeakConnections(t *testing.T) {
	g, _, l := fixture()
	var closed, accepted atomic.Int64
	var wg sync.WaitGroup
	start := make(chan struct{})
	for n := 0; n < 100; n++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if _, e := g.Track("a", "u", func() { closed.Add(1) }); e == nil {
				accepted.Add(1)
			} else if e != ErrIsolated {
				t.Error(e)
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		if _, e := g.Apply(l); e != nil {
			t.Error(e)
		}
	}()
	close(start)
	wg.Wait()
	if closed.Load() != accepted.Load() || g.Outstanding(l.Identity) != int(accepted.Load()) {
		t.Fatal("concurrent connection escaped", closed.Load(), accepted.Load())
	}
}

func TestAcknowledgementWaitsForActualHandlerCompletion(t *testing.T) {
	g, _, l := fixture()
	done, _ := g.Track("a", "u", func() {})
	_, _ = g.Apply(l)
	if g.Outstanding(l.Identity) != 1 {
		t.Fatal("cancel request falsely acknowledged as closed")
	}
	done()
	if g.Outstanding(l.Identity) != 0 {
		t.Fatal("handler completion not recorded")
	}
}
func TestCloseMayReenterAndUntrackIsIdempotent(t *testing.T) {
	g, _, l := fixture()
	var done func()
	done, _ = g.Track("a", "u", func() { done(); done(); g.Stats() })
	if _, e := g.Apply(l); e != nil {
		t.Fatal(e)
	}
}
func TestCapacityIsExplicitAndCannotBypassExistingBlock(t *testing.T) {
	g, _, l := fixture()
	g.maxSessions = 1
	done, _ := g.Track("a", "other", nil)
	if _, e := g.Track("a", "u", nil); e != ErrCapacity {
		t.Fatal(e)
	}
	if g.Stats().CapacityFailures != 1 {
		t.Fatal("unreported capacity failure")
	}
	_, _ = g.Apply(l)
	if _, e := g.Track("a", "u", nil); e != ErrIsolated {
		t.Fatal("capacity bypassed block")
	}
	done()
}
