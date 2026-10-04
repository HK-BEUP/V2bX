package beuptransfer

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/InazumaV/V2bX/common/beupguard"
)

func TestGuardAdapterUsesHandlerCompletionNotCloseRequest(t *testing.T) {
	var up atomic.Int64
	id := Identity{12, beupguard.CredentialDigest("synthetic-credential")}
	a, e := NewGuardAdapter("synthetic-vless", testEpoch, func(context.Context) ([]Sample, error) { return []Sample{{12, id.Credential, up.Load(), 0}}, nil })
	if e != nil {
		t.Fatal(e)
	}
	if e = a.Bind("label", 12, "synthetic-credential"); e != nil {
		t.Fatal(e)
	}
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	finish, e := a.Track("label", func() { server.Close() })
	if e != nil {
		t.Fatal(e)
	}
	returned := make(chan struct{})
	allowFinish := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 1)
		_, _ = server.Read(buf)
		close(returned)
		<-allowFinish
		up.Add(7)
		finish()
	}()
	o, _, r := setup(t)
	request := DrainRequest{strings.Repeat("5", 32), id}
	if _, e = o.Drain(ctx, request, a); !errors.Is(e, ErrPending) {
		t.Fatal("close request mistaken for handler completion", e)
	}
	select {
	case <-returned:
	case <-time.After(time.Second):
		t.Fatal("flow not interrupted")
	}
	if _, e = a.Track("label", func() {}); e != beupguard.ErrIsolated {
		t.Fatal("old credential reconnected", e)
	}
	close(allowFinish)
	<-done
	p, e := o.Drain(ctx, request, a)
	if e != nil {
		t.Fatal(e)
	}
	if p.Final.Upload != 7 || r.up != 7 {
		t.Fatal("handler's final accounting was lost")
	}
}

func TestGuardAdapterAdmissionRacingFenceCannotEscape(t *testing.T) {
	a, e := NewGuardAdapter("synthetic-vless", testEpoch, func(context.Context) ([]Sample, error) { return nil, nil })
	if e != nil {
		t.Fatal(e)
	}
	a.Bind("label", 12, "synthetic-credential")
	id := Identity{12, beupguard.CredentialDigest("synthetic-credential")}
	var admitted, closed atomic.Int64
	var wg sync.WaitGroup
	start := make(chan struct{})
	errs := make(chan error, 100)
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			finish, e := a.Track("label", func() { closed.Add(1) })
			if e == nil {
				admitted.Add(1)
				errs <- nil
				_ = finish
			} else if e != beupguard.ErrIsolated {
				errs <- e
			}
		}()
	}
	close(start)
	if e = a.Fence(ctx, id); e != nil {
		t.Fatal(e)
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		if e != nil {
			t.Fatal(e)
		}
	}
	if admitted.Load() != closed.Load() {
		t.Fatal("admitted session escaped close")
	}
	s, e := a.Inspect(ctx, id)
	if e != nil || int64(s.Outstanding) != admitted.Load() {
		t.Fatal("close requests erased outstanding sessions")
	}
}

func TestGuardAdapterCoverageFailureIsSticky(t *testing.T) {
	a, e := NewGuardAdapter("synthetic-vless", testEpoch, func(context.Context) ([]Sample, error) { return nil, nil })
	if e != nil {
		t.Fatal(e)
	}
	a.Bind("label", 12, "synthetic-credential")
	if _, e = a.Track("unknown", func() {}); e != beupguard.ErrIdentity {
		t.Fatal(e)
	}
	id := Identity{12, beupguard.CredentialDigest("synthetic-credential")}
	a.Bind("later", 13, "synthetic-another")
	s, _ := a.Inspect(ctx, id)
	if s.TrackingReady {
		t.Fatal("coverage hole disappeared after a good binding")
	}
}

func TestGuardAdapterDoesNotTouchExistingGlobalGuards(t *testing.T) {
	g := beupguard.New(20, nil)
	beupguard.Set(g)
	defer beupguard.Set(nil)
	g.Bind("old", "label", 12, "synthetic-credential")
	l := beupguard.Lease{ID: strings.Repeat("6", 32), Identity: beupguard.Identity{UID: 12, Credential: beupguard.CredentialDigest("synthetic-credential")}, StartedAt: time.Now().Unix(), Manual: true}
	if _, e := g.Apply(l); e != nil {
		t.Fatal(e)
	}
	a, e := NewGuardAdapter("new", testEpoch, func(context.Context) ([]Sample, error) { return nil, nil })
	if e != nil {
		t.Fatal(e)
	}
	a.Bind("label", 12, "synthetic-credential")
	if e = a.Fence(ctx, Identity{12, l.Identity.Credential}); e != nil {
		t.Fatal(e)
	}
	if beupguard.Current() != g || g.Stats().Leases != 1 {
		t.Fatal("existing guard modified")
	}
	if _, e = g.Track("old", "label", func() {}); e != beupguard.ErrIsolated {
		t.Fatal("existing hold released")
	}
}

func TestGuardAdapterRejectsRebindingBeforeRetirement(t *testing.T) {
	a, _ := NewGuardAdapter("synthetic-vless", testEpoch, func(context.Context) ([]Sample, error) { return nil, nil })
	if e := a.Bind("label", 12, "synthetic-credential"); e != nil {
		t.Fatal(e)
	}
	if e := a.Bind("label", 13, "changed"); e == nil {
		t.Fatal("counter identity reassigned")
	}
	s, _ := a.Inspect(ctx, Identity{12, beupguard.CredentialDigest("synthetic-credential")})
	if s.TrackingReady {
		t.Fatal("unsafe binding still ready")
	}
}
