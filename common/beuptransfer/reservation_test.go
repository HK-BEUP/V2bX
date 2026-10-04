package beuptransfer

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

func TestProbeReservesLastSlotAtomically(t *testing.T) {
	o, store, receiver := setup(t)
	for n := 0; n < 999; n++ {
		id := fmt.Sprintf("%032x", n+1)
		o.state.Drains[id] = drainRecord{Request: DrainRequest{id, Identity{int64(n + 100), testCredential}}}
	}
	var wins atomic.Int32
	var wg sync.WaitGroup
	for n := 0; n < 12; n++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			r := DrainRequest{fmt.Sprintf("%032x", 2000+n), Identity{int64(2000 + n), testCredential}}
			if o.probeReady(r) == nil {
				wins.Add(1)
			}
		}(n)
	}
	wg.Wait()
	if wins.Load() != 1 || len(o.state.Reservations) != 1 {
		t.Fatal("overcommitted final journal slot", wins.Load())
	}
	var reserved DrainRequest
	for _, r := range o.state.Reservations {
		reserved = r
	}
	if err := o.probeReady(reserved); err != nil {
		t.Fatal("idempotent promise refused", err)
	}
	other := DrainRequest{strings.Repeat("e", 32), Identity{9999, testCredential}}
	if _, err := o.Drain(ctx, other, funcDriver()); err == nil {
		t.Fatal("unreserved drain stole promised capacity")
	}
	// Reopening keeps the promise, but does not disconnect that account.
	reopened, err := Open(store, receiver, "vless_42", testEpoch)
	if err != nil {
		t.Fatal(err)
	}
	if reopened.state.Reservations[reserved.ID] != reserved {
		t.Fatal("promise lost on reopen")
	}
}
func funcDriver() DrainAdapter { a, _ := driver(); return a }

func TestReservationDoesNotFenceAndPromotesOnDrain(t *testing.T) {
	o, s, r := setup(t)
	a, req := driver()
	if err := o.probeReady(req); err != nil {
		t.Fatal(err)
	}
	o, err := Open(s, r, "vless_42", testEpoch)
	if err != nil {
		t.Fatal(err)
	}
	if err = o.RestoreFences(ctx, a); err != nil || a.calls != 0 {
		t.Fatal("probe became a fence", err)
	}
	if _, err = o.Drain(ctx, req, a); err != nil {
		t.Fatal(err)
	}
	if len(o.state.Reservations) != 0 || o.state.Drains[req.ID].Proof == nil || !a.status.RejectNew {
		t.Fatal("reservation did not atomically become durable drain")
	}
}

func TestReservationBindingAndWriteFailures(t *testing.T) {
	o, s, _ := setup(t)
	_, req := driver()
	if err := o.probeReady(req); err != nil {
		t.Fatal(err)
	}
	bad := req
	bad.Identity.UID++
	if err := o.probeReady(bad); err == nil {
		t.Fatal("rebound transfer")
	}
	bad = req
	bad.ID = strings.Repeat("e", 32)
	if err := o.probeReady(bad); err == nil {
		t.Fatal("duplicate identity reserved twice")
	}
	s.fail = true
	if err := o.probeReady(req); !errors.Is(err, ErrUncertain) {
		t.Fatal("fsync failure reported ready", err)
	}
}

func TestReservationJournalRejectsMalformedPromises(t *testing.T) {
	for _, mode := range []string{"id", "credential", "duplicate-identity", "duplicate-drain", "capacity"} {
		t.Run(mode, func(t *testing.T) {
			o, s, r := setup(t)
			_, req := driver()
			j := clone(o.state)
			j.Reservations = map[string]DrainRequest{req.ID: req}
			switch mode {
			case "id":
				wrong := req
				wrong.ID = strings.Repeat("e", 32)
				j.Reservations[req.ID] = wrong
			case "credential":
				wrong := req
				wrong.Identity.Credential = ""
				j.Reservations[req.ID] = wrong
			case "duplicate-identity":
				wrong := req
				wrong.ID = strings.Repeat("e", 32)
				j.Reservations[wrong.ID] = wrong
			case "duplicate-drain":
				j.Drains[req.ID] = drainRecord{Request: req}
			case "capacity":
				for n := 0; n < 1000; n++ {
					id := fmt.Sprintf("%032x", n+1)
					j.Drains[id] = drainRecord{Request: DrainRequest{id, Identity{int64(n + 100), testCredential}}}
				}
			}
			s.data, _ = json.Marshal(j)
			if _, err := Open(s, r, "vless_42", testEpoch); err == nil {
				t.Fatal("unsafe reservation journal accepted")
			}
		})
	}
}
