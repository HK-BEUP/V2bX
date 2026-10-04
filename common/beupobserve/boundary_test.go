package observer

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

const epoch = int64(1800000000)

func request(o *Observer) {
	o.Observe("test-inbound", "PRIVATE-TEST-CREDENTIAL", "tcp", "example.test", 443)
}
func total(reports []Report) (n, lost uint64) {
	for _, r := range reports {
		for _, s := range r.Subjects {
			n += uint64(s.Metrics.ProxyRequests)
		}
	}
	// Quality is repeated on chunks, not additive across chunks of one window.
	if len(reports) > 0 {
		lost = reports[0].Quality.DroppedRequests
	}
	return
}

func TestLookaheadMetricsAndLossStayInNextMinute(t *testing.T) {
	o, clock := sample(t)
	request(o)
	oldFingerprint := o.digest("target-1800000000", "tcp\x00h0.test")
	clock.Store(epoch + 60)
	for i := 0; i < 2050; i++ {
		o.Observe("test-inbound", "PRIVATE-TEST-CREDENTIAL", "tcp", fmt.Sprintf("h%d.test", i), 443)
	}
	o.Observe("test-inbound", "unknown", "tcp", "example.test", 443)
	if _, ok := o.next.accounts[testSubject].targets[oldFingerprint]; ok {
		t.Fatal("fingerprints crossed minutes")
	}
	if _, ok := o.next.accounts[testSubject].targets[o.digest("target-1800000060", "tcp\x00h0.test")]; !ok {
		t.Fatal("lookahead fingerprint missing event window")
	}
	first := snapshot(t, o, epoch+60)[0]
	second := snapshot(t, o, epoch+120)[0]
	if first.Quality.DroppedRequests != 0 || first.Quality.UnmappedRequests != 0 || first.Subjects[0].Metrics.ProxyRequests != 1 {
		t.Fatal("lookahead contaminated old minute")
	}
	if second.Quality.DroppedRequests != 2 || second.Quality.UnmappedRequests != 1 || second.Subjects[0].Metrics.ProxyRequests != 2048 {
		t.Fatal("lookahead metrics/loss lost")
	}
}

func TestLookaheadCannotGrowPastOneMinuteOrHideDiscardedSamples(t *testing.T) {
	o, clock := sample(t)
	request(o)
	clock.Store(epoch + 60)
	request(o)
	clock.Store(epoch + 120)
	request(o)
	r := snapshot(t, o, epoch+180)[0]
	if len(r.Subjects) != 0 || !r.Quality.PartialWindow || !r.Quality.ClockDiscontinuity || r.Quality.DroppedRequests != 3 {
		t.Fatalf("outage hidden: %+v", r)
	}
	d := o.LossDiagnostics()
	if d.WindowBoundary != 1 || d.DiscardedSamples != 2 || o.next != nil {
		t.Fatal("outage loss ledger")
	}
	clock.Store(epoch + 180)
	request(o)
	r = snapshot(t, o, epoch+240)[0]
	if r.Subjects[0].Metrics.ProxyRequests != 1 || r.Quality.DroppedRequests != 0 {
		t.Fatal("outage recovery")
	}
}

func TestLookaheadSharesOriginalMemoryCaps(t *testing.T) {
	t.Run("accounts", func(t *testing.T) {
		bindings := map[int]string{}
		for i := 1; i <= 4096; i++ {
			bindings[i] = fmt.Sprintf("%032x", i)
		}
		o, clock := sample(t)
		if err := o.ReplaceRegistry("v2", map[string]map[int]string{"tag": bindings}); err != nil {
			t.Fatal(err)
		}
		for i := 1; i <= 4096; i++ {
			label := fmt.Sprintf("test-%d", i)
			o.Bind("tag", label, i)
			o.Observe("tag", label, "tcp", "example.test", 443)
		}
		clock.Store(epoch + 60)
		o.Observe("tag", "test-1", "tcp", "example.test", 443)
		if len(o.accounts) != 4096 || len(o.next.accounts) != 0 || o.next.lost != 1 {
			t.Fatal("lookahead exceeded account slots")
		}
		snapshot(t, o, epoch+60)
		o.Observe("tag", "test-1", "tcp", "example.test", 443)
		r := snapshot(t, o, epoch+120)[0]
		if r.Subjects[0].Metrics.ProxyRequests != 1 || r.Quality.DroppedRequests != 1 {
			t.Fatal("capacity not released after drain")
		}
	})
	t.Run("edges", func(t *testing.T) {
		o, clock := sample(t)
		for i := 0; i < 16; i++ {
			subject := fmt.Sprintf("%032x", i+10)
			o.registry["test-inbound"][i+10] = subject
			label := fmt.Sprintf("edge-%d", i)
			o.Bind("test-inbound", label, i+10)
			for j := 0; j < 2048; j++ {
				o.Observe("test-inbound", label, "tcp", fmt.Sprintf("h%d.test", j), uint16(j+1))
			}
		}
		if o.edges != 65536 {
			t.Fatal("test did not reach cap")
		}
		clock.Store(epoch + 60)
		request(o)
		if o.next.edges != 0 || o.next.lost != 1 || o.edges != 65536 {
			t.Fatal("lookahead exceeded edge limit")
		}
		snapshot(t, o, epoch+60)
		request(o)
		r := snapshot(t, o, epoch+120)[0]
		if r.Subjects[0].Metrics.ProxyRequests != 1 || r.Quality.DroppedRequests != 1 {
			t.Fatal("edge capacity not released")
		}
	})
}

func TestLookaheadInvalidatedOnRegistryReplacementAndReset(t *testing.T) {
	for _, reset := range []bool{false, true} {
		t.Run(fmt.Sprint(reset), func(t *testing.T) {
			o, clock := sample(t)
			request(o)
			clock.Store(epoch + 60)
			request(o)
			if reset {
				Set(o)
				defer Set(nil)
				Reset()
			} else {
				if err := o.ReplaceRegistry("next-v2", map[string]map[int]string{}); err != nil {
					t.Fatal(err)
				}
			}
			request(o) // Previous credential cannot survive either invalidation.
			first := snapshot(t, o, epoch+60)[0]
			second := snapshot(t, o, epoch+120)[0]
			if len(first.Subjects) != 0 || len(second.Subjects) != 0 || first.Quality.DroppedRequests != 2 || !first.Quality.PartialWindow || !second.Quality.PartialWindow || second.Quality.UnmappedRequests != 1 {
				t.Fatal("stale identity/counter survived reset")
			}
			if o.LossDiagnostics().DiscardedSamples != 2 {
				t.Fatal("discard not accounted")
			}
		})
	}
}

func TestClockReversalWithinLookaheadIsNotReassigned(t *testing.T) {
	o, clock := sample(t)
	request(o)
	clock.Store(epoch + 60)
	request(o)
	clock.Store(epoch)
	request(o)
	first := snapshot(t, o, epoch+60)[0]
	second := snapshot(t, o, epoch+120)[0]
	if first.Subjects[0].Metrics.ProxyRequests != 1 || second.Subjects[0].Metrics.ProxyRequests != 1 || !first.Quality.ClockDiscontinuity || first.Quality.DroppedRequests != 1 || !second.Quality.PartialWindow {
		t.Fatal("clock reversal hidden")
	}
}

func TestUnlockedLossConservativelyMarksAdjacentWindows(t *testing.T) {
	o, clock := sample(t)
	// Inject unavailable buffering so this remains a loss-quality test.
	o.pending = nil
	request(o)
	clock.Store(epoch + 60)
	o.mu.Lock()
	request(o)
	o.mu.Unlock()
	first := snapshot(t, o, epoch+60)[0]
	request(o)
	second := snapshot(t, o, epoch+120)[0]
	if first.Quality.DroppedRequests+second.Quality.DroppedRequests != 1 || !first.Quality.PartialWindow || !second.Quality.PartialWindow {
		t.Fatal("unscoped contention claimed clean boundary")
	}
}

func TestConcurrentLookaheadDrainConservesRequestsAndClosesOnce(t *testing.T) {
	o, clock := sample(t)
	request(o)
	clock.Store(epoch + 60)
	request(o)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var closed []Report
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 500; j++ {
				request(o)
			}
		}()
	}
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, err := o.Snapshot(time.Unix(epoch+60, 0))
			if err == nil {
				mu.Lock()
				closed = append(closed, r...)
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if len(closed) != 1 || closed[0].Subjects[0].Metrics.ProxyRequests != 1 {
		t.Fatal("duplicate close or next-minute event in old minute")
	}
	next := snapshot(t, o, epoch+120)
	a, l := total(closed)
	b, m := total(next)
	if a+b+l+m != 8002 || o.LossDiagnostics().WindowBoundary != 0 {
		t.Fatalf("unaccounted requests: accepted=%d lost=%d", a+b, l+m)
	}
	if _, err := o.Snapshot(time.Unix(epoch+120, 0)); err == nil {
		t.Fatal("window replay")
	}
}

func TestRepeatedMinuteTransitionsNoBoundaryLoss(t *testing.T) {
	o, clock := sample(t)
	request(o)
	for i := int64(1); i <= 120; i++ {
		clock.Store(epoch + i*60)
		request(o)
		r := snapshot(t, o, epoch+i*60)[0]
		if r.WindowStart != epoch+(i-1)*60 || r.WindowEnd != epoch+i*60 || r.Subjects[0].Metrics.ProxyRequests != 1 || r.Quality.DroppedRequests != 0 || r.Quality.PartialWindow {
			t.Fatalf("transition %d", i)
		}
	}
	if o.LossDiagnostics().WindowBoundary != 0 {
		t.Fatal("normal boundary lost requests")
	}
}
