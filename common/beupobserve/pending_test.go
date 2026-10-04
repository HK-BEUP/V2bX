package observer

import (
	"fmt"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestPendingPausedPreparationIsNotClockReversal(t *testing.T) {
	o, _ := sample(t)
	var calls atomic.Int64
	paused, resume, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	o.now = func() time.Time {
		if calls.Add(1) == 1 {
			close(paused)
			<-resume
			return time.Unix(epoch, 0)
		}
		return time.Unix(epoch+60, 0)
	}
	go func() { request(o); close(done) }()
	<-paused
	request(o)
	close(resume)
	<-done
	first := snapshot(t, o, epoch+60)
	second := snapshot(t, o, epoch+120)
	n, l := total(first)
	m, k := total(second)
	if n+m != 2 || l+k != 0 || first[0].Quality.ClockDiscontinuity || second[0].Quality.ClockDiscontinuity {
		t.Fatal("scheduler pause was misclassified as clock reversal")
	}
}

func TestPendingPerCallDrainIsBounded(t *testing.T) {
	o, _ := sample(t)
	holdBurst(t, o, 100)
	request(o)
	if len(o.pending) != 100-pendingDrainBudget {
		t.Fatal("producer drained an unbounded backlog")
	}
	if n, l := total(snapshot(t, o, epoch+60)); n != 101 || l != 0 {
		t.Fatal("bounded drain lost data")
	}
}

func TestPendingThreeCleanSyntheticWindows(t *testing.T) {
	o, clock := sample(t)
	for minute := int64(0); minute < 3; minute++ {
		clock.Store(epoch + minute*60)
		for burst := 0; burst < 40; burst++ {
			var wg sync.WaitGroup
			for worker := 0; worker < 4; worker++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for j := 0; j < 32; j++ {
						request(o)
					}
				}()
			}
			wg.Wait()
			o.Snapshot(time.Unix(epoch+minute*60+10, 0))
		}
		r := snapshot(t, o, epoch+(minute+1)*60)
		if n, l := total(r); n != 5120 || l != 0 || r[0].Quality.PartialWindow || r[0].Quality.ClockDiscontinuity || r[0].Quality.UnmappedRequests != 0 {
			t.Fatal("bounded burst window not complete")
		}
	}
}

func TestPendingUnrelatedIdentityChangeRemainsConservative(t *testing.T) {
	o, _ := sample(t)
	holdBurst(t, o, 20)
	o.Bind("test-inbound", "new-label", 2)
	r := snapshot(t, o, epoch+60)
	if n, l := total(r); n != 0 || l != 20 || !r[0].Quality.PartialWindow || o.LossDiagnostics().DiscardedSamples != 20 {
		t.Fatal("global generation safety was weakened")
	}
}

func holdBurst(t *testing.T, o *Observer, n int) {
	t.Helper()
	o.mu.Lock()
	done := make(chan struct{})
	go func() {
		for i := 0; i < n; i++ {
			request(o)
		}
		close(done)
	}()
	select {
	case <-done:
		o.mu.Unlock()
	case <-time.After(2 * time.Second):
		o.mu.Unlock()
		<-done
		t.Fatal("producer waited for telemetry lock")
	}
}

func TestPendingRecoversBoundedContentionWithoutWaiting(t *testing.T) {
	o, _ := sample(t)
	holdBurst(t, o, pendingCapacity)
	if len(o.pending) != pendingCapacity {
		t.Fatal("burst not retained")
	}
	r := snapshot(t, o, epoch+60)
	n, lost := total(r)
	if n != pendingCapacity || lost != 0 || len(o.pending) != 0 || r[0].Quality.PartialWindow || o.LossDiagnostics().Contention != 0 {
		t.Fatal("retained samples reported as loss")
	}
}

func TestPendingOverflowRemainsBoundedVisibleAndConserved(t *testing.T) {
	o, _ := sample(t)
	holdBurst(t, o, pendingCapacity+37)
	r := snapshot(t, o, epoch+60)
	n, lost := total(r)
	if n != pendingCapacity || lost != 37 || o.LossDiagnostics().Contention != 37 || !r[0].Quality.PartialWindow {
		t.Fatal("overflow hidden")
	}
	b := snapshot(t, o, epoch+120)[0]
	c := snapshot(t, o, epoch+180)[0]
	if b.Quality.DroppedRequests != 0 || !b.Quality.PartialWindow || c.Quality.PartialWindow {
		t.Fatal("conservative adjacent quality changed")
	}
}

func TestPendingIdlePollDrainsWithoutClosingWindow(t *testing.T) {
	o, _ := sample(t)
	holdBurst(t, o, 25)
	if _, err := o.Snapshot(time.Unix(epoch+10, 0)); err == nil {
		t.Fatal("open window closed")
	}
	if len(o.pending) != 0 {
		t.Fatal("idle burst stuck until minute close")
	}
	if n, l := total(snapshot(t, o, epoch+60)); n != 25 || l != 0 {
		t.Fatal("poll accounting")
	}
}

func TestPendingBusyPollDoesNotWait(t *testing.T) {
	o, _ := sample(t)
	holdBurst(t, o, 1)
	o.mu.Lock()
	done := make(chan struct{})
	go func() { o.Snapshot(time.Unix(epoch+10, 0)); close(done) }()
	select {
	case <-done:
		o.mu.Unlock()
	case <-time.After(time.Second):
		o.mu.Unlock()
		<-done
		t.Fatal("poll blocked")
	}
	if n, l := total(snapshot(t, o, epoch+60)); n != 1 || l != 0 {
		t.Fatal("busy poll lost sample")
	}
}

func TestPendingStoresOnlyFixedSizeFingerprints(t *testing.T) {
	typ := reflect.TypeOf(pendingRequest{})
	if typ.Size()*pendingCapacity > 64*1024 {
		t.Fatal("pending payload exceeds 64KiB")
	}
	for i := 0; i < typ.NumField(); i++ {
		k := typ.Field(i).Type.Kind()
		if k == reflect.String || k == reflect.Slice || k == reflect.Map || k == reflect.Pointer || k == reflect.Interface {
			t.Fatal("raw or unbounded pending data")
		}
	}
	o, _ := sample(t)
	if cap(o.pending) != pendingCapacity {
		t.Fatal("capacity drift")
	}
}

func TestPendingLateDrainKeepsOriginalMinutes(t *testing.T) {
	o, clock := sample(t)
	holdBurst(t, o, 300)
	clock.Store(epoch + 60)
	holdBurst(t, o, 100)
	request(o) // Drain eight old entries, then record a new-minute direct request.
	first := snapshot(t, o, epoch+60)
	second := snapshot(t, o, epoch+120)
	a, l := total(first)
	b, m := total(second)
	if a != 300 || b != 101 || l+m != 0 || first[0].Quality.ClockDiscontinuity || second[0].Quality.ClockDiscontinuity {
		t.Fatal("buffer moved samples between minutes")
	}
}

func TestPendingClockReversalIsStillVisible(t *testing.T) {
	o, clock := sample(t)
	holdBurst(t, o, 1)
	clock.Store(epoch + 60)
	holdBurst(t, o, 1)
	clock.Store(epoch)
	holdBurst(t, o, 1)
	a := snapshot(t, o, epoch+60)
	b := snapshot(t, o, epoch+120)
	n, l := total(a)
	m, k := total(b)
	if n+m != 2 || l+k != 1 || !a[0].Quality.ClockDiscontinuity || o.LossDiagnostics().WindowBoundary != 1 {
		t.Fatal("clock reversal hidden")
	}
}

func TestPendingTooLateForClosedWindowIsNotMoved(t *testing.T) {
	o, _ := sample(t)
	e := pendingRequest{o.labelKey("test-inbound", "PRIVATE-TEST-CREDENTIAL"), o.digest("target-1800000000", "tcp\x00example.test"), epoch, o.generation.Load(), 443, true, 0}
	snapshot(t, o, epoch+60)
	o.pending <- e // Emulate a producer completing its enqueue after the close.
	r := snapshot(t, o, epoch+120)
	if n, l := total(r); n != 0 || l != 1 || !r[0].Quality.PartialWindow {
		t.Fatal("late sample was reassigned or hidden")
	}
}

func TestPendingUnbindRebindCannotAttributeOldRequestsToNewUID(t *testing.T) {
	o, _ := sample(t)
	if err := o.ReplaceRegistry("v2", map[string]map[int]string{"test-inbound": {2: testSubject, 3: fmt.Sprintf("%032x", 3)}}); err != nil {
		t.Fatal(err)
	}
	holdBurst(t, o, 40)
	o.Unbind("test-inbound", "PRIVATE-TEST-CREDENTIAL")
	o.Bind("test-inbound", "PRIVATE-TEST-CREDENTIAL", 3)
	request(o)
	r := snapshot(t, o, epoch+60)
	if n, l := total(r); n != 1 || l != 40 || r[0].Subjects[0].Subject != fmt.Sprintf("%032x", 3) || o.LossDiagnostics().DiscardedSamples != 40 {
		t.Fatal("stale queue crossed identity")
	}
}

func TestPendingUnchangedBindDoesNotInvalidateBurst(t *testing.T) {
	o, _ := sample(t)
	holdBurst(t, o, 40)
	o.Bind("test-inbound", "PRIVATE-TEST-CREDENTIAL", 2)
	if n, l := total(snapshot(t, o, epoch+60)); n != 40 || l != 0 {
		t.Fatal("unchanged binding discarded samples")
	}
}

func TestPendingRegistryReplacementAndCoreResetDiscardExactlyOnce(t *testing.T) {
	for _, reset := range []bool{false, true} {
		t.Run(fmt.Sprint(reset), func(t *testing.T) {
			o, _ := sample(t)
			request(o)
			holdBurst(t, o, 40)
			if reset {
				Set(o)
				defer Set(nil)
				Reset()
			} else {
				if err := o.ReplaceRegistry("v2", map[string]map[int]string{}); err != nil {
					t.Fatal(err)
				}
			}
			r := snapshot(t, o, epoch+60)
			if n, l := total(r); n != 0 || l != 41 || o.LossDiagnostics().DiscardedSamples != 41 || len(o.pending) != 0 {
				t.Fatal("reset accounting or stale identity")
			}
		})
	}
}

func TestPendingMutationInProgressIsNeverAccepted(t *testing.T) {
	o, _ := sample(t)
	o.mu.Lock()
	o.generation.Add(1)
	request(o)
	o.generation.Add(1)
	o.mu.Unlock()
	if n, l := total(snapshot(t, o, epoch+60)); n != 0 || l != 1 || o.LossDiagnostics().DiscardedSamples != 1 {
		t.Fatal("odd mutation epoch accepted")
	}
}

func TestPendingPreparationCannotRaceIdentityReplacement(t *testing.T) {
	o, _ := sample(t)
	first := true
	o.now = func() time.Time {
		if first {
			first = false
			o.Unbind("test-inbound", "PRIVATE-TEST-CREDENTIAL")
			o.Bind("test-inbound", "PRIVATE-TEST-CREDENTIAL", 2)
		}
		return time.Unix(epoch, 0)
	}
	request(o)
	if n, l := total(snapshot(t, o, epoch+60)); n != 0 || l != 1 {
		t.Fatal("prepared request survived identity mutation")
	}
}

func TestPendingConcurrentIdentityChangesConserveAllAttempts(t *testing.T) {
	o, _ := sample(t)
	const workers = 4
	const each = 3000
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < each; j++ {
				request(o)
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for j := 0; j < 100; j++ {
			o.Unbind("test-inbound", "PRIVATE-TEST-CREDENTIAL")
			o.Bind("test-inbound", "PRIVATE-TEST-CREDENTIAL", 2)
		}
	}()
	wg.Wait()
	r := snapshot(t, o, epoch+60)
	n, l := total(r)
	if n+l+r[0].Quality.UnmappedRequests != workers*each {
		t.Fatal("attempts lost during concurrent identity changes")
	}
	d := o.LossDiagnostics()
	if l != d.Contention+d.DiscardedSamples {
		t.Fatal("unexplained loss")
	}
}

func TestPendingConcurrentRosterResetsConserveAllAttempts(t *testing.T) {
	o, _ := sample(t)
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 2000; j++ {
				request(o)
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for j := 0; j < 30; j++ {
			if e := o.ReplaceRegistry(fmt.Sprintf("v%d", j), map[string]map[int]string{"test-inbound": {2: testSubject}}); e != nil {
				t.Error(e)
			}
		}
	}()
	wg.Wait()
	r := snapshot(t, o, epoch+60)
	n, l := total(r)
	if n+l+r[0].Quality.UnmappedRequests != 8000 {
		t.Fatal("attempts lost across roster resets")
	}
}

func TestPendingMixedTCPUDPMetadataAndUnknowns(t *testing.T) {
	o, _ := sample(t)
	o.mu.Lock()
	o.Observe("test-inbound", "PRIVATE-TEST-CREDENTIAL", "tcp", "EXAMPLE.TEST.", 443)
	o.Observe("test-inbound", "PRIVATE-TEST-CREDENTIAL", "tcp", "example.test", 443)
	o.Observe("test-inbound", "PRIVATE-TEST-CREDENTIAL", "udp", "192.0.2.1", 53)
	o.mu.Unlock()
	r := snapshot(t, o, epoch+60)[0]
	m := r.Subjects[0].Metrics
	if m.ProxyRequests != 3 || m.TCPRequests != 2 || m.UDPAssociations != 1 || m.DistinctTargets != 2 || m.DistinctPorts != 2 || m.MaxTargetRequests != 2 || m.FailedConnections != nil || m.UDPPackets != nil || m.BytesIn != nil || r.Complete {
		t.Fatal("metadata or unknown contract changed")
	}
}
