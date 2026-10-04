package observer

import (
	"encoding/json"
	"sync"
	"testing"
	"time"
)

func TestMinuteBoundaryRequestsRetainTheirEventWindow(t *testing.T) {
	o, clock := sample(t)
	o.Observe("test-inbound", "PRIVATE-TEST-CREDENTIAL", "tcp", "example.test", 443)
	clock.Store(1800000060)
	// Emulate a request after a minute boundary but before the 250ms poll.
	o.Observe("test-inbound", "PRIVATE-TEST-CREDENTIAL", "tcp", "example.test", 443)
	r := snapshot(t, o, 1800000060)[0]
	if r.Quality.DroppedRequests != 0 || r.Subjects[0].Metrics.ProxyRequests != 1 || r.WindowStart != 1800000000 || r.WindowEnd != 1800000060 {
		t.Fatal("boundary regression")
	}
	if r.Subjects[0].Metrics.FailedConnections != nil {
		t.Fatal("telemetry loss invented as network failure")
	}
	o.Observe("test-inbound", "PRIVATE-TEST-CREDENTIAL", "tcp", "example.test", 443)
	next := snapshot(t, o, 1800000120)[0]
	if next.Quality.DroppedRequests != 0 || next.Subjects[0].Metrics.ProxyRequests != 2 || next.WindowStart != 1800000060 || next.WindowEnd != 1800000120 {
		t.Fatal("post-rotation collection")
	}
}

func TestRequestHotPathRemainsNonblocking(t *testing.T) {
	o, _ := sample(t)
	o.mu.Lock()
	done := make(chan struct{})
	go func() { o.Observe("test-inbound", "PRIVATE-TEST-CREDENTIAL", "tcp", "example.test", 443); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		o.mu.Unlock()
		t.Fatal("proxy path blocked on telemetry lock")
	}
	o.mu.Unlock()
	if n, lost := total(snapshot(t, o, 1800000060)); n != 1 || lost != 0 {
		t.Fatal("nonblocking burst was not recovered")
	}
}

func TestOpenWindowSnapshotAvoidsHotLock(t *testing.T) {
	o, _ := sample(t)
	o.mu.Lock()
	done := make(chan struct{})
	go func() {
		_, err := o.Snapshot(time.Unix(1800000030, 0))
		if err == nil {
			t.Error("open snapshot accepted")
		}
		close(done)
	}()
	select {
	case <-done:
		o.mu.Unlock()
	case <-time.After(100 * time.Millisecond):
		o.mu.Unlock()
		<-done
		t.Fatal("not-yet-closed snapshot waited on request lock")
	}
}

func TestConcurrentWindowClosureRemainsExactlyOnce(t *testing.T) {
	o, _ := sample(t)
	var mu sync.Mutex
	closed := 0
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := o.Snapshot(time.Unix(1800000060, 0)); err == nil {
				mu.Lock()
				closed++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if closed != 1 {
		t.Fatalf("closed %d times", closed)
	}
}

func TestQualityWireShapeUnchanged(t *testing.T) {
	o, _ := sample(t)
	r := snapshot(t, o, 1800000060)[0]
	raw, _ := json.Marshal(r)
	var decoded map[string]any
	if json.Unmarshal(raw, &decoded) != nil {
		t.Fatal("invalid JSON")
	}
	q := decoded["quality"].(map[string]any)
	if len(q) != 4 || decoded["complete"] != false {
		t.Fatal("wire compatibility or complete evidence changed")
	}
	for _, k := range []string{"partial_window", "clock_discontinuity", "dropped_requests", "unmapped_requests"} {
		if _, ok := q[k]; !ok {
			t.Fatal(k)
		}
	}
}

func BenchmarkOpenWindowSnapshot(b *testing.B) {
	o, _ := New(Config{Node: "demo", IdentityRevision: "v1", Bindings: map[string]map[int]string{}, Now: func() time.Time { return time.Unix(1800000000, 0) }})
	at := time.Unix(1800000030, 0)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = o.Snapshot(at)
	}
}
