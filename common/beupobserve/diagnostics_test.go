package observer

import (
	"fmt"
	"testing"
)

func TestDiagnosticReasonsConserveLossWithoutChangingReports(t *testing.T) {
	o, clock := sample(t)
	// Force overflow rather than assuming every contended sample is lost.
	o.pending = nil
	o.Observe("test-inbound", "PRIVATE-TEST-CREDENTIAL", "tcp", "example.test", 0)
	o.Observe("test-inbound", "PRIVATE-TEST-CREDENTIAL", "tcp", "invalid address", 443)
	o.mu.Lock()
	o.Observe("test-inbound", "PRIVATE-TEST-CREDENTIAL", "tcp", "example.test", 443)
	o.mu.Unlock()
	for i := 0; i < 2049; i++ {
		o.Observe("test-inbound", "PRIVATE-TEST-CREDENTIAL", "tcp", fmt.Sprintf("host%d.example.test", i), 443)
	}
	clock.Store(1799999940) // True clock rollback, not normal minute lookahead.
	o.Observe("test-inbound", "PRIVATE-TEST-CREDENTIAL", "tcp", "example.test", 443)
	r := snapshot(t, o, 1800000060)[0]
	d := o.LossDiagnostics()
	if d.InvalidInput != 2 || d.Contention != 1 || d.WindowBoundary != 1 || d.Capacity != 1 {
		t.Fatalf("wrong reasons: %+v", d)
	}
	if d.InvalidInput+d.Contention+d.WindowBoundary+d.Capacity != r.Quality.DroppedRequests {
		t.Fatal("loss total mismatch")
	}
	if r.Subjects[0].Metrics.ProxyRequests != 2048 || r.Complete {
		t.Fatal("report semantics changed")
	}
}
