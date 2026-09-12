package observer

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const testSubject = "00000000000000000000000000000002"

func sample(t *testing.T) (*Observer, *atomic.Int64) {
	t.Helper()
	clock := new(atomic.Int64)
	clock.Store(1800000000)
	o, err := New(Config{"demo-hk", "synthetic-v1", map[string]map[int]string{"test-inbound": {2: testSubject}}, func() time.Time { return time.Unix(clock.Load(), 0) }})
	if err != nil {
		t.Fatal(err)
	}
	if !o.Bind("test-inbound", "PRIVATE-TEST-CREDENTIAL", 2) {
		t.Fatal("binding failed")
	}
	return o, clock
}
func snapshot(t *testing.T, o *Observer, end int64) []Report {
	t.Helper()
	r, err := o.Snapshot(time.Unix(end, 0))
	if err != nil {
		t.Fatal(err)
	}
	return r
}
func TestKnownAndUnknownMetrics(t *testing.T) {
	o, _ := sample(t)
	for i := 0; i < 10; i++ {
		o.Observe("test-inbound", "PRIVATE-TEST-CREDENTIAL", "tcp", "private.example.test", 443)
	}
	o.Observe("test-inbound", "PRIVATE-TEST-CREDENTIAL", "udp", "192.0.2.10", 53)
	r := snapshot(t, o, 1800000060)[0]
	m := r.Subjects[0].Metrics
	if r.Complete || m.ProxyRequests != 11 || m.TCPRequests != 10 || m.UDPAssociations != 1 || m.DistinctTargets != 2 || m.DistinctPorts != 2 || m.MaxTargetRequests != 10 {
		t.Fatalf("invalid aggregate: %+v", m)
	}
	if m.FailedConnections != nil || m.UDPPackets != nil || m.BytesOut != nil || m.BytesIn != nil {
		t.Fatal("unknown metrics fabricated")
	}
	b, h, err := o.Encode(r, []byte(strings.Repeat("synthetic-only-", 3)), time.Unix(1800000060, 0))
	if err != nil || len(h["signature"]) != 64 {
		t.Fatal("encode", err)
	}
	for _, secret := range []string{"PRIVATE-TEST-CREDENTIAL", "private.example.test", "192.0.2.10", "test-inbound", "\"uid\""} {
		if strings.Contains(string(b), secret) {
			t.Fatal("privacy leak:", secret)
		}
	}
	if !strings.Contains(string(b), `"failed_connections":null`) {
		t.Fatal("null lost")
	}
	if r.Quality.DroppedRequests != 0 || r.Quality.UnmappedRequests != 0 || r.Quality.PartialWindow {
		t.Fatal("unexpected loss")
	}
}
func TestBindingTrustAndRevocation(t *testing.T) {
	o, _ := sample(t)
	o.Observe("other-inbound", "PRIVATE-TEST-CREDENTIAL", "tcp", "example.test", 443)
	o.Observe("test-inbound", "invented-label", "tcp", "example.test", 443)
	if o.Bind("test-inbound", "invented-label", 999) {
		t.Fatal("unregistered UID accepted")
	}
	o.Unbind("test-inbound", "PRIVATE-TEST-CREDENTIAL")
	o.Observe("test-inbound", "PRIVATE-TEST-CREDENTIAL", "tcp", "example.test", 443)
	r := snapshot(t, o, 1800000060)[0]
	if len(r.Subjects) != 0 || r.Quality.UnmappedRequests != 3 {
		t.Fatal("unmapped account attributed")
	}
}
func TestBoundsAndContention(t *testing.T) {
	o, _ := sample(t)
	for i := 0; i < 2050; i++ {
		o.Observe("test-inbound", "PRIVATE-TEST-CREDENTIAL", "tcp", fmt.Sprintf("host%d.example.test", i), 443)
	}
	o.mu.Lock()
	o.Observe("test-inbound", "PRIVATE-TEST-CREDENTIAL", "tcp", "example.test", 443)
	o.mu.Unlock()
	r := snapshot(t, o, 1800000060)[0]
	if r.Subjects[0].Metrics.DistinctTargets != 2048 || r.Quality.DroppedRequests != 3 {
		t.Fatal("unbounded or unreported loss")
	}
}
func TestClockAndPartialWindow(t *testing.T) {
	o, clock := sample(t)
	clock.Store(1800000060)
	o.Observe("test-inbound", "PRIVATE-TEST-CREDENTIAL", "tcp", "example.test", 443)
	r := snapshot(t, o, 1800000120)[0]
	if !r.Quality.ClockDiscontinuity || !r.Quality.PartialWindow || len(r.Subjects) != 0 {
		t.Fatal("timer outage hidden")
	}
	clock.Store(1799999940)
	o.Observe("test-inbound", "PRIVATE-TEST-CREDENTIAL", "tcp", "example.test", 443)
	r = snapshot(t, o, 1800000180)[0]
	if !r.Quality.ClockDiscontinuity || r.Quality.DroppedRequests != 1 {
		t.Fatal("rollback hidden")
	}
	if _, err := o.Snapshot(time.Unix(1800000180, 0)); err == nil {
		t.Fatal("window replay")
	}
	partial, err := New(Config{"node", "revision", nil, func() time.Time { return time.Unix(1800000010, 0) }})
	if err != nil {
		t.Fatal(err)
	}
	if !snapshot(t, partial, 1800000060)[0].Quality.PartialWindow {
		t.Fatal("warmup hidden")
	}
}
func TestConcurrentAccountingAndNoPayload(t *testing.T) {
	o, _ := sample(t)
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for n := 0; n < 500; n++ {
				o.Observe("test-inbound", "PRIVATE-TEST-CREDENTIAL", "tcp", "example.test", 443)
			}
		}()
	}
	wg.Wait()
	r := snapshot(t, o, 1800000060)[0]
	var n int64
	if len(r.Subjects) > 0 {
		n = r.Subjects[0].Metrics.ProxyRequests
	}
	if uint64(n)+r.Quality.DroppedRequests != 8000 {
		t.Fatal("silent loss")
	}
}
func TestChunksAndDisabledGlobal(t *testing.T) {
	bindings := map[int]string{}
	for i := 1; i <= 401; i++ {
		bindings[i] = fmt.Sprintf("%032x", i)
	}
	o, err := New(Config{"demo-hk", "synthetic-v1", map[string]map[int]string{"tag": bindings}, func() time.Time { return time.Unix(1800000000, 0) }})
	if err != nil {
		t.Fatal(err)
	}
	Set(nil)
	Record("tag", "a", "tcp", "example.test", 443)
	Set(o)
	defer Set(nil)
	for i := 1; i <= 401; i++ {
		label := fmt.Sprintf("label%d", i)
		Bind("tag", label, i)
		Record("tag", label, "tcp", "example.test", 443)
	}
	r := snapshot(t, o, 1800000060)
	if len(r) != 3 || len(r[0].Subjects) != 200 || len(r[1].Subjects) != 200 || len(r[2].Subjects) != 1 {
		t.Fatal("chunk sizes")
	}
	if r[0].BatchID == r[1].BatchID {
		t.Fatal("batch collision")
	}
	for _, part := range r {
		if _, err := json.Marshal(part); err != nil {
			t.Fatal(err)
		}
	}
}
func TestRegistrationValidation(t *testing.T) {
	for _, subject := range []string{"2", "uuid-like-value", strings.Repeat("A", 32)} {
		if _, err := New(Config{Node: "demo-hk", IdentityRevision: "v1", Bindings: map[string]map[int]string{"t": {2: subject}}}); err == nil {
			t.Fatal("unsafe subject accepted")
		}
	}
	o, _ := sample(t)
	r := snapshot(t, o, 1800000060)[0]
	r.Complete = true
	if _, _, err := o.Encode(r, []byte(strings.Repeat("a", 32)), time.Unix(1800000060, 0)); err == nil {
		t.Fatal("complete observation accepted")
	}
}
func BenchmarkObserver(b *testing.B) {
	o, _ := New(Config{"node", "v1", map[string]map[int]string{"tag": {2: testSubject}}, func() time.Time { return time.Unix(1800000000, 0) }})
	o.Bind("tag", "label", 2)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		o.Observe("tag", "label", "tcp", "example.test", 443)
	}
}
