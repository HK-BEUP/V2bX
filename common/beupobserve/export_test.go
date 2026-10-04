package observer

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

func diagnosticRuntime(t *testing.T) *Runtime {
	t.Helper()
	o, _ := sample(t)
	return &Runtime{Observer: o, queue: make(chan Report, 64), diagnosticQueue: make(chan diagnosticRecord, 1), diagnosticStartedAt: 1234}
}
func TestExportFiveReasonsAndNoReset(t *testing.T) {
	r := diagnosticRuntime(t)
	o := r.Observer
	o.pending = nil // Inject unavailable buffer to retain the five-loss oracle.
	o.Observe("test-inbound", "PRIVATE-TEST-CREDENTIAL", "tcp", "example.test", 0)
	o.mu.Lock()
	o.Observe("test-inbound", "PRIVATE-TEST-CREDENTIAL", "tcp", "example.test", 443)
	o.mu.Unlock()
	for i := 0; i < 2049; i++ {
		o.Observe("test-inbound", "PRIVATE-TEST-CREDENTIAL", "tcp", fmt.Sprintf("host%d.test", i), 443)
	}
	o.now = func() time.Time { return time.Unix(1799999940, 0) }
	o.Observe("test-inbound", "PRIVATE-TEST-CREDENTIAL", "tcp", "example.test", 443)
	o.mu.Lock()
	o.resetWindowsLocked()
	o.mu.Unlock()
	before := o.LossDiagnostics()
	d := r.diagnostics(time.Unix(1800000060, 0), Report{})
	if d.Loss != (diagnosticLoss{1, 1, 1, 1, 2048}) {
		t.Fatalf("unexpected synthetic reasons: %+v", d.Loss)
	}
	if before != o.LossDiagnostics() {
		t.Fatal("diagnostic read reset counters")
	}
	if r.diagnostics(time.Now(), Report{}).Loss != d.Loss {
		t.Fatal("totals not retained")
	}
}
func TestExportStrictPrivacySchema(t *testing.T) {
	r := diagnosticRuntime(t)
	r.settings = Settings{Node: "secret-node", Endpoint: "https://secret-endpoint.test", ObservationKey: "private-key"}
	report := Report{IdentityRevision: "secret-revision", BatchID: "secret-batch", Subjects: []Sample{{Subject: "secret-account"}}}
	b, err := json.Marshal(r.diagnostics(time.Now(), report))
	if err != nil || len(b) > 2047 {
		t.Fatal("invalid diagnostic")
	}
	for _, s := range []string{"secret-", "private-key", "PRIVATE-TEST-CREDENTIAL", "test-inbound", testSubject, "bindings", "signature"} {
		if bytes.Contains(b, []byte(s)) {
			t.Fatal("privacy leak")
		}
	}
	var obj map[string]any
	if json.Unmarshal(b, &obj) != nil {
		t.Fatal("json")
	}
	allowed := strings.Fields("kind version pid runtime_started_unix_ms observed_at counter_scope window_start window_end quality loss_totals delivery_totals export_skipped export_failed")
	if len(obj) != len(allowed) {
		t.Fatal("schema expanded")
	}
	for _, k := range allowed {
		if _, ok := obj[k]; !ok {
			t.Fatal(k)
		}
	}
	for _, key := range []string{"quality", "loss_totals", "delivery_totals"} {
		for _, v := range obj[key].(map[string]any) {
			switch v.(type) {
			case float64, bool:
			default:
				t.Fatal("non-numeric or boolean value")
			}
		}
	}
}
func TestExportPreservesReportBytesAndUnknowns(t *testing.T) {
	r := diagnosticRuntime(t)
	r.Observer.Observe("test-inbound", "PRIVATE-TEST-CREDENTIAL", "tcp", "private.test", 443)
	report := snapshot(t, r.Observer, 1800000060)[0]
	a, _ := json.Marshal(report)
	r.offerDiagnostics(time.Now(), report)
	b, _ := json.Marshal(report)
	if !bytes.Equal(a, b) || report.Complete || report.Subjects[0].Metrics.BytesIn != nil || report.Subjects[0].Metrics.FailedConnections != nil {
		t.Fatal("report or unknown changed")
	}
	if bytes.Contains(b, []byte("loss_totals")) {
		t.Fatal("diagnostics leaked into wire protocol")
	}
}
func TestExportDeliveryCountersAreIndependent(t *testing.T) {
	r := diagnosticRuntime(t)
	r.Sent.Store(1)
	r.Failed.Store(2)
	r.Expired.Store(3)
	r.QueueDropped.Store(4)
	r.StaleRevision.Store(5)
	r.RegistrationReloaded.Store(6)
	r.RegistrationRejected.Store(7)
	r.RegistrationExpired.Store(8)
	d := r.diagnostics(time.Now(), Report{})
	if d.Delivery != (diagnosticDelivery{1, 2, 3, 4, 5, 6, 7, 8}) || d.Loss != (diagnosticLoss{}) {
		t.Fatal("delivery confused with collection")
	}
}

type diagWriter func([]byte) (int, error)

func (w diagWriter) Write(b []byte) (int, error) { return w(b) }
func awaitCounter(t *testing.T, check func() bool) {
	t.Helper()
	end := time.Now().Add(2 * time.Second)
	for time.Now().Before(end) {
		if check() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("worker did not finish")
}
func TestExportOneLineAndCancellation(t *testing.T) {
	r := diagnosticRuntime(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	line := make(chan []byte, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		r.runDiagnostics(ctx, diagWriter(func(b []byte) (int, error) { line <- append([]byte(nil), b...); return len(b), nil }))
	}()
	r.offerDiagnostics(time.Now(), Report{WindowStart: 60, WindowEnd: 120})
	select {
	case b := <-line:
		if bytes.Count(b, []byte("\n")) != 1 || !json.Valid(bytes.TrimSpace(b)) {
			t.Fatal("invalid log line")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("missing log")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("cancellation")
	}
}
func TestExportBoundedUnderBlockedSink(t *testing.T) {
	r := diagnosticRuntime(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		r.runDiagnostics(ctx, diagWriter(func(b []byte) (int, error) { close(entered); <-release; return len(b), nil }))
	}()
	r.offerDiagnostics(time.Now(), Report{})
	<-entered
	for i := 0; i < 1000; i++ {
		r.offerDiagnostics(time.Now(), Report{})
	}
	if len(r.diagnosticQueue) != 1 || cap(r.diagnosticQueue) != 1 || r.diagnosticSkipped.Load() != 999 {
		t.Fatal("unbounded diagnostic queue")
	}
	r.Observer.Observe("test-inbound", "PRIVATE-TEST-CREDENTIAL", "tcp", "example.test", 443)
	if !r.Enqueue(Report{}) {
		t.Fatal("diagnostics blocked report queue")
	}
	if snapshot(t, r.Observer, 1800000060)[0].Subjects[0].Metrics.ProxyRequests != 1 {
		t.Fatal("diagnostics blocked sampling")
	}
	cancel()
	close(release)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("worker remains after release")
	}
}
func TestExportWriterFailuresDoNotAffectSampling(t *testing.T) {
	for _, w := range []io.Writer{diagWriter(func([]byte) (int, error) { return 0, errors.New("private-path-never-log") }), diagWriter(func(b []byte) (int, error) { return len(b) - 1, nil })} {
		r := diagnosticRuntime(t)
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() { defer close(done); r.runDiagnostics(ctx, w) }()
		r.offerDiagnostics(time.Now(), Report{})
		awaitCounter(t, func() bool { return r.diagnosticFailed.Load() == 1 })
		cancel()
		<-done
		r.Observer.Observe("test-inbound", "PRIVATE-TEST-CREDENTIAL", "tcp", "example.test", 443)
		if r.Observer.LossDiagnostics() != (LossDiagnostics{}) {
			t.Fatal("log error became sample loss")
		}
	}
}
func TestExportConcurrentReadAndLoss(t *testing.T) {
	r := diagnosticRuntime(t)
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 1000; j++ {
				r.Observer.Observe("test-inbound", "PRIVATE-TEST-CREDENTIAL", "tcp", "example.test", 0)
				r.offerDiagnostics(time.Now(), Report{})
			}
		}()
	}
	wg.Wait()
	d := r.diagnostics(time.Now(), Report{})
	if d.Loss.InvalidInput != 4000 || r.diagnosticSkipped.Load() != 3999 {
		t.Fatal("concurrent total lost")
	}
}
func TestExportAdjacentPartialWindowIsNotAnotherDrop(t *testing.T) {
	r := diagnosticRuntime(t)
	r.Observer.pending = nil // Exercise real loss, not recovered contention.
	r.Observer.mu.Lock()
	r.Observer.Observe("test-inbound", "PRIVATE-TEST-CREDENTIAL", "tcp", "example.test", 443)
	r.Observer.mu.Unlock()
	a := snapshot(t, r.Observer, 1800000060)[0]
	b := snapshot(t, r.Observer, 1800000120)[0]
	c := snapshot(t, r.Observer, 1800000180)[0]
	if a.Quality.DroppedRequests != 1 || b.Quality.DroppedRequests != 0 || !b.Quality.PartialWindow || c.Quality.PartialWindow {
		t.Fatal("adjacent quality semantics")
	}
	x := r.diagnostics(time.Now(), a)
	y := r.diagnostics(time.Now(), b)
	if !reflect.DeepEqual(x.Loss, y.Loss) || y.Loss.Contention != 1 {
		t.Fatal("carry double-counted")
	}
}

func TestExportRuntimeHookOnceForMultipleChunks(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, `{"data":{"observation_only":true}}`) }))
	defer srv.Close()
	r, err := NewRuntime(settings(srv.URL + "/api/v1/attack-guard/observation"))
	if err != nil {
		t.Fatal(err)
	}
	end := time.Now().Unix() / 60 * 60
	r.Observer.start = end - 60
	r.Observer.windowStart.Store(end - 60)
	for i := 0; i < 401; i++ {
		r.Observer.accounts[fmt.Sprintf("synthetic-%04d", i)] = &counts{targets: map[[32]byte]int64{}, ports: map[uint16]struct{}{}}
	}
	lines := make(chan []byte, 4)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		r.runWithDiagnosticSink(ctx, diagWriter(func(b []byte) (int, error) { lines <- append([]byte(nil), b...); return len(b), nil }))
	}()
	awaitCounter(t, func() bool { return r.Sent.Load() == 3 })
	select {
	case b := <-lines:
		var d diagnosticRecord
		if json.Unmarshal(b, &d) != nil || d.WindowEnd != end || d.RuntimeStartedAt <= 0 {
			t.Fatal("runtime record")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("runtime hook absent")
	}
	cancel()
	<-done
	if len(lines) != 0 {
		t.Fatal("logged per chunk rather than per window")
	}
}

func TestExportRuntimeShutdownDoesNotWaitForSink(t *testing.T) {
	r, err := NewRuntime(settings("http://127.0.0.1:1/api/v1/attack-guard/observation"))
	if err != nil {
		t.Fatal(err)
	}
	end := time.Now().Unix() / 60 * 60
	r.Observer.start = end - 60
	r.Observer.windowStart.Store(end - 60)
	entered, release, written := make(chan struct{}), make(chan struct{}), make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		r.runWithDiagnosticSink(ctx, diagWriter(func(b []byte) (int, error) { close(entered); <-release; close(written); return len(b), nil }))
	}()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("no diagnostic")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		close(release)
		t.Fatal("shutdown waited for stderr")
	}
	close(release)
	<-written
}
