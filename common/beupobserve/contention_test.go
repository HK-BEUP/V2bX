package observer

import (
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"sync"
	"testing"
	"time"
)

// Opt-in synthetic workload, not a prediction of Japan traffic or network loss.
// Repeat with identical attempt counts/GOMAXPROCS; do not pass/fail on timing.
func TestContentionEvidence(t *testing.T) {
	if os.Getenv("BEUP_CONTENTION_EVIDENCE") != "synthetic-only" {
		t.Skip("opt-in benchmark")
	}
	for _, workers := range []int{1, 4, 16} {
		for round := 0; round < 5; round++ {
			o, _ := sample(t)
			const perWorker = 20000
			start := make(chan struct{})
			var wg sync.WaitGroup
			for w := 0; w < workers; w++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					<-start
					for j := 0; j < perWorker; j++ {
						request(o)
					}
				}()
			}
			at := time.Now()
			close(start)
			wg.Wait()
			elapsed := time.Since(at)
			r := snapshot(t, o, epoch+60)
			accepted, lost := total(r)
			d := o.LossDiagnostics()
			attempted := uint64(workers * perWorker)
			if accepted+lost != attempted || lost != d.Contention || d.InvalidInput+d.WindowBoundary+d.Capacity+d.DiscardedSamples != 0 || r[0].Quality.UnmappedRequests != 0 {
				t.Fatal("synthetic contention accounting mismatch")
			}
			v := map[string]any{"workers": workers, "round": round, "gomaxprocs": runtime.GOMAXPROCS(0), "attempted": attempted, "accepted": accepted, "lost": lost, "diagnostics": d, "elapsed_ns": elapsed.Nanoseconds()}
			b, _ := json.Marshal(v)
			fmt.Println("EVIDENCE " + string(b))
		}
	}
}

func BenchmarkObserveSerial(b *testing.B) {
	o, e := New(Config{Node: "synthetic", IdentityRevision: "v1", Bindings: map[string]map[int]string{"tag": {2: testSubject}}, Now: func() time.Time { return time.Unix(epoch, 0) }})
	if e != nil {
		b.Fatal(e)
	}
	o.Bind("tag", "synthetic-label", 2)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		o.Observe("tag", "synthetic-label", "tcp", "example.test", 443)
	}
}
