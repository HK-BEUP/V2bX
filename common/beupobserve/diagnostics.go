package observer

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"time"
)

// Only fixed labels, numeric counters and quality booleans may leave this
// diagnostic path. Do not add Settings, Report, Subject, labels or error text.
type diagnosticRecord struct {
	Kind             string             `json:"kind"`
	Version          int                `json:"version"`
	PID              int                `json:"pid"`
	RuntimeStartedAt int64              `json:"runtime_started_unix_ms"`
	ObservedAt       int64              `json:"observed_at"`
	CounterScope     string             `json:"counter_scope"`
	WindowStart      int64              `json:"window_start"`
	WindowEnd        int64              `json:"window_end"`
	Quality          Quality            `json:"quality"`
	Loss             diagnosticLoss     `json:"loss_totals"`
	Delivery         diagnosticDelivery `json:"delivery_totals"`
	ExportSkipped    uint64             `json:"export_skipped"`
	ExportFailed     uint64             `json:"export_failed"`
}
type diagnosticLoss struct {
	InvalidInput     uint64 `json:"invalid_input"`
	Contention       uint64 `json:"contention"`
	WindowBoundary   uint64 `json:"window_boundary"`
	Capacity         uint64 `json:"capacity"`
	DiscardedSamples uint64 `json:"discarded_samples"`
}
type diagnosticDelivery struct {
	Sent                 uint64 `json:"sent"`
	Failed               uint64 `json:"failed"`
	Expired              uint64 `json:"expired"`
	QueueDropped         uint64 `json:"queue_dropped"`
	StaleRevision        uint64 `json:"stale_revision"`
	RegistrationReloaded uint64 `json:"registration_reloaded"`
	RegistrationRejected uint64 `json:"registration_rejected"`
	RegistrationExpired  uint64 `json:"registration_expired"`
}

// Called once per closed window, not per account/report chunk/request. Loads
// never reset counters or acquire the observer lock. Totals are approximate
// concurrent observations; their differences are not exact per-window losses.
func (r *Runtime) diagnostics(now time.Time, report Report) diagnosticRecord {
	d := r.Observer.LossDiagnostics()
	return diagnosticRecord{
		Kind: "beup_observation_diagnostics", Version: 1, PID: os.Getpid(),
		RuntimeStartedAt: r.diagnosticStartedAt, ObservedAt: now.Unix(),
		CounterScope: "runtime_lifetime_approximate",
		WindowStart:  report.WindowStart, WindowEnd: report.WindowEnd, Quality: report.Quality,
		Loss:          diagnosticLoss{d.InvalidInput, d.Contention, d.WindowBoundary, d.Capacity, d.DiscardedSamples},
		Delivery:      diagnosticDelivery{r.Sent.Load(), r.Failed.Load(), r.Expired.Load(), r.QueueDropped.Load(), r.StaleRevision.Load(), r.RegistrationReloaded.Load(), r.RegistrationRejected.Load(), r.RegistrationExpired.Load()},
		ExportSkipped: r.diagnosticSkipped.Load(), ExportFailed: r.diagnosticFailed.Load(),
	}
}

func (r *Runtime) offerDiagnostics(now time.Time, report Report) {
	value := r.diagnostics(now, report)
	select {
	case r.diagnosticQueue <- value:
	default:
		r.diagnosticSkipped.Add(1)
	}
}

// At most one in-flight line and one queued line per runtime. A blocked sink
// drops diagnostics rather than queueing unbounded work; no worker per sample.
// A permanently blocked stderr write can retain this one goroutine until exit.
func (r *Runtime) runDiagnostics(ctx context.Context, sink io.Writer) {
	for {
		select {
		case <-ctx.Done():
			return
		case value := <-r.diagnosticQueue:
			if ctx.Err() != nil {
				return
			}
			body, err := json.Marshal(value)
			if err != nil || len(body) > 2047 {
				r.diagnosticFailed.Add(1)
				continue
			}
			body = append(body, '\n')
			n, err := sink.Write(body)
			if err != nil || n != len(body) {
				r.diagnosticFailed.Add(1)
			}
		}
	}
}
