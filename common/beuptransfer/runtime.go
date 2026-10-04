package beuptransfer

import (
	"context"
	"errors"
	"sync"
)

type RuntimeControl interface {
	Poll(context.Context, string) ([]Command, error)
	Probe(context.Context, Command, ProbeStatus) error
}
type DrainReporter interface {
	Report(context.Context, string, DrainProof) (DrainAck, error)
}

// Runtime is a single-flight accounting/control cycle. The host must opt in
// before adding users and must never run the legacy counter-reset reporter.
type Runtime struct {
	mu           sync.Mutex
	scope, epoch string
	box          *Outbox
	adapter      DrainAdapter
	control      RuntimeControl
	reporter     DrainReporter
}

func NewRuntime(scope, epoch string, box *Outbox, adapter DrainAdapter, control RuntimeControl, reporter DrainReporter) (*Runtime, error) {
	if box == nil || adapter == nil || control == nil || reporter == nil || !scopePattern.MatchString(scope) || !validHex(epoch, 16) {
		return nil, ErrCoverage
	}
	box.mu.Lock()
	matches := box.state.Scope == scope && box.state.Epoch == epoch
	box.mu.Unlock()
	if !matches {
		return nil, ErrEpoch
	}
	return &Runtime{scope: scope, epoch: epoch, box: box, adapter: adapter, control: control, reporter: reporter}, nil
}
func (r *Runtime) Step(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	// A failed traffic delivery retains the journal; no positive capability is sent.
	totals, err := r.adapter.Snapshot(ctx)
	if err != nil {
		return err
	}
	if _, err = r.box.Flush(ctx, totals); err != nil {
		return err
	}
	commands, err := r.control.Poll(ctx, r.epoch)
	if err != nil {
		return err
	}
	if len(commands) > 32 {
		return ErrCoverage
	}
	// Validate the whole response before executing any disconnect command.
	seen := map[string]bool{}
	for _, cmd := range commands {
		if !cmd.valid(r.scope, r.epoch) || seen[cmd.Request.ID] {
			return ErrCoverage
		}
		seen[cmd.Request.ID] = true
	}
	var failures []error
	for _, cmd := range commands {
		if err = ctx.Err(); err != nil {
			return errors.Join(append(failures, err)...)
		}
		if cmd.Kind == "probe" {
			status, e := r.adapter.Inspect(ctx, cmd.Request.Identity)
			if e != nil || status.Epoch != r.epoch || status.Identity != cmd.Request.Identity {
				failures = append(failures, ErrCoverage)
				continue
			}
			ready := status.TrackingReady && r.box.probeReady(cmd.Request) == nil
			e = r.control.Probe(ctx, cmd, ProbeStatus{ready, status.RejectNew, status.Bindings, status.Outstanding})
			if e != nil {
				failures = append(failures, e)
			}
		} else {
			proof, e := r.box.Drain(ctx, cmd.Request, r.adapter)
			if e != nil {
				failures = append(failures, e)
				continue
			}
			ack, e := r.reporter.Report(ctx, cmd.Challenge, *proof)
			if e == nil && ack != (DrainAck{proof.Request.ID, proof.Scope, proof.Epoch, cmd.Challenge, proof.Receipt}) {
				e = errors.New("runtime drain acknowledgement mismatch")
			}
			if e != nil {
				failures = append(failures, e)
			}
		}
	}
	return errors.Join(failures...)
}
