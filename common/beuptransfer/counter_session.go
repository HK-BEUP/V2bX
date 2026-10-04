package beuptransfer

import (
	"context"
	"errors"
	"math"
	"sync/atomic"
	"time"
)

// Epoch is the logical cumulative accounting stream. Process-local Xray
// counters may restart only after a sealed, fully acknowledged shutdown. The
// carried base keeps the logical stream monotonic across that clean restart.
var ErrUnsealed = errors.Join(ErrEpoch, errors.New("unsealed counter process requires uncertain recovery"))

type uncleanRecovery struct {
	Count           uint64 `json:"count"`
	Since           int64  `json:"since"`
	PreviousProcess string `json:"previous_process"`
}

type counterSession struct {
	Process  string           `json:"process"`
	Base     []Sample         `json:"base"`
	Sealed   bool             `json:"sealed"`
	Recovery *uncleanRecovery `json:"unclean_recovery,omitempty"`
}

type QuiescingAdapter interface {
	DrainAdapter
	Quiesce(context.Context) error
	RestoreSealedIdentities([]Identity) error
}

type CounterSession struct {
	inner          QuiescingAdapter
	base           []Sample
	process, epoch string
	box            *Outbox
	sealed         atomic.Bool
	uncertain      bool
}

func validateCounterSession(s journal) error {
	if s.Session == nil {
		return nil
	}
	if !validHex(s.Session.Process, 16) || s.Session.Base == nil {
		return ErrEpoch
	}
	if _, err := samples(s.Session.Base); err != nil {
		return err
	}
	if _, err := delta(s.Session.Base, s.Committed); err != nil {
		return ErrEpoch
	}
	if r := s.Session.Recovery; r != nil && (r.Count == 0 || r.Count > 1<<53 || r.Since <= 0 || !validHex(r.PreviousProcess, 16)) {
		return ErrEpoch
	}
	if s.Session.Sealed && (s.Pending != nil || s.LastAck == nil) {
		return ErrEpoch
	}
	return nil
}

// BeginCounterSession must run on a newly created, empty inbound, before users
// are added. process must be a fresh cryptographic nonce for this startup. An
// unsealed journal cannot be relabelled as a new process, even with zero usage.
func (o *Outbox) BeginCounterSession(ctx context.Context, process string, inner QuiescingAdapter) (*CounterSession, error) {
	return o.beginCounterSession(ctx, process, inner, false)
}

// ResumeUncleanCounterSession resumes known, acknowledged counters for normal
// service only. It durably records missing-tail uncertainty for this epoch;
// Inspect can never produce a new positive migration proof afterward. This is
// not reconciliation and does not invent or forgive unpersisted traffic.
func (o *Outbox) ResumeUncleanCounterSession(ctx context.Context, process string, inner QuiescingAdapter) (*CounterSession, error) {
	return o.beginCounterSession(ctx, process, inner, true)
}

func (o *Outbox) beginCounterSession(ctx context.Context, process string, inner QuiescingAdapter, uncertainRecovery bool) (*CounterSession, error) {
	if !validHex(process, 16) || inner == nil {
		return nil, ErrCoverage
	}
	raw, err := inner.Snapshot(ctx)
	if err != nil {
		return nil, err
	}
	if len(raw) != 0 {
		return nil, ErrCoverage
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.poisoned {
		return nil, ErrUncertain
	}
	if uncertainRecovery && (o.state.Session == nil || o.state.Session.Sealed) {
		return nil, ErrEpoch
	}
	if o.state.Session != nil {
		if o.state.Session.Process == process || o.state.Pending != nil {
			return nil, ErrEpoch
		}
		if !o.state.Session.Sealed && !uncertainRecovery {
			return nil, ErrUnsealed
		}
	} else if o.state.Next != 1 || len(o.state.Committed) != 0 || o.state.Pending != nil || len(o.state.Drains) != 0 || len(o.state.Reservations) != 0 {
		return nil, ErrEpoch
	}
	s := clone(o.state)
	base := append([]Sample{}, s.Committed...)
	var recovery *uncleanRecovery
	if s.Session != nil {
		recovery = s.Session.Recovery
	}
	if uncertainRecovery {
		if recovery == nil {
			recovery = &uncleanRecovery{Since: time.Now().Unix()}
		}
		if recovery.Count >= 1<<53 {
			return nil, ErrEpoch
		}
		recovery.Count++
		recovery.PreviousProcess = s.Session.Process
	}
	s.Session = &counterSession{Process: process, Base: base, Recovery: recovery}
	if err = o.save(s); err != nil {
		return nil, err
	}
	a := &CounterSession{inner: inner, base: base, process: process, epoch: s.Epoch, box: o, uncertain: recovery != nil}
	identities := make([]Identity, 0, len(base))
	for _, b := range base {
		identities = append(identities, Identity{b.UID, b.Credential})
	}
	if err = inner.RestoreSealedIdentities(identities); err != nil {
		return nil, err
	}
	// Existing migration holds survive clean restarts. Shutdown-only fences do not.
	for _, d := range s.Drains {
		if err = inner.Fence(ctx, d.Request.Identity); err != nil {
			return nil, err
		}
	}
	return a, nil
}

func (s *CounterSession) Uncertain() bool { return s.uncertain }

func (s *CounterSession) Snapshot(ctx context.Context) ([]Sample, error) {
	if s.sealed.Load() {
		return nil, ErrEpoch
	}
	raw, err := s.inner.Snapshot(ctx)
	if err != nil {
		return nil, err
	}
	raw, err = samples(raw)
	if err != nil {
		return nil, err
	}
	combined := make(map[string]Sample, len(s.base)+len(raw))
	for _, b := range s.base {
		combined[key(b)] = b
	}
	for _, r := range raw {
		b := combined[key(r)]
		if r.Upload > math.MaxInt64-b.Upload || r.Download > math.MaxInt64-b.Download {
			return nil, errors.New("cumulative restart counter overflow")
		}
		r.Upload += b.Upload
		r.Download += b.Download
		combined[key(r)] = r
	}
	out := make([]Sample, 0, len(combined))
	for _, row := range combined {
		out = append(out, row)
	}
	return samples(out)
}
func (s *CounterSession) Fence(ctx context.Context, id Identity) error { return s.inner.Fence(ctx, id) }
func (s *CounterSession) Inspect(ctx context.Context, id Identity) (FenceStatus, error) {
	status, err := s.inner.Inspect(ctx, id)
	if err != nil {
		return status, err
	}
	if status.Epoch != s.epoch || status.Identity != id {
		return FenceStatus{}, ErrCoverage
	}
	if s.uncertain {
		status.TrackingReady = false
	}
	return status, nil
}
func (s *CounterSession) Quiesce(ctx context.Context) error {
	if err := s.inner.Quiesce(ctx); err != nil {
		return err
	}
	for _, b := range s.base {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := s.inner.Fence(ctx, Identity{b.UID, b.Credential}); err != nil {
			return err
		}
	}
	return nil
}
func (s *CounterSession) closed(ctx context.Context, rows []Sample) error {
	for _, r := range rows {
		id := Identity{r.UID, r.Credential}
		// Seal checks this process's lifecycle, not the historical uncertainty.
		// The marker survives the seal; migration Inspect above remains false.
		status, err := s.inner.Inspect(ctx, id)
		if err == nil && (status.Epoch != s.epoch || status.Identity != id) {
			return ErrCoverage
		}
		if err != nil {
			return err
		}
		if !status.TrackingReady || !status.RejectNew || status.Bindings < 1 || status.Outstanding != 0 {
			return ErrPending
		}
	}
	return nil
}

// Seal is called after stopping/joining the worker and all user-list updates,
// while counters still exist. Failure retains the unsealed journal and fences;
// the caller may retry but must not claim a clean restart or discard the store.
func (s *CounterSession) Seal(ctx context.Context) error {
	if err := s.Quiesce(ctx); err != nil {
		return err
	}
	o := s.box
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.poisoned {
		return ErrUncertain
	}
	if o.state.Session == nil || o.state.Session.Process != s.process {
		return ErrEpoch
	}
	if o.state.Session.Sealed {
		return nil
	}
	rows, err := s.Snapshot(ctx)
	if err != nil {
		return err
	}
	if err = s.closed(ctx, rows); err != nil {
		return err
	}
	if o.legacy {
		err = o.flushLegacySeal(ctx, rows)
	} else {
		_, err = o.flush(ctx, rows)
	}
	if err != nil {
		return err
	}
	after, err := s.Snapshot(ctx)
	if err != nil {
		return err
	}
	if err = s.closed(ctx, after); err != nil {
		return err
	}
	if len(rows) != len(after) {
		return ErrPending
	}
	for i := range rows {
		if rows[i] != after[i] {
			return ErrPending
		}
	}
	state := clone(o.state)
	state.Session.Sealed = true
	if err = o.save(state); err != nil {
		return err
	}
	s.sealed.Store(true)
	return nil
}
