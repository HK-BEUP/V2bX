package beuptransfer

import (
	"context"
	"errors"
)

type Identity struct {
	UID        int64  `json:"uid"`
	Credential string `json:"credential"`
}
type DrainRequest struct {
	ID       string   `json:"id"`
	Identity Identity `json:"identity"`
}
type FenceStatus struct {
	Epoch         string
	Identity      Identity
	RejectNew     bool
	Outstanding   int
	TrackingReady bool
	Bindings      int
}

// Adapter contract: Fence atomically excludes new authenticated flows from all
// bound entrypoints and closes tracked handlers. Outstanding reaches zero only
// after their final accounting writes. Fences survive until explicitly released
// by a separate, authorized reconciliation step. Snapshot includes all retained
// counters and must never also feed the legacy reset-based reporting path.
type DrainAdapter interface {
	Fence(context.Context, Identity) error
	Inspect(context.Context, Identity) (FenceStatus, error)
	Snapshot(context.Context) ([]Sample, error)
}
type DrainProof struct {
	Request DrainRequest `json:"request"`
	Scope   string       `json:"scope"`
	Epoch   string       `json:"epoch"`
	Final   Sample       `json:"final"`
	Receipt Ack          `json:"receipt"`
}
type drainRecord struct {
	Request DrainRequest `json:"request"`
	Proof   *DrainProof  `json:"proof,omitempty"`
}

func validRequest(r DrainRequest) bool {
	return validHex(r.ID, 16) && r.Identity.UID > 0 && validHex(r.Identity.Credential, 32)
}
func (d drainRecord) validate(id string, s journal) error {
	if id != d.Request.ID || !validRequest(d.Request) {
		return errors.New("invalid stored drain")
	}
	if p := d.Proof; p != nil {
		if p.Request != d.Request || p.Scope != s.Scope || p.Epoch != s.Epoch || p.Receipt.Scope != s.Scope || p.Receipt.Epoch != s.Epoch || p.Receipt.Sequence >= s.Next || p.Receipt.Sequence == 0 || !validHex(p.Receipt.Digest, 32) || p.Final.UID != d.Request.Identity.UID || p.Final.Credential != d.Request.Identity.Credential || p.Final.Upload < 0 || p.Final.Download < 0 {
			return errors.New("invalid stored drain proof")
		}
	}
	return nil
}

// RestoreFences must run before accepting proxy traffic when reopening the
// same counter generation. Generation changes are rejected by Open altogether.
func (o *Outbox) RestoreFences(ctx context.Context, adapter DrainAdapter) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.poisoned {
		return ErrUncertain
	}
	if adapter == nil {
		return ErrCoverage
	}
	for _, d := range o.state.Drains {
		if err := adapter.Fence(ctx, d.Request.Identity); err != nil {
			return err
		}
	}
	return nil
}

func (o *Outbox) Drain(ctx context.Context, r DrainRequest, adapter DrainAdapter) (*DrainProof, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.poisoned {
		return nil, ErrUncertain
	}
	if !validRequest(r) || adapter == nil {
		return nil, ErrCoverage
	}
	d, exists := o.state.Drains[r.ID]
	if exists && d.Request != r {
		return nil, errors.New("transfer replay identity mismatch")
	}
	if !exists {
		if err := o.canReserve(r); err != nil {
			return nil, err
		}

		s := clone(o.state)
		d = drainRecord{Request: r}
		s.Drains[r.ID] = d
		delete(s.Reservations, r.ID)
		// The hold must be durable before a disconnect can occur.
		if err := o.save(s); err != nil {
			return nil, err
		}
	}
	if err := adapter.Fence(ctx, r.Identity); err != nil {
		return nil, err
	}
	status, err := adapter.Inspect(ctx, r.Identity)
	if err != nil {
		return nil, err
	}
	if status.Epoch != o.state.Epoch {
		return nil, ErrEpoch
	}
	if status.Identity != r.Identity || !status.TrackingReady || status.Bindings < 1 || status.Outstanding < 0 {
		return nil, ErrCoverage
	}
	if !status.RejectNew || status.Outstanding != 0 {
		return nil, ErrPending
	}
	if d.Proof != nil {
		current, err := adapter.Snapshot(ctx)
		if err != nil {
			return nil, err
		}
		if !containsFinal(current, d.Proof.Final) {
			return nil, ErrPending
		}
		p := *d.Proof
		return &p, nil
	}
	totals, err := adapter.Snapshot(ctx)
	if err != nil {
		return nil, err
	}
	var final *Sample
	for _, s := range totals {
		if s.UID == r.Identity.UID && s.Credential == r.Identity.Credential {
			copy := s
			final = &copy
			break
		}
	}
	if final == nil {
		return nil, errors.New("final credential counter missing")
	}
	ack, err := o.flush(ctx, totals)
	if err != nil {
		return nil, err
	}
	// Recheck after the network round trip; an adapter reset cannot yield proof.
	status, err = adapter.Inspect(ctx, r.Identity)
	if err != nil {
		return nil, err
	}
	if status.Epoch != o.state.Epoch || status.Identity != r.Identity || !status.TrackingReady || status.Bindings < 1 || !status.RejectNew || status.Outstanding != 0 {
		return nil, ErrPending
	}
	// A driver claiming zero handlers while counters still grow is incomplete.
	check, err := adapter.Snapshot(ctx)
	if err != nil {
		return nil, err
	}
	stable := false
	for _, row := range check {
		if row.UID == final.UID && row.Credential == final.Credential {
			stable = row == *final
			break
		}
	}
	if !stable {
		return nil, ErrPending
	}
	proof := DrainProof{r, o.state.Scope, o.state.Epoch, *final, *ack}
	s := clone(o.state)
	d.Proof = &proof
	s.Drains[r.ID] = d
	if err := o.save(s); err != nil {
		return nil, err
	}
	return &proof, nil
}

func containsFinal(rows []Sample, final Sample) bool {
	found := 0
	for _, r := range rows {
		if r.UID == final.UID && r.Credential == final.Credential {
			if r != final {
				return false
			}
			found++
		}
	}
	return found == 1
}
