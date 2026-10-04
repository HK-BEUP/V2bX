// Package beuptransfer contains the opt-in transfer accounting protocol.
// It is intentionally not wired to live node startup until both the panel's
// idempotent receiver and the Xray drain adapter pass integration acceptance.
package beuptransfer

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"sync"
)

var (
	ErrEpoch     = errors.New("counter generation changed; reconciliation required")
	ErrUncertain = errors.New("journal write uncertain; reopen and reconcile")
	ErrPending   = errors.New("old connections or final usage still pending")
	ErrCoverage  = errors.New("complete identity-bound tracking required")
)

const maxSamples = 10000

var scopePattern = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`)

// Totals must be cumulative for a single counter generation, never reset on
// reporting or removal. Removed credentials remain until settlement is proven.
type Sample struct {
	UID        int64  `json:"uid"`
	Credential string `json:"credential"`
	Upload     int64  `json:"upload"`
	Download   int64  `json:"download"`
}

type Batch struct {
	Version  int      `json:"version"`
	Scope    string   `json:"scope"`
	Epoch    string   `json:"epoch"`
	Sequence uint64   `json:"sequence"`
	Entries  []Sample `json:"entries"` // deltas; zero entries are valid final barriers
	Digest   string   `json:"digest"`
}

type Ack struct {
	Scope    string `json:"scope"`
	Epoch    string `json:"epoch"`
	Sequence uint64 `json:"sequence"`
	Digest   string `json:"digest"`
}

// Receiver must commit each (scope, epoch, sequence) once, reject a different
// digest at the same key, and acknowledge only after durable SQL commitment.
type Receiver interface {
	Commit(context.Context, Batch) (Ack, error)
}
type Store interface {
	Load() ([]byte, error)
	Save([]byte) error
}

type pendingBatch struct {
	Batch   Batch    `json:"batch"`
	Through []Sample `json:"through"`
}
type journal struct {
	Version      int                     `json:"version"`
	Scope        string                  `json:"scope"`
	Epoch        string                  `json:"epoch"`
	Next         uint64                  `json:"next"`
	Committed    []Sample                `json:"committed"`
	Pending      *pendingBatch           `json:"pending,omitempty"`
	LastAck      *Ack                    `json:"last_ack,omitempty"`
	Drains       map[string]drainRecord  `json:"drains"`
	Reservations map[string]DrainRequest `json:"reservations,omitempty"`
	Session      *counterSession         `json:"counter_session,omitempty"`
}

type Outbox struct {
	mu       sync.Mutex
	store    Store
	receiver Receiver
	state    journal
	poisoned bool
	legacy   bool
}

func validHex(s string, bytes int) bool {
	b, err := hex.DecodeString(s)
	return err == nil && len(b) == bytes && hex.EncodeToString(b) == s
}
func key(s Sample) string { return fmt.Sprintf("%020d:%s", s.UID, s.Credential) }
func samples(in []Sample) ([]Sample, error) {
	if len(in) > maxSamples {
		return nil, errors.New("counter inventory capacity exceeded")
	}
	out := append([]Sample{}, in...)
	for _, s := range out {
		if s.UID <= 0 || !validHex(s.Credential, 32) || s.Upload < 0 || s.Download < 0 {
			return nil, errors.New("invalid cumulative counter")
		}
	}
	sort.Slice(out, func(i, j int) bool { return key(out[i]) < key(out[j]) })
	for i := 1; i < len(out); i++ {
		if key(out[i-1]) == key(out[i]) {
			return nil, errors.New("duplicate counter identity")
		}
	}
	return out, nil
}

func delta(before, after []Sample) ([]Sample, error) {
	old := make(map[string]Sample, len(before))
	for _, s := range before {
		old[key(s)] = s
	}
	out := make([]Sample, 0, len(after))
	for _, s := range after {
		p := old[key(s)]
		if s.Upload < p.Upload || s.Download < p.Download {
			return nil, ErrEpoch
		}
		delete(old, key(s))
		s.Upload -= p.Upload
		s.Download -= p.Download
		out = append(out, s)
	}
	if len(old) != 0 {
		return nil, errors.New("retired counters disappeared before reconciliation")
	}
	return out, nil
}

// Canonical wire hash avoids language-specific JSON encoding differences.
// Every field is validated and ASCII; entries must already be sorted.
func (b Batch) Hash() string {
	h := sha256.New()
	fmt.Fprintf(h, "beup-traffic-v1\n%s\n%s\n%d\n", b.Scope, b.Epoch, b.Sequence)
	for _, r := range b.Entries {
		fmt.Fprintf(h, "%d:%s:%d:%d\n", r.UID, r.Credential, r.Upload, r.Download)
	}
	return hex.EncodeToString(h.Sum(nil))
}
func ackFor(b Batch) Ack { return Ack{b.Scope, b.Epoch, b.Sequence, b.Digest} }

func Open(store Store, receiver Receiver, scope, epoch string) (*Outbox, error) {
	if store == nil || receiver == nil || !scopePattern.MatchString(scope) || !validHex(epoch, 16) {
		return nil, errors.New("invalid accounting scope or generation")
	}
	o := &Outbox{store: store, receiver: receiver}
	data, err := store.Load()
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		s := journal{Version: 1, Scope: scope, Epoch: epoch, Next: 1, Committed: []Sample{}, Drains: map[string]drainRecord{}}
		if err := o.save(s); err != nil {
			return nil, err
		}
		return o, nil
	}
	if len(data) > 16<<20 {
		return nil, errors.New("oversized accounting journal")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var s journal
	if err := dec.Decode(&s); err != nil {
		return nil, errors.New("invalid accounting journal")
	}
	if dec.Decode(new(any)) != io.EOF {
		return nil, errors.New("trailing journal data")
	}
	if s.Version != 1 || s.Scope != scope || s.Next == 0 || s.Next > 1<<53 || s.Drains == nil || len(s.Drains) > 1000 {
		return nil, errors.New("journal scope mismatch")
	}
	if err := validateCounterSession(s); err != nil {
		return nil, err
	}
	if err := validateReservations(s); err != nil {
		return nil, err
	}
	if s.Epoch != epoch {
		return nil, ErrEpoch
	}
	if _, err := samples(s.Committed); err != nil {
		return nil, err
	}
	if s.LastAck != nil && (s.LastAck.Scope != scope || s.LastAck.Epoch != epoch || s.LastAck.Sequence+1 != s.Next || !validHex(s.LastAck.Digest, 32)) {
		return nil, errors.New("invalid last acknowledgement")
	}
	if s.LastAck == nil && (s.Next != 1 || len(s.Committed) != 0) {
		return nil, errors.New("missing acknowledgement")
	}
	if p := s.Pending; p != nil {
		through, err := samples(p.Through)
		if err != nil {
			return nil, err
		}
		entries, err := delta(s.Committed, through)
		if err != nil {
			return nil, err
		}
		want := Batch{1, scope, epoch, s.Next, entries, ""}
		want.Digest = want.Hash()
		actual, _ := json.Marshal(p.Batch)
		expected, _ := json.Marshal(want)
		if !bytes.Equal(actual, expected) {
			return nil, errors.New("pending batch journal mismatch")
		}
	}
	for id, d := range s.Drains {
		if err := d.validate(id, s); err != nil {
			return nil, err
		}
	}
	o.state = s
	return o, nil
}

func clone(s journal) journal {
	b, _ := json.Marshal(s)
	var out journal
	_ = json.Unmarshal(b, &out)
	return out
}
func (o *Outbox) save(s journal) error {
	if o.poisoned {
		return ErrUncertain
	}
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}
	if len(b) > 16<<20 {
		return errors.New("accounting journal capacity exceeded")
	}
	if err := o.store.Save(b); err != nil {
		o.poisoned = true
		return fmt.Errorf("%w: %v", ErrUncertain, err)
	}
	o.state = s
	return nil
}

func (o *Outbox) replay(ctx context.Context) (*Ack, error) {
	if o.poisoned {
		return nil, ErrUncertain
	}
	p := o.state.Pending
	if p == nil {
		return nil, nil
	}
	// A receiver must not be able to mutate the bytes that subsequent retries use.
	b := p.Batch
	b.Entries = append([]Sample{}, p.Batch.Entries...)
	ack, err := o.receiver.Commit(ctx, b)
	if err != nil {
		return nil, err
	}
	if ack != ackFor(p.Batch) {
		return nil, errors.New("receiver acknowledgement mismatch")
	}
	s := clone(o.state)
	s.Committed = s.Pending.Through
	s.Pending = nil
	s.LastAck = &ack
	s.Next++
	if err := o.save(s); err != nil {
		return nil, err
	}
	return &ack, nil
}

// Replay delivers the exact persisted batch after a network failure. It never
// guesses a new delta. A changed node generation must first be reconciled.
func (o *Outbox) Replay(ctx context.Context) (*Ack, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.replay(ctx)
}

func (o *Outbox) flush(ctx context.Context, totals []Sample) (*Ack, error) {
	if o.state.Session != nil && o.state.Session.Sealed {
		return nil, ErrEpoch
	}
	if _, err := o.replay(ctx); err != nil {
		return nil, err
	}
	if o.state.Next >= 1<<53 {
		return nil, errors.New("accounting sequence exhausted")
	}
	after, err := samples(totals)
	if err != nil {
		return nil, err
	}
	for _, d := range o.state.Drains {
		if d.Proof != nil && !containsFinal(after, d.Proof.Final) {
			return nil, ErrPending
		}
	}
	entries, err := delta(o.state.Committed, after)
	if err != nil {
		return nil, err
	}
	s := clone(o.state)
	b := Batch{1, s.Scope, s.Epoch, s.Next, entries, ""}
	b.Digest = b.Hash()
	s.Pending = &pendingBatch{b, after}
	if err := o.save(s); err != nil {
		return nil, err
	}
	return o.replay(ctx)
}

// Flush persists before sending and acknowledges only after a durable receiver
// receipt. Counters are never reset here, including on failures and retries.
func (o *Outbox) Flush(ctx context.Context, totals []Sample) (*Ack, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.flush(ctx, totals)
}
