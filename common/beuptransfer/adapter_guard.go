package beuptransfer

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/InazumaV/V2bX/common/beupguard"
)

// GuardAdapter owns a separate guard, so a migration hold cannot release or
// weaken the existing attack/subscription guards. Proxy hooks must call Track
// on this adapter as well as every existing guard. This is not a runtime switch.
type GuardAdapter struct {
	mu         sync.Mutex
	fenceMu    sync.Mutex
	guard      *beupguard.Guard
	tag, epoch string
	bindings   map[string]Identity
	incomplete map[Identity]bool
	holds      map[Identity]beupguard.Lease
	snapshot   func(context.Context) ([]Sample, error)
	quiescing  bool
	sealed     map[Identity]bool
}

func NewGuardAdapter(tag, epoch string, snapshot func(context.Context) ([]Sample, error)) (*GuardAdapter, error) {
	if tag == "" || len(tag) > 512 || !validHex(epoch, 16) || snapshot == nil {
		return nil, ErrCoverage
	}
	g := beupguard.New(65536, nil)
	if err := g.RequireTags([]string{tag}); err != nil {
		return nil, err
	}
	return &GuardAdapter{guard: g, tag: tag, epoch: epoch, bindings: map[string]Identity{}, incomplete: map[Identity]bool{}, holds: map[Identity]beupguard.Lease{}, snapshot: snapshot, sealed: map[Identity]bool{}}, nil
}

// Called before the credential is made available to an inbound. Retired
// bindings are intentionally retained along with their final traffic counters.
func (a *GuardAdapter) Bind(label string, uid int, credential string) error {
	digest := beupguard.CredentialDigest(credential)
	if label == "" || len(label) > 1024 || uid <= 0 || digest == "" {
		a.guard.NoteCoverageFailure()
		return ErrCoverage
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.quiescing {
		return ErrPending
	}
	id := Identity{int64(uid), digest}
	if old, exists := a.bindings[label]; exists && old != id {
		a.guard.NoteCoverageFailure()
		return errors.New("binding identity changed during counter generation")
	}
	if _, exists := a.bindings[label]; !exists && len(a.bindings) >= maxSamples {
		a.guard.NoteCoverageFailure()
		return ErrCoverage
	}
	a.guard.Bind(a.tag, label, uid, credential)
	a.bindings[label] = id
	return nil
}

func (a *GuardAdapter) Track(label string, closeFlow func()) (func(), error) {
	a.mu.Lock()
	id := a.bindings[label]
	_, held := a.holds[id]
	closing := a.quiescing || held
	a.mu.Unlock()
	if closing {
		return func() {}, beupguard.ErrIsolated
	}
	return a.guard.Track(a.tag, label, closeFlow)
}
func (a *GuardAdapter) NoteCoverageFailure() { a.guard.NoteCoverageFailure() }
func (a *GuardAdapter) NoteIdentityCoverageFailure(label string) {
	a.mu.Lock()
	id, ok := a.bindings[label]
	if ok {
		a.incomplete[id] = true
	}
	a.mu.Unlock()
	if !ok {
		a.guard.NoteCoverageFailure()
	}
}

func (a *GuardAdapter) Fence(_ context.Context, id Identity) error {
	if id.UID <= 0 || !validHex(id.Credential, 32) || int64(int(id.UID)) != id.UID {
		return ErrCoverage
	}
	a.fenceMu.Lock()
	defer a.fenceMu.Unlock()
	a.mu.Lock()
	lease, exists := a.holds[id]
	a.mu.Unlock()
	if exists {
		return nil
	}
	h := sha256.Sum256([]byte(fmt.Sprintf("BEUP-TRANSFER-HOLD-V1\n%s\n%s\n%d\n%s", a.tag, a.epoch, id.UID, id.Credential)))
	lease = beupguard.Lease{ID: hex.EncodeToString(h[:16]), Identity: beupguard.Identity{UID: int(id.UID), Credential: id.Credential}, StartedAt: time.Now().Unix(), Manual: true}
	// Sealed historical identities have no current-process handler. Keep an
	// adapter admission hold; Track also checks it if the UUID is reintroduced.
	a.mu.Lock()
	bound := false
	for _, b := range a.bindings {
		if b == id {
			bound = true
			break
		}
	}
	if !bound && a.sealed[id] {
		a.holds[id] = lease
		a.mu.Unlock()
		return nil
	}
	a.mu.Unlock()
	// Apply closes outside the guard mutex. Completion callbacks may run here;
	// do not hold the adapter's state mutex while invoking external close hooks.
	if _, err := a.guard.Apply(lease); err != nil {
		return err
	}
	a.mu.Lock()
	a.holds[id] = lease
	a.mu.Unlock()
	return nil
}

func (a *GuardAdapter) Inspect(_ context.Context, id Identity) (FenceStatus, error) {
	a.mu.Lock()
	_, held := a.holds[id]
	incomplete := a.incomplete[id]
	bound := 0
	for _, binding := range a.bindings {
		if binding == id {
			bound++
		}
	}
	if bound == 0 && a.sealed[id] {
		bound = 1
	}
	a.mu.Unlock()
	s := a.guard.Stats()
	return FenceStatus{Epoch: a.epoch, Identity: id, RejectNew: held, Outstanding: a.guard.Outstanding(beupguard.Identity{UID: int(id.UID), Credential: id.Credential}), TrackingReady: !incomplete && s.CapacityFailures == 0 && s.CoverageFailures == 0, Bindings: bound}, nil
}
func (a *GuardAdapter) Snapshot(ctx context.Context) ([]Sample, error) { return a.snapshot(ctx) }

// Freeze bindings/admission before draining the complete counter inventory for a clean restart.
func (a *GuardAdapter) Quiesce(ctx context.Context) error {
	a.mu.Lock()
	a.quiescing = true
	ids := map[Identity]bool{}
	for _, id := range a.bindings {
		ids[id] = true
	}
	for id := range a.sealed {
		ids[id] = true
	}
	a.mu.Unlock()
	for id := range ids {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := a.Fence(ctx, id); err != nil {
			return err
		}
	}
	return nil
}

// Only CounterSession may restore identities from a sealed, acknowledged
// journal. Raw UUIDs are neither required nor persisted for retired counters.
func (a *GuardAdapter) RestoreSealedIdentities(ids []Identity) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.bindings) != 0 || len(a.holds) != 0 || len(a.sealed) != 0 || a.quiescing || len(ids) > maxSamples {
		return ErrCoverage
	}
	restored := map[Identity]bool{}
	for _, id := range ids {
		if id.UID <= 0 || int64(int(id.UID)) != id.UID || !validHex(id.Credential, 32) || restored[id] {
			return ErrCoverage
		}
		restored[id] = true
	}
	a.sealed = restored
	return nil
}
