// Package beupguard implements a credential-bound, node-local overlay. It never
// changes the panel's user state, subscription credential or bandwidth limit.
package beupguard

import (
	"encoding/hex"
	"errors"
	"github.com/InazumaV/V2bX/common/beupidentity"
	"sync"
	"sync/atomic"
	"time"
)

var ErrIsolated = errors.New("account isolation overlay active")
var ErrIdentity = errors.New("isolation identity mismatch")
var ErrCapacity = errors.New("isolation tracking capacity reached")

type Identity struct {
	UID        int    `json:"uid"`
	Credential string `json:"credential"` // SHA256 of the exact authenticated credential, never plaintext.
}
type Binding struct{ Tag, Label string }
type Lease struct {
	ID        string   `json:"id"`
	Identity  Identity `json:"identity"`
	StartedAt int64    `json:"started_at"`
	ExpiresAt int64    `json:"expires_at"`
	Manual    bool     `json:"manual"`
}
type activeLease struct {
	Lease
	deadline time.Time
}
type sessionEntry struct {
	identity Identity
	close    func()
}
type Guard struct {
	authorizations   map[Binding]string
	authorizationUse map[Identity]int64
	controlMu        sync.Mutex
	mu               sync.Mutex
	bindings         map[Binding]Identity
	leases           map[Identity]activeLease
	seen             map[string]Lease
	sessions         map[uint64]sessionEntry
	next             uint64
	maxSessions      int
	now              func() time.Time
	capacityFailures atomic.Uint64
	coverageFailures atomic.Uint64
	requiredTags     map[string]bool
}
type Stats struct {
	Bindings, Leases, Sessions int
	CapacityFailures           uint64
	CoverageFailures           uint64
}

func CredentialDigest(credential string) string {
	return beupidentity.CredentialDigest(credential)
}
func New(maxSessions int, now func() time.Time) *Guard {
	if maxSessions <= 0 {
		maxSessions = 65536
	}
	if now == nil {
		now = time.Now
	}
	return &Guard{authorizations: map[Binding]string{}, authorizationUse: map[Identity]int64{}, bindings: map[Binding]Identity{}, leases: map[Identity]activeLease{}, seen: map[string]Lease{}, sessions: map[uint64]sessionEntry{}, maxSessions: maxSessions, now: now}
}
func (g *Guard) Bind(tag, label string, uid int, credential string) {
	if uid <= 0 || tag == "" || label == "" || CredentialDigest(credential) == "" {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.bindings[Binding{tag, label}] = Identity{uid, CredentialDigest(credential)}
}
func (g *Guard) Unbind(tag, label string) {
	g.mu.Lock()
	delete(g.bindings, Binding{tag, label})
	delete(g.authorizations, Binding{tag, label})
	g.mu.Unlock()
}

// Configured before user loading. A removed, missing or unexpected inbound
// makes new enforcement ineligible; restoring traffic does not erase holds.
func (g *Guard) RequireTags(tags []string) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if len(g.bindings) != 0 || len(tags) == 0 || len(tags) > 32 {
		return errors.New("invalid isolation inbound scope")
	}
	want := map[string]bool{}
	for _, tag := range tags {
		if tag == "" || len(tag) > 512 || want[tag] {
			return errors.New("invalid isolation inbound scope")
		}
		want[tag] = true
	}
	g.requiredTags = want
	return nil
}
func (g *Guard) trackingReadyLocked() bool {
	if g.capacityFailures.Load() != 0 || g.coverageFailures.Load() != 0 {
		return false
	}
	if len(g.requiredTags) == 0 {
		return true
	}
	seen := map[string]bool{}
	for b := range g.bindings {
		if !g.requiredTags[b.Tag] {
			return false
		}
		seen[b.Tag] = true
	}
	return len(seen) == len(g.requiredTags)
}
func (g *Guard) unbindTag(tag string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	for b := range g.bindings {
		if b.Tag == tag {
			delete(g.bindings, b)
		}
	}
}
func (g *Guard) Identity(tag, label string) (Identity, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	i, ok := g.bindings[Binding{tag, label}]
	return i, ok
}
func (g *Guard) expired(l activeLease, now time.Time) bool {
	return !l.Manual && !now.Before(l.deadline)
}

// Track is serialized with Apply: a connection is either registered before the
// block (and closed) or rejected. Unknown identities are not guessed or blocked.
// A capacity failure is explicit; callers may continue proxy service, but must
// not report the enforcement adapter as ready for untracked traffic.
func (g *Guard) Track(tag, label string, close func()) (func(), error) {
	g.mu.Lock()
	id, ok := g.bindings[Binding{tag, label}]
	if !ok {
		g.coverageFailures.Add(1)
		g.mu.Unlock()
		return func() {}, ErrIdentity
	}
	if l, ok := g.leases[id]; ok {
		if !g.expired(l, g.now()) {
			g.mu.Unlock()
			return func() {}, ErrIsolated
		}
		delete(g.leases, id)
	}
	if len(g.sessions) >= g.maxSessions {
		g.capacityFailures.Add(1)
		g.mu.Unlock()
		return func() {}, ErrCapacity
	}
	g.next++
	n := g.next
	g.sessions[n] = sessionEntry{id, close}
	if _, grant := g.authorizationUse[id]; grant {
		g.authorizationUse[id] = g.now().Unix()
	}
	g.mu.Unlock()
	var once sync.Once
	return func() { once.Do(func() { g.mu.Lock(); delete(g.sessions, n); g.mu.Unlock() }) }, nil
}

func validateLease(l Lease, now time.Time) error {
	b, e := hex.DecodeString(l.ID)
	if e != nil || len(b) != 16 || l.Identity.UID <= 0 {
		return errors.New("invalid lease")
	}
	b, e = hex.DecodeString(l.Identity.Credential)
	if e != nil || len(b) != 32 {
		return errors.New("invalid credential digest")
	}
	if l.StartedAt <= 0 || l.StartedAt > now.Unix()+5 {
		return errors.New("invalid lease start")
	}
	if l.Manual {
		if l.ExpiresAt != 0 {
			return errors.New("manual lease must not expire")
		}
	} else if l.ExpiresAt <= now.Unix() || l.ExpiresAt-l.StartedAt != 600 {
		return errors.New("temporary lease must be 600 seconds and fresh")
	}
	return nil
}

// Apply installs only a separate overlay. Replaying the same lease is harmless;
// changing its identity/expiry or resurrecting a released lease is rejected.
// close callbacks execute outside the guard mutex and may finish concurrently.
func (g *Guard) Apply(l Lease) (int, error) {
	g.controlMu.Lock()
	defer g.controlMu.Unlock()
	g.mu.Lock()
	if old, ok := g.seen[l.ID]; ok {
		if old != l {
			g.mu.Unlock()
			return 0, errors.New("lease replay conflict")
		}
		if active, ok := g.leases[l.Identity]; !ok || active.ID != l.ID || g.expired(active, g.now()) {
			g.mu.Unlock()
			return 0, errors.New("lease already ended")
		}
		g.mu.Unlock()
		return 0, nil
	}
	if err := validateLease(l, g.now()); err != nil {
		g.mu.Unlock()
		return 0, err
	}
	bound := false
	for _, i := range g.bindings {
		if i == l.Identity {
			bound = true
			break
		}
	}
	if !bound {
		g.mu.Unlock()
		return 0, ErrIdentity
	}
	if old, ok := g.leases[l.Identity]; ok && !g.expired(old, g.now()) {
		g.mu.Unlock()
		return 0, errors.New("account already isolated")
	}
	// Never silently evict replay protection while enabled.
	if len(g.seen) >= 10000 {
		g.mu.Unlock()
		return 0, ErrCapacity
	}
	entry := activeLease{Lease: l}
	if !l.Manual {
		entry.deadline = g.now().Add(time.Duration(l.ExpiresAt-g.now().Unix()) * time.Second)
	}
	g.leases[l.Identity] = entry
	g.seen[l.ID] = l
	closes := []func(){}
	for _, s := range g.sessions {
		if s.identity == l.Identity {
			closes = append(closes, s.close)
		}
	}
	g.mu.Unlock()
	for _, f := range closes {
		if f != nil {
			f()
		}
	}
	return len(closes), nil
}

// Outstanding is used for acknowledgement, not the number of cancel requests.
// The proxy must call the Track completion only after its handler has returned.
func (g *Guard) Outstanding(identity Identity) int {
	g.mu.Lock()
	defer g.mu.Unlock()
	n := 0
	for _, s := range g.sessions {
		if s.identity == identity {
			n++
		}
	}
	return n
}
func (g *Guard) Release(id string, identity Identity) error {
	g.controlMu.Lock()
	defer g.controlMu.Unlock()
	g.mu.Lock()
	defer g.mu.Unlock()
	seen, ok := g.seen[id]
	if !ok || seen.Identity != identity {
		return ErrIdentity
	}
	if l, ok := g.leases[identity]; ok && l.ID == id {
		delete(g.leases, identity)
	}
	return nil
}
func (g *Guard) Stats() Stats {
	g.mu.Lock()
	defer g.mu.Unlock()
	for i, l := range g.leases {
		if g.expired(l, g.now()) {
			delete(g.leases, i)
		}
	}
	return Stats{len(g.bindings), len(g.leases), len(g.sessions), g.capacityFailures.Load(), g.coverageFailures.Load()}
}

// Sticky until a verified restart: a once-untracked connection may still be
// alive, so later successful samples must not silently restore readiness.
func (g *Guard) NoteCoverageFailure() { g.coverageFailures.Add(1) }
