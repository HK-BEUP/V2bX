package beupguard

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"sync"
	"time"
)

const CommandDomain = "BEUP-ACCOUNT-ISOLATION-COMMAND-V1\n"

// Commands are signed independently from observation registrations. An
// observation key cannot authorize account isolation. Scope is one node only.
type Command struct {
	Version   int    `json:"version"`
	Node      string `json:"node"`
	Sequence  uint64 `json:"sequence"`
	IssuedAt  int64  `json:"issued_at"`
	NotAfter  int64  `json:"not_after"`
	Operation string `json:"operation"`
	Lease     Lease  `json:"lease"`
}
type Envelope struct {
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

// BootStamp lets a service restart preserve the original remaining lifetime
// without trusting wall-clock corrections. A machine reboot requires explicit
// reconciliation of temporary leases; it never silently restarts a 10m timer.
type BootStamp struct {
	ID    string `json:"id"`
	Nanos int64  `json:"nanos"`
}
type Record struct {
	Envelope   Envelope  `json:"envelope"`
	AcceptedAt int64     `json:"accepted_at"`
	Boot       BootStamp `json:"boot"`
}
type Journal struct {
	Version int      `json:"version"`
	Node    string   `json:"node"`
	Records []Record `json:"records"`
}

// Store must provide atomic, durable compare-and-swap. A write error is treated
// as uncertain: the controller stops accepting commands until it is reloaded.
// Loading a missing or corrupt store must fail, never initialize silently.
type Store interface {
	Load() (Journal, error)
	Save(expectedRecords int, next Journal) error
}
type Controller struct {
	mu        sync.Mutex
	g         *Guard
	node      string
	key       ed25519.PublicKey
	store     Store
	journal   Journal
	now       func() time.Time
	boot      func() (BootStamp, error)
	poisoned  bool
	lastWall  int64
	released  map[string]bool
	reconcile map[string]bool
	cancelled map[string]bool
}
type Acknowledgement struct {
	Node                   string `json:"node"`
	Sequence               uint64 `json:"sequence"`
	LeaseID                string `json:"lease_id"`
	State                  string `json:"state"`
	RejectNew              bool   `json:"reject_new"`
	ExistingClosed         bool   `json:"existing_closed"`
	Outstanding            int    `json:"outstanding"`
	Manual                 bool   `json:"manual"`
	ExpiresAt              int64  `json:"expires_at"`
	TrackingReady          bool   `json:"tracking_ready"`
	IdentityBound          bool   `json:"identity_bound"`
	CurrentLeaseID         string `json:"current_lease_id"`
	ReconciliationRequired bool   `json:"reconciliation_required"`
}

func decodeStrict(b []byte, v any) error {
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if e := d.Decode(v); e != nil {
		return e
	}
	if d.Decode(new(any)) != io.EOF {
		return errors.New("trailing command data")
	}
	return nil
}
func verifyEnvelope(e Envelope, node string, key ed25519.PublicKey) (Command, error) {
	var c Command
	fail := errors.New("isolation command rejected")
	if len(e.Payload) > 1024 || len(e.Signature) != 128 {
		return c, fail
	}
	p, err := base64.StdEncoding.Strict().DecodeString(e.Payload)
	if err != nil {
		return c, fail
	}
	sig, err := hex.DecodeString(e.Signature)
	if err != nil || !ed25519.Verify(key, append([]byte(CommandDomain), p...), sig) || decodeStrict(p, &c) != nil {
		return Command{}, fail
	}
	if c.Version != 1 || c.Node != node || c.Sequence < 1 || c.IssuedAt <= 0 || c.NotAfter <= c.IssuedAt || c.NotAfter-c.IssuedAt > 60 || (c.Operation != "block" && c.Operation != "release" && c.Operation != "cancel") {
		return Command{}, fail
	}
	// Validate the signed lease at its original start, not at replay time.
	if validateLease(c.Lease, time.Unix(c.Lease.StartedAt, 0)) != nil {
		return Command{}, fail
	}
	if c.Operation == "block" && (c.Lease.StartedAt > c.IssuedAt || c.IssuedAt-c.Lease.StartedAt > 60) {
		return Command{}, fail
	}
	return c, nil
}
func envelopeDigest(e Envelope) [32]byte {
	return sha256.Sum256([]byte(e.Payload + "\n" + e.Signature))
}

// OpenController must run before users or sessions are loaded. It verifies the
// complete signed journal and reconstructs only this tool's overlays. No panel
// ban, credential, subscription or bandwidth setting is edited.
func OpenController(g *Guard, node string, key ed25519.PublicKey, store Store, now func() time.Time, boot func() (BootStamp, error)) (*Controller, error) {
	if g == nil || node == "" || len(node) > 64 || len(key) != ed25519.PublicKeySize || store == nil || boot == nil {
		return nil, errors.New("invalid isolation controller settings")
	}
	if now == nil {
		now = time.Now
	}
	j, err := store.Load()
	if err != nil {
		return nil, err
	}
	if j.Version != 1 || j.Node != node || len(j.Records) > 10000 {
		return nil, errors.New("invalid isolation journal")
	}
	stamp, err := boot()
	if err != nil || stamp.ID == "" || stamp.Nanos < 0 {
		return nil, errors.New("boot clock unavailable")
	}
	seen := map[string]Lease{}
	released := map[string]bool{}
	cancelled := map[string]bool{}
	pending := map[Identity]Record{}
	lastWall := int64(0)
	var previous BootStamp
	for idx, r := range j.Records {
		c, err := verifyEnvelope(r.Envelope, node, key)
		if err != nil || c.Sequence != uint64(idx+1) || r.AcceptedAt < c.IssuedAt-5 || r.AcceptedAt >= c.NotAfter || (c.Operation == "block" && r.AcceptedAt < lastWall) || r.Boot.ID == "" || r.Boot.Nanos < 0 || (previous.ID == r.Boot.ID && r.Boot.Nanos < previous.Nanos) {
			return nil, errors.New("invalid isolation journal record")
		}
		lastWall, previous = max(lastWall, r.AcceptedAt), r.Boot
		l := c.Lease
		if c.Operation == "cancel" {
			if _, exists := seen[l.ID]; exists || len(seen) >= 4096 {
				return nil, errors.New("invalid journal cancellation")
			}
			seen[l.ID], released[l.ID], cancelled[l.ID] = l, true, true
			continue
		}
		if c.Operation == "release" {
			if old, ok := seen[l.ID]; !ok || old != l {
				return nil, errors.New("invalid journal release")
			}
			if released[l.ID] {
				return nil, errors.New("duplicate journal release")
			}
			released[l.ID] = true
			if old, ok := pending[l.Identity]; ok {
				oldCmd, _ := verifyEnvelope(old.Envelope, node, key)
				if oldCmd.Lease.ID == l.ID {
					delete(pending, l.Identity)
				}
			}
			continue
		}
		if _, ok := seen[l.ID]; ok {
			return nil, errors.New("duplicate journal lease")
		}
		seen[l.ID] = l
		if len(seen) > 4096 {
			return nil, errors.New("isolation lease history capacity exceeded")
		}
		if old, ok := pending[l.Identity]; ok {
			oldCmd, _ := verifyEnvelope(old.Envelope, node, key)
			oldLease := oldCmd.Lease
			if oldLease.Manual || old.Boot.ID != r.Boot.ID || time.Duration(oldLease.ExpiresAt-old.AcceptedAt)*time.Second > time.Duration(r.Boot.Nanos-old.Boot.Nanos) {
				return nil, errors.New("overlapping journal leases")
			}
		}
		pending[l.Identity] = r
	}
	active := map[Identity]activeLease{}
	reconcile := map[string]bool{}
	for identity, r := range pending {
		cmd, _ := verifyEnvelope(r.Envelope, node, key)
		entry := activeLease{Lease: cmd.Lease}
		if !cmd.Lease.Manual {
			// A new kernel cannot prove how much of a temporary hold remains.
			// Never start another 600s or prevent the whole proxy starting. The
			// temporary overlay is interrupted, explicitly non-ready until the
			// panel durably closes it with a signed release. Manual holds remain.
			if r.Boot.ID != stamp.ID {
				reconcile[cmd.Lease.ID] = true
				continue
			}
			if stamp.Nanos < r.Boot.Nanos {
				return nil, errors.New("boot clock moved backwards")
			}
			remaining := time.Duration(cmd.Lease.ExpiresAt-r.AcceptedAt)*time.Second - time.Duration(stamp.Nanos-r.Boot.Nanos)
			if remaining <= 0 {
				continue
			}
			entry.deadline = now().Add(remaining)
		}
		active[identity] = entry
	}
	// Even expired/released records retain anti-replay protection. Restore is
	// atomic and permitted only on a fresh guard, before any serving traffic.
	g.mu.Lock()
	defer g.mu.Unlock()
	if len(g.bindings)+len(g.leases)+len(g.seen)+len(g.sessions) != 0 {
		return nil, errors.New("controller must start before user loading")
	}
	g.seen, g.leases = seen, active
	return &Controller{g: g, node: node, key: append(ed25519.PublicKey(nil), key...), store: store, journal: j, now: now, boot: boot, released: released, reconcile: reconcile, cancelled: cancelled, lastWall: lastWall}, nil
}

func (c *Controller) Execute(e Envelope) (Acknowledgement, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.g.controlMu.Lock()
	defer c.g.controlMu.Unlock()
	if c.poisoned {
		return Acknowledgement{}, errors.New("controller needs recovery after uncertain write")
	}
	cmd, err := verifyEnvelope(e, c.node, c.key)
	if err != nil {
		return Acknowledgement{}, err
	}
	count := len(c.journal.Records)
	if cmd.Sequence <= uint64(count) {
		r := c.journal.Records[cmd.Sequence-1]
		if envelopeDigest(r.Envelope) != envelopeDigest(e) {
			return Acknowledgement{}, errors.New("command replay conflict")
		}
		return c.ack(cmd), nil // Read current state; never reapply an old block.
	}
	now := c.now()
	stamp, err := c.boot()
	if err != nil || stamp.ID == "" || stamp.Nanos < 0 {
		return Acknowledgement{}, errors.New("boot clock unavailable")
	}
	if cmd.Sequence != uint64(count+1) || now.Unix() < cmd.IssuedAt-5 || now.Unix() >= cmd.NotAfter {
		return Acknowledgement{}, errors.New("stale or out-of-order isolation command")
	}
	if count > 0 {
		prev := c.journal.Records[count-1]
		if (cmd.Operation == "block" && now.Unix() < c.lastWall) || (prev.Boot.ID == stamp.ID && stamp.Nanos < prev.Boot.Nanos) {
			return Acknowledgement{}, errors.New("clock rollback; new commands suspended")
		}
	}
	// Serialize mutations separately from the hot-path lock. A slow disk must
	// not stall normal proxy connections. Connections opened during commit are
	// included when the committed overlay atomically becomes active.
	c.g.mu.Lock()
	l := cmd.Lease
	if cmd.Operation == "block" {
		if len(c.reconcile) != 0 {
			c.g.mu.Unlock()
			return Acknowledgement{}, errors.New("temporary lease requires signed reboot reconciliation")
		}
		if err = validateLease(l, now); err == nil {
			bound := false
			for _, id := range c.g.bindings {
				if id == l.Identity {
					bound = true
					break
				}
			}
			if !bound {
				err = ErrIdentity
			}
		}
		if _, exists := c.g.seen[l.ID]; exists {
			err = errors.New("lease id already used")
		}
		if old, exists := c.g.leases[l.Identity]; exists && !c.g.expired(old, now) {
			err = errors.New("account already isolated")
		}
		if !c.g.trackingReadyLocked() {
			err = errors.New("connection tracking incomplete")
		}
		if len(c.g.seen) >= 4096 {
			err = errors.New("isolation history full; release remains available")
		}
	} else if cmd.Operation == "cancel" {
		// Consume an unaccepted expired intent's sequence, never undo a hold.
		// A prior accepted block at this sequence already returned/conflicted
		// above. Even a later cancel cannot target any previously seen lease.
		if _, exists := c.g.seen[l.ID]; exists || len(c.g.seen) >= 4096 {
			err = errors.New("only an unseen intent can be cancelled")
		}
	} else {
		if old, exists := c.g.seen[l.ID]; !exists || old != l {
			err = ErrIdentity
		}
		if c.released[l.ID] {
			err = errors.New("lease already released")
		}
	}
	if err != nil {
		c.g.mu.Unlock()
		return Acknowledgement{}, err
	}
	c.g.mu.Unlock()
	next := Journal{Version: 1, Node: c.node, Records: append(append([]Record(nil), c.journal.Records...), Record{Envelope: e, AcceptedAt: now.Unix(), Boot: stamp})}
	if err = c.store.Save(count, next); err != nil {
		c.poisoned = true
		return Acknowledgement{}, errors.New("isolation journal commit uncertain")
	}
	c.journal = next
	c.lastWall = max(c.lastWall, now.Unix())
	c.g.mu.Lock()
	closes := []func(){}
	if cmd.Operation == "cancel" {
		c.g.seen[l.ID], c.released[l.ID], c.cancelled[l.ID] = l, true, true
	} else if cmd.Operation == "release" {
		c.released[l.ID] = true
		delete(c.reconcile, l.ID)
		if old, exists := c.g.leases[l.Identity]; exists && old.ID == l.ID {
			delete(c.g.leases, l.Identity)
		}
	} else {
		entry := activeLease{Lease: l}
		if !l.Manual {
			entry.deadline = now.Add(time.Duration(l.ExpiresAt-now.Unix()) * time.Second)
		}
		c.g.seen[l.ID], c.g.leases[l.Identity] = l, entry
		for _, session := range c.g.sessions {
			if session.identity == l.Identity {
				closes = append(closes, session.close)
			}
		}
	}
	c.g.mu.Unlock()
	for _, close := range closes {
		if close != nil {
			close()
		}
	}
	return c.ack(cmd), nil
}
func (c *Controller) ack(cmd Command) Acknowledgement {
	g := c.g
	g.mu.Lock()
	defer g.mu.Unlock()
	ack := Acknowledgement{Node: c.node, Sequence: cmd.Sequence, LeaseID: cmd.Lease.ID, State: "ended", Manual: cmd.Lease.Manual, ExpiresAt: cmd.Lease.ExpiresAt, TrackingReady: g.trackingReadyLocked() && len(c.reconcile) == 0, ReconciliationRequired: len(c.reconcile) != 0}
	if c.cancelled[cmd.Lease.ID] {
		ack.State = "not_applied"
		return ack
	}
	if c.reconcile[cmd.Lease.ID] {
		ack.State = "interrupted_by_reboot"
	}
	for _, identity := range g.bindings {
		if identity == cmd.Lease.Identity {
			ack.IdentityBound = true
			break
		}
	}
	if l, ok := g.leases[cmd.Lease.Identity]; ok && !g.expired(l, c.now()) {
		ack.CurrentLeaseID = l.ID
		if l.ID != cmd.Lease.ID {
			ack.State = "superseded"
			ack.RejectNew = true
			return ack
		}
		ack.State, ack.RejectNew = "isolated", true
		for _, s := range g.sessions {
			if s.identity == cmd.Lease.Identity {
				ack.Outstanding++
			}
		}
		ack.ExistingClosed = ack.Outstanding == 0 && ack.TrackingReady
	}
	return ack
}
