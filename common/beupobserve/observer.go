// Package observer collects authenticated proxy-request metadata only.
// It never reads payloads, infers network failures, or changes proxy behavior.
package observer

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const Profile = "v2bx-xray-requests-v1"

var namePattern = regexp.MustCompile(`^[a-zA-Z0-9_.-]{1,64}$`)
var nodePattern = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`)
var subjectPattern = regexp.MustCompile(`^[a-f0-9]{32}$`)

type Config struct {
	Node             string
	IdentityRevision string
	// Exact, trusted inbound tag -> panel UID -> independently issued subject.
	// No UUID or derived UUID hash belongs in this registry.
	Bindings map[string]map[int]string
	Now      func() time.Time
}

type Metrics struct {
	ProxyRequests     int64  `json:"proxy_requests"`
	TCPRequests       int64  `json:"tcp_requests"`
	UDPAssociations   int64  `json:"udp_associations"`
	DistinctTargets   int    `json:"distinct_targets"`
	DistinctPorts     int    `json:"distinct_ports"`
	MaxTargetRequests int64  `json:"max_target_requests"`
	FailedConnections *int64 `json:"failed_connections"`
	UDPPackets        *int64 `json:"udp_packets"`
	BytesOut          *int64 `json:"bytes_out"`
	BytesIn           *int64 `json:"bytes_in"`
}
type Sample struct {
	Subject string  `json:"subject"`
	Metrics Metrics `json:"metrics"`
}
type Quality struct {
	PartialWindow      bool   `json:"partial_window"`
	ClockDiscontinuity bool   `json:"clock_discontinuity"`
	DroppedRequests    uint64 `json:"dropped_requests"`
	UnmappedRequests   uint64 `json:"unmapped_requests"`
}
type Report struct {
	Version          int      `json:"version"`
	Profile          string   `json:"profile"`
	IdentityRevision string   `json:"identity_revision"`
	BatchID          string   `json:"batch_id"`
	WindowStart      int64    `json:"window_start"`
	WindowEnd        int64    `json:"window_end"`
	Complete         bool     `json:"complete"` // Always false: this profile lacks outcome and packet metrics.
	Quality          Quality  `json:"quality"`
	Subjects         []Sample `json:"subjects"`
}
type counts struct {
	metrics Metrics
	targets map[[32]byte]int64
	ports   map[uint16]struct{}
}
type Observer struct {
	mu             sync.Mutex
	node, revision string
	now            func() time.Time
	secret         [32]byte
	registry       map[string]map[int]string
	bindings       map[[32]byte]string
	// Core-authenticated references, retained even before the UID is registered.
	// Labels remain HMAC-only. This permits roster refresh without core restart.
	authRefs          map[[32]byte]authRef
	accounts          map[string]*counts
	start             int64
	partial           bool
	edges             int
	dropped, unmapped atomic.Uint64
	clockGap          atomic.Bool
}
type authRef struct {
	Tag string
	UID int
}

func New(c Config) (*Observer, error) {
	if !nodePattern.MatchString(c.Node) || !namePattern.MatchString(c.IdentityRevision) {
		return nil, errors.New("invalid registration")
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	o := &Observer{node: c.Node, revision: c.IdentityRevision, now: c.Now, registry: map[string]map[int]string{}, bindings: map[[32]byte]string{}, authRefs: map[[32]byte]authRef{}, accounts: map[string]*counts{}}
	seen := map[string]int{}
	uidSubjects := map[int]string{}
	entries := 0
	for tag, users := range c.Bindings {
		if tag == "" || len(tag) > 512 {
			return nil, errors.New("invalid inbound registration")
		}
		o.registry[tag] = map[int]string{}
		for uid, subject := range users {
			entries++
			if entries > 50000 || uid <= 0 || !subjectPattern.MatchString(subject) {
				return nil, errors.New("invalid subject registration")
			}
			if other, ok := seen[subject]; ok && other != uid {
				return nil, errors.New("ambiguous subject registration")
			}
			if previous, ok := uidSubjects[uid]; ok && previous != subject {
				return nil, errors.New("inconsistent account registration")
			}
			seen[subject] = uid
			uidSubjects[uid] = subject
			o.registry[tag][uid] = subject
		}
	}
	if _, err := rand.Read(o.secret[:]); err != nil {
		return nil, errors.New("observer entropy unavailable")
	}
	n := c.Now()
	o.start = n.Unix() / 60 * 60
	o.partial = !n.Equal(time.Unix(o.start, 0))
	return o, nil
}
func (o *Observer) digest(domain, value string) [32]byte {
	h := hmac.New(sha256.New, o.secret[:])
	h.Write([]byte(domain))
	h.Write([]byte{0})
	h.Write([]byte(value))
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}
func (o *Observer) labelKey(tag, label string) [32]byte { return o.digest("binding", tag+"\x00"+label) }
func (o *Observer) Bind(tag, label string, uid int) bool {
	if label == "" || len(label) > 1024 || tag == "" || len(tag) > 512 || uid <= 0 {
		return false
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	subject := o.registry[tag][uid]
	key := o.labelKey(tag, label)
	if len(o.authRefs) >= 50000 {
		if _, exists := o.authRefs[key]; !exists {
			return false
		}
	}
	o.authRefs[key] = authRef{tag, uid}
	if subject == "" {
		delete(o.bindings, key)
		return false
	}
	if len(o.bindings) >= 50000 && o.bindings[key] == "" {
		return false
	}
	o.bindings[key] = subject
	return true
}
func (o *Observer) Unbind(tag, label string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	delete(o.bindings, o.labelKey(tag, label))
	delete(o.authRefs, o.labelKey(tag, label))
}

// Build and validate outside the hot lock. New/revoked UIDs are rebound from
// authenticated core references, never labels or source IP heuristics.
func (o *Observer) ReplaceRegistry(revision string, bindings map[string]map[int]string) error {
	next, err := New(Config{Node: o.node, IdentityRevision: revision, Bindings: bindings})
	if err != nil {
		return err
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	o.registry = next.registry
	o.revision = revision
	o.bindings = map[[32]byte]string{}
	for key, ref := range o.authRefs {
		if subject := o.registry[ref.Tag][ref.UID]; subject != "" {
			o.bindings[key] = subject
		}
	}
	o.accounts = map[string]*counts{}
	o.edges = 0
	o.partial = true
	return nil
}

// Observe records a logical authenticated request, not a successful TCP dial,
// an HTTP request, or a UDP datagram. TryLock keeps telemetry off the critical path.
func (o *Observer) Observe(tag, label, network, address string, port uint16) {
	if len(tag) > 512 || len(label) > 1024 || len(address) > 253 || port == 0 || (network != "tcp" && network != "udp") {
		o.dropped.Add(1)
		return
	}
	address = strings.TrimSuffix(strings.ToLower(address), ".")
	if ip, err := netip.ParseAddr(address); err == nil {
		address = ip.Unmap().String()
	} else if address == "" || strings.ContainsAny(address, " /\\@|\t\r\n\x00") {
		o.dropped.Add(1)
		return
	}
	if !o.mu.TryLock() {
		o.dropped.Add(1)
		return
	}
	defer o.mu.Unlock()
	nowStart := o.now().Unix() / 60 * 60
	if nowStart != o.start {
		if nowStart < o.start || nowStart > o.start+60 {
			o.clockGap.Store(true)
		}
		o.dropped.Add(1)
		return
	}
	subject := o.bindings[o.labelKey(tag, label)]
	if subject == "" {
		o.unmapped.Add(1)
		return
	}
	a := o.accounts[subject]
	if a == nil {
		if len(o.accounts) >= 4096 {
			o.dropped.Add(1)
			return
		}
		a = &counts{targets: map[[32]byte]int64{}, ports: map[uint16]struct{}{}}
		o.accounts[subject] = a
	}
	// Destination fingerprints stay in memory and are never serialized. Their
	// domain includes the sampling window to prevent cross-window linking.
	target := o.digest("target-"+strconv.FormatInt(o.start, 10), network+"\x00"+address)
	_, knownTarget := a.targets[target]
	_, knownPort := a.ports[port]
	delta := 0
	if !knownTarget {
		delta++
	}
	if !knownPort {
		delta++
	}
	if (!knownTarget && len(a.targets) >= 2048) || (!knownPort && len(a.ports) >= 2048) || o.edges+delta > 65536 {
		o.dropped.Add(1)
		return
	}
	o.edges += delta
	a.targets[target]++
	a.ports[port] = struct{}{}
	a.metrics.ProxyRequests++
	if network == "tcp" {
		a.metrics.TCPRequests++
	} else {
		a.metrics.UDPAssociations++
	}
	if a.targets[target] > a.metrics.MaxTargetRequests {
		a.metrics.MaxTargetRequests = a.targets[target]
	}
}

// Snapshot closes a window exactly once. Caller owns a single periodic runner.
// No disk/network I/O occurs under the telemetry lock; retries reuse returned bytes.
func (o *Observer) Snapshot(at time.Time) ([]Report, error) {
	end := at.Unix() / 60 * 60
	o.mu.Lock()
	if end <= o.start {
		o.mu.Unlock()
		return nil, errors.New("window not closed")
	}
	start := o.start
	revision := o.revision
	accounts := o.accounts
	q := Quality{o.partial, o.clockGap.Swap(false) || end-start != 60, o.dropped.Swap(0), o.unmapped.Swap(0)}
	o.start = end
	o.partial = false
	o.accounts = map[string]*counts{}
	o.edges = 0
	o.mu.Unlock()
	// Never spread counters collected before a timer outage across invented windows.
	if end-start != 60 {
		accounts = map[string]*counts{}
		start = end - 60
		q.PartialWindow = true
	}
	subjects := make([]Sample, 0, len(accounts))
	for subject, c := range accounts {
		c.metrics.DistinctTargets = len(c.targets)
		c.metrics.DistinctPorts = len(c.ports)
		subjects = append(subjects, Sample{subject, c.metrics})
	}
	sort.Slice(subjects, func(i, j int) bool { return subjects[i].Subject < subjects[j].Subject })
	var reports []Report
	for offset := 0; offset < len(subjects) || offset == 0; offset += 200 {
		stop := min(offset+200, len(subjects))
		id := make([]byte, 16)
		if _, err := rand.Read(id); err != nil {
			return nil, errors.New("observer entropy unavailable")
		}
		reports = append(reports, Report{1, Profile, revision, hex.EncodeToString(id), start, end, false, q, subjects[offset:stop]})
	}
	return reports, nil
}

// Encode signs only the separate observation endpoint; it has no network side effects.
func (o *Observer) Encode(r Report, key []byte, at time.Time) ([]byte, map[string]string, error) {
	return o.encodeWithKeyID(r, key, "", at)
}
func (o *Observer) encodeWithKeyID(r Report, key []byte, keyID string, at time.Time) ([]byte, map[string]string, error) {
	if len(key) < 32 || r.Complete || r.Profile != Profile {
		return nil, nil, errors.New("invalid observation envelope")
	}
	b, err := json.Marshal(r)
	if err != nil {
		return nil, nil, err
	}
	if len(b) > 262144 {
		return nil, nil, errors.New("observation too large")
	}
	ts := strconv.FormatInt(at.Unix(), 10)
	hash := sha256.Sum256(b)
	canonical := fmt.Sprintf("POST\n/api/v1/attack-guard/observation\n%s\n%s\n%x", o.node, ts, hash)
	if keyID != "" {
		canonical = fmt.Sprintf("POST\n/api/v1/attack-guard/observation\n%s\n%s\n%s\n%x", o.node, keyID, ts, hash)
	}
	h := hmac.New(sha256.New, key)
	h.Write([]byte(canonical))
	return b, map[string]string{"node": o.node, "timestamp": ts, "signature": hex.EncodeToString(h.Sum(nil))}, nil
}

var active atomic.Pointer[Observer]

// Set is intentionally not called by the production entrypoint in this candidate.
// A verified local bootstrap/runner must be implemented before a canary install.
func Set(o *Observer) { active.Store(o) }
func Bind(tag, label string, uid int) {
	if o := active.Load(); o != nil {
		o.Bind(tag, label, uid)
	}
}
func Unbind(tag, label string) {
	if o := active.Load(); o != nil {
		o.Unbind(tag, label)
	}
}
func Record(tag, label, network, address string, port uint16) {
	if o := active.Load(); o != nil {
		o.Observe(tag, label, network, address, port)
	}
}
