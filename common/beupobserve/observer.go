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
	"github.com/InazumaV/V2bX/common/beupidentity"
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
const TCPProfile = "v2bx-xray-tcp-outcomes-v2"

// A contended producer stores fingerprints only. No worker, raw address or
// credential is retained. The original aggregate limits remain unchanged.
const pendingCapacity = 512
const pendingDrainBudget = 8

type pendingRequest struct {
	key, target [32]byte
	minute      int64
	generation  uint64
	port        uint16
	tcp         bool
	outcome     uint8
}

type minuteMarker struct {
	sequence uint64
	minute   int64
}

var namePattern = regexp.MustCompile(`^[a-zA-Z0-9_.-]{1,64}$`)
var nodePattern = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`)
var subjectPattern = regexp.MustCompile(`^[a-f0-9]{32}$`)

type Config struct {
	Node             string
	IdentityRevision string
	// Exact, trusted inbound tag -> panel UID -> independently issued subject.
	// No UUID or derived UUID hash belongs in this registry.
	Bindings       map[string]map[int]string
	Now            func() time.Time
	TCPDialMetrics bool
}

type Metrics struct {
	ProxyRequests     int64        `json:"proxy_requests"`
	TCPRequests       int64        `json:"tcp_requests"`
	UDPAssociations   int64        `json:"udp_associations"`
	DistinctTargets   int          `json:"distinct_targets"`
	DistinctPorts     int          `json:"distinct_ports"`
	MaxTargetRequests int64        `json:"max_target_requests"`
	FailedConnections *int64       `json:"failed_connections"`
	UDPPackets        *int64       `json:"udp_packets"`
	BytesOut          *int64       `json:"bytes_out"`
	BytesIn           *int64       `json:"bytes_in"`
	TCPDial           *DialMetrics `json:"tcp_dial,omitempty"`
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
	Version          int             `json:"version"`
	Profile          string          `json:"profile"`
	IdentityRevision string          `json:"identity_revision"`
	BatchID          string          `json:"batch_id"`
	WindowStart      int64           `json:"window_start"`
	WindowEnd        int64           `json:"window_end"`
	Complete         bool            `json:"complete"` // Always false: neither profile measures UDP packets or all-protocol outcomes.
	Quality          Quality         `json:"quality"`
	Subjects         []Sample        `json:"subjects"`
	TCPWindow        *WindowManifest `json:"tcp_window,omitempty"`
}

// V2 explicitly closes the complete account window across bounded batches.
// No decision may infer complete node quality from just the first batch.
type WindowManifest struct {
	ID       string `json:"id"`
	Index    int    `json:"index"`
	Batches  int    `json:"batches"`
	Subjects int    `json:"subjects"`
}
type counts struct {
	metrics     Metrics
	targets     map[[32]byte]int64
	ports       map[uint16]struct{}
	dialTargets map[[32]byte]*dialTarget
}

// At most two adjacent minutes are retained. Both share the original account
// slot and edge limits; the lookahead buffer never grows into an outage queue.
type windowCounts struct {
	accounts                 map[string]*counts
	partial                  bool
	edges                    int
	accepted, lost, unmapped uint64
}
type Observer struct {
	mu      sync.Mutex
	pending chan pendingRequest
	// Even values are stable; odd values are an identity mutation in progress.
	generation     atomic.Uint64
	clockSequence  atomic.Uint64
	observedMinute atomic.Pointer[minuteMarker]
	node, revision string
	now            func() time.Time
	tcpDialMetrics bool
	secret         [32]byte
	registry       map[string]map[int]string
	bindings       map[[32]byte]string
	// Core-authenticated references, retained even before the UID is registered.
	// Labels remain HMAC-only. This permits roster refresh without core restart.
	authRefs map[[32]byte]authRef
	windowCounts
	next  *windowCounts
	start int64
	// Invalid inputs and TryLock losses cannot safely mutate a minute bucket.
	// They are drained once, and conservatively taint both adjacent windows.
	dropped                                                     atomic.Uint64
	clockGap                                                    atomic.Bool
	windowStart                                                 atomic.Int64 // Lock-free rejection of not-yet-closed windows.
	invalidDrops, contentionDrops, boundaryDrops, capacityDrops atomic.Uint64
	discardedSamples                                            atomic.Uint64
}
type authRef struct {
	Tag        string
	UID        int
	Credential string
}

func New(c Config) (*Observer, error) {
	if !nodePattern.MatchString(c.Node) || !namePattern.MatchString(c.IdentityRevision) {
		return nil, errors.New("invalid registration")
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	o := &Observer{node: c.Node, revision: c.IdentityRevision, now: c.Now, tcpDialMetrics: c.TCPDialMetrics, registry: map[string]map[int]string{}, bindings: map[[32]byte]string{}, authRefs: map[[32]byte]authRef{}, windowCounts: windowCounts{accounts: map[string]*counts{}}}
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
	o.windowStart.Store(o.start)
	o.observedMinute.Store(&minuteMarker{minute: o.start})
	o.pending = make(chan pendingRequest, pendingCapacity)
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
func (o *Observer) Bind(tag, label string, uid int, credential ...string) bool {
	if label == "" || len(label) > 1024 || tag == "" || len(tag) > 512 || uid <= 0 {
		return false
	}
	key := o.labelKey(tag, label)
	ref := authRef{Tag: tag, UID: uid}
	if len(credential) == 1 {
		ref.Credential = beupidentity.CredentialDigest(credential[0])
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	subject := o.registry[tag][uid]
	if len(o.authRefs) >= 50000 {
		if _, exists := o.authRefs[key]; !exists {
			return false
		}
	}
	if previous, exists := o.authRefs[key]; !exists || previous != ref {
		o.generation.Add(1)
		defer o.generation.Add(1)
	}
	o.authRefs[key] = ref
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
	key := o.labelKey(tag, label)
	o.mu.Lock()
	defer o.mu.Unlock()
	o.generation.Add(1)
	defer o.generation.Add(1)
	delete(o.bindings, key)
	delete(o.authRefs, key)
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
	o.resetWindowsLocked()
	return nil
}

// Used on both roster replacement and core reset. Counters discarded for
// identity safety remain visible as quality loss, never reassigned to a new UID.
func (o *Observer) resetWindowsLocked() {
	o.generation.Add(1)
	defer o.generation.Add(1)
	n := o.accepted
	lost, unmapped := o.lost, o.unmapped
	if o.next != nil {
		n += o.next.accepted
		lost += o.next.lost
		unmapped += o.next.unmapped
	}
	// Drain only the initial bounded backlog. Late producers carry an old/odd
	// generation and will be rejected, never rebound to the replacement UID.
	for i := len(o.pending); i > 0; i-- {
		select {
		case <-o.pending:
			n++
		default:
		}
	}
	o.discardedSamples.Add(n)
	o.dropped.Add(n + lost)
	o.windowCounts = windowCounts{accounts: map[string]*counts{}, partial: true, unmapped: unmapped}
	o.next = nil
}

// Observe records a logical authenticated request, not a successful TCP dial,
// an HTTP request, or a UDP datagram. It never waits for the telemetry mutex;
// contention is buffered to a fixed bound and overflow remains visible loss.
func (o *Observer) Observe(tag, label, network, address string, port uint16) {
	o.observeEvent(tag, label, network, address, port, 0)
}
func (o *Observer) observeEvent(tag, label, network, address string, port uint16, outcome uint8) {
	if len(tag) > 512 || len(label) > 1024 || len(address) > 253 || port == 0 || (network != "tcp" && network != "udp") {
		o.drop(&o.invalidDrops)
		return
	}
	address = strings.TrimSuffix(strings.ToLower(address), ".")
	if ip, err := netip.ParseAddr(address); err == nil {
		address = ip.Unmap().String()
	} else if address == "" || strings.ContainsAny(address, " /\\@|\t\r\n\x00") {
		o.drop(&o.invalidDrops)
		return
	}
	// The per-process secret is immutable. Prepare expensive HMACs before
	// TryLock; binding authorization and all mutable counters stay under it.
	generation := o.generation.Load()
	key := o.labelKey(tag, label)
	sequence := o.clockSequence.Add(1)
	preparedStart := o.now().Unix() / 60 * 60
	if !o.observeMinute(preparedStart, sequence) {
		return
	}
	targetValue := network + "\x00" + address
	target := o.digest("target-"+strconv.FormatInt(preparedStart, 10), targetValue)
	event := pendingRequest{key: key, target: target, minute: preparedStart, generation: generation, port: port, tcp: network == "tcp", outcome: outcome}
	if !o.mu.TryLock() {
		select {
		case o.pending <- event:
		default:
			o.drop(&o.contentionDrops)
		}
		return
	}
	defer o.mu.Unlock()
	o.drainPendingLocked(pendingDrainBudget)
	sequence = o.clockSequence.Add(1)
	nowStart := o.now().Unix() / 60 * 60
	if !o.observeMinute(nowStart, sequence) {
		return
	}
	if preparedStart != nowStart {
		event.minute = nowStart
		event.target = o.digest("target-"+strconv.FormatInt(nowStart, 10), targetValue)
	}
	o.recordPreparedLocked(event)
}

// Monotonic arrival evidence distinguishes a real clock reversal from a valid
// old-minute entry being drained after a newer minute has already arrived.
func (o *Observer) observeMinute(minute int64, sequence uint64) bool {
	start := o.windowStart.Load()
	if minute < start || minute > start+60 {
		o.clockGap.Store(true)
		o.drop(&o.boundaryDrops)
		return false
	}
	for {
		previous := o.observedMinute.Load()
		// An older read can finish after another thread observed the new
		// minute. Read ordering, not goroutine scheduling, decides rollback.
		if sequence < previous.sequence {
			return true
		}
		if minute < previous.minute {
			o.clockGap.Store(true)
			o.drop(&o.boundaryDrops)
			return false
		}
		if minute == previous.minute || o.observedMinute.CompareAndSwap(previous, &minuteMarker{sequence, minute}) {
			return true
		}
	}
}

func (o *Observer) drainPendingLocked(limit int) {
	for i := 0; i < limit; i++ {
		select {
		case event := <-o.pending:
			o.recordPreparedLocked(event)
		default:
			return
		}
	}
}

func (o *Observer) recordPreparedLocked(event pendingRequest) {
	if event.generation&1 != 0 || event.generation != o.generation.Load() {
		o.discardedSamples.Add(1)
		o.dropped.Add(1)
		return
	}
	nowStart := event.minute
	if nowStart < o.start || nowStart > o.start+60 {
		// A producer can enqueue after a concurrent close. Never move that
		// sample to a later minute or silently discard it.
		o.clockGap.Store(true)
		o.drop(&o.boundaryDrops)
		return
	}
	w := &o.windowCounts
	if nowStart == o.start+60 {
		if o.next == nil {
			o.next = &windowCounts{}
		}
		w = o.next
	}
	subject := o.bindings[event.key]
	if subject == "" {
		w.unmapped++
		return
	}
	a := w.accounts[subject]
	if a == nil {
		slots := len(o.accounts)
		if o.next != nil {
			slots += len(o.next.accounts)
		}
		if slots >= 4096 {
			o.capacityDrops.Add(1)
			w.lost++
			return
		}
		a = &counts{targets: map[[32]byte]int64{}, ports: map[uint16]struct{}{}}
		if w.accounts == nil {
			w.accounts = map[string]*counts{}
		}
		w.accounts[subject] = a
	}
	if o.tcpDialMetrics {
		credential := o.authRefs[event.key].Credential
		if a.metrics.TCPDial == nil {
			a.metrics.TCPDial = &DialMetrics{Credential: credential, IdentityComplete: credential != ""}
		} else if a.metrics.TCPDial.Credential != credential {
			// Credential rotation or ambiguous binding taints this account's
			// whole minute, never attributes old evidence to a new credential.
			a.metrics.TCPDial.Credential = ""
			a.metrics.TCPDial.IdentityComplete = false
		}
	}
	if event.outcome != 0 {
		o.recordDialLocked(w, a, event)
		return
	}
	// Destination fingerprints stay in memory and are never serialized. Their
	// domain includes the sampling window to prevent cross-window linking.
	target, port := event.target, event.port
	_, knownTarget := a.targets[target]
	_, knownPort := a.ports[port]
	delta := 0
	if !knownTarget {
		delta++
	}
	if !knownPort {
		delta++
	}
	edges := o.edges
	if o.next != nil {
		edges += o.next.edges
	}
	if (!knownTarget && len(a.targets) >= 2048) || (!knownPort && len(a.ports) >= 2048) || edges+delta > 65536 {
		o.capacityDrops.Add(1)
		w.lost++
		return
	}
	w.edges += delta
	w.accepted++
	a.targets[target]++
	a.ports[port] = struct{}{}
	a.metrics.ProxyRequests++
	if event.tcp {
		a.metrics.TCPRequests++
	} else {
		a.metrics.UDPAssociations++
	}
	if a.targets[target] > a.metrics.MaxTargetRequests {
		a.metrics.MaxTargetRequests = a.targets[target]
	}
}

// LossDiagnostics contains only process-lifetime counters, not account data.
// It is intentionally absent from Report/Quality JSON to preserve wire compatibility.
// Concurrent reads are approximate; use quiescent reads for counter conservation tests.
type LossDiagnostics struct {
	InvalidInput     uint64
	Contention       uint64
	WindowBoundary   uint64
	Capacity         uint64
	DiscardedSamples uint64
}

func (o *Observer) LossDiagnostics() LossDiagnostics {
	return LossDiagnostics{o.invalidDrops.Load(), o.contentionDrops.Load(), o.boundaryDrops.Load(), o.capacityDrops.Load(), o.discardedSamples.Load()}
}
func (o *Observer) drop(reason *atomic.Uint64) {
	reason.Add(1)
	o.dropped.Add(1)
}

// Snapshot closes a window exactly once. Caller owns a single periodic runner.
// No disk/network I/O occurs under the telemetry lock; retries reuse returned bytes.
func (o *Observer) Snapshot(at time.Time) ([]Report, error) {
	end := at.Unix() / 60 * 60
	// Runtime polls four times per second; most calls cannot close a window.
	// Keep these no-op polls from competing with request collection.
	if end <= o.windowStart.Load() {
		// The 250ms runtime poll also drains idle bursts, but still never
		// waits on a busy telemetry lock or creates an additional goroutine.
		if len(o.pending) > 0 && o.mu.TryLock() {
			o.drainPendingLocked(pendingCapacity)
			o.mu.Unlock()
		}
		return nil, errors.New("window not closed")
	}
	o.mu.Lock()
	if end <= o.start {
		o.mu.Unlock()
		return nil, errors.New("window not closed")
	}
	o.drainPendingLocked(pendingCapacity)
	start := o.start
	revision := o.revision
	accounts := o.accounts
	sharedLoss := o.dropped.Swap(0)
	clockGap := o.clockGap.Swap(false) || end-start != 60
	q := Quality{o.partial || sharedLoss > 0, clockGap, sharedLoss + o.lost, o.unmapped}
	if end-start != 60 {
		// A stalled runner must not spread counts into invented windows, or
		// silently erase the accepted requests it can no longer report.
		discarded := o.accepted
		if o.next != nil {
			discarded += o.next.accepted
			q.DroppedRequests += o.next.lost
			q.UnmappedRequests += o.next.unmapped
		}
		o.discardedSamples.Add(discarded)
		q.DroppedRequests += discarded
		q.PartialWindow = true
		accounts = nil
		start = end - 60
		o.next = nil
	}
	o.start = end
	o.windowStart.Store(end)
	if o.next != nil {
		o.windowCounts = *o.next
		o.next = nil
	} else {
		o.windowCounts = windowCounts{}
	}
	// Do not claim a clean next window when unlocked loss/clock evidence
	// could include requests that arrived after the boundary but before drain.
	o.partial = o.partial || sharedLoss > 0 || clockGap
	o.mu.Unlock()
	subjects := make([]Sample, 0, len(accounts))
	for subject, c := range accounts {
		if o.tcpDialMetrics && c.metrics.TCPDial == nil {
			c.metrics.TCPDial = &DialMetrics{}
		}
		c.metrics.DistinctTargets = len(c.targets)
		c.metrics.DistinctPorts = len(c.ports)
		subjects = append(subjects, Sample{subject, c.metrics})
	}
	sort.Slice(subjects, func(i, j int) bool { return subjects[i].Subject < subjects[j].Subject })
	windowID := ""
	if o.tcpDialMetrics {
		b := make([]byte, 16)
		if _, err := rand.Read(b); err != nil {
			return nil, errors.New("observer entropy unavailable")
		}
		windowID = hex.EncodeToString(b)
	}
	var reports []Report
	for offset := 0; offset < len(subjects) || offset == 0; offset += 200 {
		stop := min(offset+200, len(subjects))
		id := make([]byte, 16)
		if _, err := rand.Read(id); err != nil {
			return nil, errors.New("observer entropy unavailable")
		}
		version, profile := 1, Profile
		if o.tcpDialMetrics {
			version, profile = 2, TCPProfile
		}
		report := Report{Version: version, Profile: profile, IdentityRevision: revision, BatchID: hex.EncodeToString(id), WindowStart: start, WindowEnd: end, Complete: false, Quality: q, Subjects: subjects[offset:stop]}
		if o.tcpDialMetrics {
			report.TCPWindow = &WindowManifest{windowID, offset / 200, max(1, (len(subjects)+199)/200), len(subjects)}
		}
		reports = append(reports, report)
	}
	return reports, nil
}

// Encode signs only the separate observation endpoint; it has no network side effects.
func (o *Observer) Encode(r Report, key []byte, at time.Time) ([]byte, map[string]string, error) {
	return o.encodeWithKeyID(r, key, "", at)
}
func (o *Observer) encodeWithKeyID(r Report, key []byte, keyID string, at time.Time) ([]byte, map[string]string, error) {
	validProfile := (r.Version == 1 && r.Profile == Profile) || (o.tcpDialMetrics && r.Version == 2 && r.Profile == TCPProfile)
	if len(key) < 32 || r.Complete || !validProfile {
		return nil, nil, errors.New("invalid observation envelope")
	}
	if (r.Version == 1 && r.TCPWindow != nil) || (r.Version == 2 && r.TCPWindow == nil) {
		return nil, nil, errors.New("observation window/profile mismatch")
	}
	for _, sample := range r.Subjects {
		if (r.Version == 1 && sample.Metrics.TCPDial != nil) || (r.Version == 2 && sample.Metrics.TCPDial == nil) {
			return nil, nil, errors.New("observation metrics/profile mismatch")
		}
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

// Start owns the production runtime. Tests may set an isolated collector.
func Set(o *Observer) { active.Store(o) }
func Bind(tag, label string, uid int, credential ...string) {
	if o := active.Load(); o != nil {
		o.Bind(tag, label, uid, credential...)
	}
}
func Unbind(tag, label string) {
	if o := active.Load(); o != nil {
		o.Unbind(tag, label)
	}
}
func UnbindTag(tag string) {
	if o := active.Load(); o != nil {
		o.mu.Lock()
		defer o.mu.Unlock()
		o.generation.Add(1)
		defer o.generation.Add(1)
		for key, ref := range o.authRefs {
			if ref.Tag == tag {
				delete(o.authRefs, key)
				delete(o.bindings, key)
			}
		}
	}
}
func Record(tag, label, network, address string, port uint16) {
	if o := active.Load(); o != nil {
		o.Observe(tag, label, network, address, port)
	}
}
