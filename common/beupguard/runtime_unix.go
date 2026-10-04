//go:build linux || darwin

package beupguard

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"syscall"
	"time"
)

type RuntimeSettings struct {
	Version           int      `json:"version"`
	Node              string   `json:"node"`
	StateDirectory    string   `json:"state_directory"`
	CommandPublicKey  string   `json:"command_public_key"`
	RequiredTags      []string `json:"required_tags"`
	AllowBlocks       bool     `json:"allow_blocks"`
	AuthorizationOnly bool     `json:"authorization_only,omitempty"`
}
type RuntimeHealth struct {
	Version         int      `json:"version"`
	Node            string   `json:"node"`
	Sequence        int      `json:"sequence"`
	AllowBlocks     bool     `json:"allow_blocks"`
	Ready           bool     `json:"ready"`
	TrackingReady   bool     `json:"tracking_ready"`
	Bindings        int      `json:"bindings"`
	ActiveLeases    int      `json:"active_leases"`
	TrackedSessions int      `json:"tracked_sessions"`
	Reconcile       []string `json:"reconcile"`
}
type Runtime struct {
	settings   RuntimeSettings
	controller *Controller
	guard      *Guard
	store      *FileStore
	server     *http.Server
	listener   *net.UnixListener
	gate       chan struct{}
}

func LoadRuntimeSettings(path string) (RuntimeSettings, error) {
	var s RuntimeSettings
	if !filepath.IsAbs(path) || privateDir(filepath.Dir(path)) != nil {
		return s, errors.New("private isolation settings required")
	}
	b, e := readPrivate(path)
	if e != nil || len(b) > 65536 {
		return s, errors.New("isolation settings unavailable")
	}
	if decodeStrict(b, &s) != nil || s.Version != 1 || !regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`).MatchString(s.Node) {
		return RuntimeSettings{}, errors.New("invalid isolation settings")
	}
	return s, nil
}

func startRuntime(s RuntimeSettings, now func() time.Time, boot func() (BootStamp, error)) (*Runtime, error) {
	if s.Version != 1 || !regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`).MatchString(s.Node) {
		return nil, errors.New("invalid isolation settings")
	}
	key, e := hex.DecodeString(s.CommandPublicKey)
	if e != nil || len(key) != ed25519.PublicKeySize {
		return nil, errors.New("invalid isolation verification key")
	}
	g := New(65536, now)
	if e = g.RequireTags(s.RequiredTags); e != nil {
		return nil, e
	}
	store, e := OpenFileStore(s.StateDirectory, s.Node, false)
	if e != nil {
		return nil, e
	}
	c, e := OpenController(g, s.Node, ed25519.PublicKey(key), store, now, boot)
	if e != nil {
		store.Close()
		return nil, e
	}
	path := filepath.Join(s.StateDirectory, "control.sock")
	if st, err := os.Lstat(path); err == nil {
		owner, ok := st.Sys().(*syscall.Stat_t)
		if !ok || int(owner.Uid) != os.Geteuid() || st.Mode()&os.ModeSocket == 0 {
			store.Close()
			return nil, errors.New("unsafe isolation socket path")
		}
		// The private journal flock proves no other runtime owns this path.
		if e = os.Remove(path); e != nil {
			store.Close()
			return nil, e
		}
	} else if !os.IsNotExist(err) {
		store.Close()
		return nil, err
	}
	l, e := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if e != nil {
		store.Close()
		return nil, e
	}
	if e = os.Chmod(path, 0600); e != nil {
		l.Close()
		store.Close()
		return nil, e
	}
	r := &Runtime{settings: s, controller: c, guard: g, store: store, listener: l, gate: make(chan struct{}, 1)}
	r.server = &http.Server{Handler: r, ReadHeaderTimeout: time.Second, ReadTimeout: 2 * time.Second, WriteTimeout: 4 * time.Second, IdleTimeout: 5 * time.Second, MaxHeaderBytes: 4096}
	go func() { _ = r.server.Serve(l) }()
	return r, nil
}
func (r *Runtime) health() RuntimeHealth {
	c := r.controller
	c.mu.Lock()
	defer c.mu.Unlock()
	g := r.guard
	g.mu.Lock()
	defer g.mu.Unlock()
	h := RuntimeHealth{Version: 1, Node: c.node, Sequence: len(c.journal.Records), AllowBlocks: r.settings.AllowBlocks, TrackingReady: g.trackingReadyLocked(), Bindings: len(g.bindings), TrackedSessions: len(g.sessions), Reconcile: []string{}}
	for _, l := range g.leases {
		if !g.expired(l, c.now()) {
			h.ActiveLeases++
		}
	}
	for id := range c.reconcile {
		h.Reconcile = append(h.Reconcile, id)
	}
	sort.Strings(h.Reconcile)
	h.Ready = h.AllowBlocks && h.TrackingReady && !c.poisoned && len(h.Reconcile) == 0 && c.now().Unix() >= c.lastWall
	return h
}
func (r *Runtime) ServeHTTP(w http.ResponseWriter, q *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	select {
	case r.gate <- struct{}{}:
		defer func() { <-r.gate }()
	default:
		http.Error(w, "busy", http.StatusServiceUnavailable)
		return
	}
	if q.URL.RawQuery != "" {
		http.Error(w, "invalid request", 400)
		return
	}
	if q.Method == http.MethodGet && q.URL.Path == "/v1/status" {
		_ = json.NewEncoder(w).Encode(r.health())
		return
	}
	if q.Method == http.MethodPost && q.URL.Path == "/v1/authorizations" {
		b, e := io.ReadAll(io.LimitReader(q.Body, 4097))
		var query AuthorizationRequest
		if e != nil || len(b) > 4096 || decodeStrict(b, &query) != nil || !validAuthorizationRequest(query) {
			http.Error(w, "invalid scoped proof request", 400)
			return
		}
		proofs, e := r.guard.authorizationProof(query)
		if e != nil {
			http.Error(w, "proof unavailable", 409)
			return
		}
		h := r.health()
		_ = json.NewEncoder(w).Encode(AuthorizationReport{Version: 1, Node: r.settings.Node, RequestID: query.ID, ObservedAt: r.controller.now().Unix(), Ready: h.Ready, Proofs: proofs})
		return
	}
	if q.Method != http.MethodPost || q.URL.Path != "/v1/execute" {
		http.Error(w, "not found", 404)
		return
	}
	b, e := io.ReadAll(io.LimitReader(q.Body, 4097))
	var envelope Envelope
	if e != nil || len(b) > 4096 || decodeStrict(b, &envelope) != nil {
		http.Error(w, "invalid request", 400)
		return
	}
	cmd, e := verifyEnvelope(envelope, r.settings.Node, r.controller.key)
	if e != nil {
		http.Error(w, "command rejected", 403)
		return
	}
	if cmd.Operation == "block" && r.settings.AuthorizationOnly {
		if cmd.Lease.Manual || cmd.Lease.ExpiresAt-cmd.Lease.StartedAt > 600 || !r.guard.independentIdentity(cmd.Lease.Identity) {
			http.Error(w, "command outside independent authorization scope", 403)
			return
		}
	}
	if cmd.Operation == "block" && !r.settings.AllowBlocks {
		r.controller.mu.Lock()
		known := cmd.Sequence <= uint64(len(r.controller.journal.Records))
		r.controller.mu.Unlock()
		if !known {
			http.Error(w, "new isolation disabled", 409)
			return
		}
	}
	ack, e := r.controller.Execute(envelope)
	if e != nil {
		http.Error(w, "command not applied; reconcile status", 409)
		return
	}
	_ = json.NewEncoder(w).Encode(ack)
}
func (r *Runtime) Close() {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = r.server.Shutdown(ctx)
	_ = r.server.Close()
	_ = r.listener.Close()
	_ = r.store.Close()
}
