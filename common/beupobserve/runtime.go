package observer

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

type Settings struct {
	Enabled          bool                      `json:"enabled"`
	Mode             string                    `json:"mode"`
	Node             string                    `json:"node"`
	IdentityRevision string                    `json:"identity_revision"`
	Endpoint         string                    `json:"endpoint"`
	ObservationKey   string                    `json:"observation_key"`
	Bindings         map[string]map[int]string `json:"bindings"`
	Registration     *RegistrationSource       `json:"registration,omitempty"`
}
type Runtime struct {
	Observer                                                                       *Observer
	settings                                                                       Settings
	client                                                                         *http.Client
	queue                                                                          chan Report
	Sent, Failed, Expired, QueueDropped                                            atomic.Uint64
	settingsMu                                                                     sync.RWMutex
	source                                                                         *RegistrationSource
	sequence, expiresAt, issuedAt                                                  int64
	keyID                                                                          string
	registrationFingerprint                                                        [32]byte
	suspended                                                                      bool
	RegistrationReloaded, RegistrationRejected, RegistrationExpired, StaleRevision atomic.Uint64
}

func validEndpoint(endpoint string) bool {
	u, e := url.Parse(endpoint)
	if e != nil || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "/api/v1/attack-guard/observation" {
		return false
	}
	if u.Scheme == "https" {
		return true
	}
	ip, e := netip.ParseAddr(u.Hostname())
	return u.Scheme == "http" && e == nil && ip.IsLoopback()
}
func NewRuntime(s Settings) (*Runtime, error) {
	var claims registrationClaims
	if s.Registration != nil {
		// Signed and legacy unsigned fields must never be mixed.
		if s.ObservationKey != "" || s.IdentityRevision != "" || len(s.Bindings) > 0 {
			return nil, errors.New("mixed registration settings")
		}
		var err error
		claims, err = loadRegistration(*s.Registration, s.Node, s.Endpoint, time.Now())
		if err != nil {
			return nil, err
		}
		s.IdentityRevision = claims.IdentityRevision
		s.ObservationKey = claims.ObservationKey
		s.Bindings = claims.Bindings
	}
	if !s.Enabled || s.Mode != "observe" || !validEndpoint(s.Endpoint) || len(s.ObservationKey) < 32 {
		return nil, errors.New("invalid observation-only runtime settings")
	}
	o, e := New(Config{Node: s.Node, IdentityRevision: s.IdentityRevision, Bindings: s.Bindings})
	if e != nil {
		return nil, e
	}
	r := &Runtime{Observer: o, settings: s, queue: make(chan Report, 64), client: &http.Client{
		Timeout:       2 * time.Second,
		Transport:     &http.Transport{Proxy: nil, MaxIdleConns: 2, MaxIdleConnsPerHost: 2, IdleConnTimeout: 60 * time.Second},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
	if s.Registration != nil {
		source := *s.Registration
		r.source = &source
		r.sequence = claims.Sequence
		r.expiresAt = claims.ExpiresAt
		r.issuedAt = claims.IssuedAt
		r.keyID = claims.KeyID
		r.registrationFingerprint = claims.fingerprint()
	}
	return r, nil
}

// Config contains a report key, so validate ownership/permissions before reading.
// Only a private regular file inside a private directory is accepted.
func LoadSettings(path string) (Settings, error) {
	var s Settings
	if !filepath.IsAbs(path) {
		return s, errors.New("private observation settings required")
	}
	for _, p := range []string{filepath.Dir(path), path} {
		st, e := os.Lstat(p)
		if e != nil {
			return s, errors.New("private observation settings unavailable")
		}
		if !ownedByCurrentUser(st) || st.Mode().Perm()&0077 != 0 || st.Mode()&os.ModeSymlink != 0 {
			return s, errors.New("private observation settings required")
		}
		if p == path && (!st.Mode().IsRegular() || st.Size() > 4*1024*1024) {
			return s, errors.New("invalid observation settings file")
		}
	}
	before, e := os.Lstat(path)
	if e != nil {
		return s, errors.New("observation settings unavailable")
	}
	f, e := os.Open(path)
	if e != nil {
		return s, errors.New("observation settings unavailable")
	}
	defer f.Close()
	opened, e := f.Stat()
	if e != nil || !os.SameFile(before, opened) || opened.Mode().Perm()&0077 != 0 {
		return s, errors.New("observation settings changed")
	}
	d := json.NewDecoder(io.LimitReader(f, 4*1024*1024+1))
	d.DisallowUnknownFields()
	if e = d.Decode(&s); e != nil {
		return Settings{}, errors.New("invalid observation settings")
	}
	if d.Decode(new(any)) != io.EOF {
		return Settings{}, errors.New("invalid observation settings")
	}
	return s, nil
}

// Enqueue is bounded and nonblocking. No traffic-handling goroutine does HTTP I/O.
func (r *Runtime) Enqueue(report Report) bool {
	select {
	case r.queue <- report:
		return true
	default:
		r.QueueDropped.Add(1)
		return false
	}
}
func (r *Runtime) send(ctx context.Context, report Report) bool {
	for attempt := 0; attempt < 2; attempt++ {
		if time.Now().Unix()-report.WindowEnd > 120 {
			r.Expired.Add(1)
			return false
		}
		r.settingsMu.RLock()
		key, endpoint, keyID := r.settings.ObservationKey, r.settings.Endpoint, r.keyID
		stale := report.IdentityRevision != r.settings.IdentityRevision
		expired := r.source != nil && (r.suspended || time.Now().Unix() >= r.expiresAt)
		r.settingsMu.RUnlock()
		if stale {
			r.StaleRevision.Add(1)
			return false
		}
		if expired {
			r.Expired.Add(1)
			return false
		}
		body, h, e := r.Observer.encodeWithKeyID(report, []byte(key), keyID, time.Now())
		if e != nil {
			r.Failed.Add(1)
			return false
		}
		req, e := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
		if e != nil {
			r.Failed.Add(1)
			return false
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Guard-Node", h["node"])
		if keyID != "" {
			req.Header.Set("X-Guard-Key-Id", keyID)
		}
		req.Header.Set("X-Guard-Timestamp", h["timestamp"])
		req.Header.Set("X-Guard-Signature", h["signature"])
		resp, e := r.client.Do(req)
		if e == nil {
			var reply struct {
				Data struct {
					ObservationOnly bool `json:"observation_only"`
				} `json:"data"`
			}
			decodeErr := json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&reply)
			resp.Body.Close()
			if resp.StatusCode >= 200 && resp.StatusCode < 300 && decodeErr == nil && reply.Data.ObservationOnly {
				r.Sent.Add(1)
				return true
			}
			// Authentication, schema and redirects are not retried automatically.
			if resp.StatusCode < 500 {
				break
			}
		}
		if attempt == 0 {
			select {
			case <-ctx.Done():
				r.Failed.Add(1)
				return false
			case <-time.After(250 * time.Millisecond):
			}
		}
	}
	r.Failed.Add(1)
	return false
}
func (r *Runtime) Run(ctx context.Context) {
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-ctx.Done():
				return
			case report := <-r.queue:
				r.send(ctx, report)
			}
		}
	}()
	ticker := time.NewTicker(250 * time.Millisecond)
	reloader := time.NewTicker(5 * time.Second)
	defer reloader.Stop()
	defer ticker.Stop()
	defer func() { wg.Wait(); r.client.CloseIdleConnections() }()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-reloader.C:
			_ = r.reloadRegistration(now)
		case now := <-ticker.C:
			if reports, e := r.Observer.Snapshot(now); e == nil {
				for _, report := range reports {
					r.Enqueue(report)
				}
			}
		}
	}
}

// Called once by the candidate server entrypoint. Empty env -> no-op. Failure
// disables telemetry, not the proxy, and returns only a generic diagnostic.
func StartFromEnvironment() (func(), error) {
	path := os.Getenv("BEUP_OBSERVATION_CONFIG")
	if path == "" {
		return func() {}, nil
	}
	s, e := LoadSettings(path)
	if e != nil {
		return func() {}, e
	}
	if !s.Enabled {
		return func() {}, nil
	}
	r, e := NewRuntime(s)
	if e != nil {
		return func() {}, e
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	Set(r.Observer)
	go func() { defer close(done); r.Run(ctx) }()
	var once sync.Once
	return func() { once.Do(func() { Set(nil); cancel(); <-done }) }, nil
}

// A full proxy-core reload invalidates previous credential bindings and counters.
func Reset() {
	if o := active.Load(); o != nil {
		o.mu.Lock()
		o.bindings = map[[32]byte]string{}
		o.authRefs = map[[32]byte]authRef{}
		o.accounts = map[string]*counts{}
		o.edges = 0
		o.partial = true
		o.mu.Unlock()
	}
}
