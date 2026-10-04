//go:build linux || darwin

package beupguard

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"
)

const PollDomain = "BEUP-ACCOUNT-ISOLATION-POLL-V1\n"

type Poll struct {
	Version    int           `json:"version"`
	Node       string        `json:"node"`
	Nonce      string        `json:"nonce"`
	ObservedAt int64         `json:"observed_at"`
	Health     RuntimeHealth `json:"health"`
}
type PullSettings struct {
	Version           int    `json:"version"`
	Node              string `json:"node"`
	APIBase           string `json:"api_base"`
	StateDirectory    string `json:"state_directory"`
	ReceiptPrivateKey string `json:"receipt_private_key"`
}
type pollResponse struct {
	Authorizations *AuthorizationRequest `json:"authorizations,omitempty"`
	Version        int                   `json:"version"`
	Node           string                `json:"node"`
	PollNonce      string                `json:"poll_nonce"`
	Challenge      string                `json:"challenge"`
	Command        *Envelope             `json:"command"`
	Reconcile      bool                  `json:"reconcile"`
}
type receiptResponse struct {
	Accepted bool   `json:"accepted"`
	Outcome  string `json:"outcome"`
	LeaseID  string `json:"lease_id"`
	Scope    string `json:"scope"`
	Node     string `json:"node"`
}

// PullAgent is independent of proxy goroutines. It exposes no TCP listener,
// accepts no command-line credentials, and never calls a public node port.
type PullAgent struct {
	settings PullSettings
	key      ed25519.PrivateKey
	remote   *http.Client
	local    *http.Client
	now      func() time.Time
	lock     *os.File
}

func LoadPullSettings(path string) (PullSettings, error) {
	var s PullSettings
	if !filepath.IsAbs(path) || privateDir(filepath.Dir(path)) != nil {
		return s, errors.New("private pull settings required")
	}
	b, e := readPrivate(path)
	if e != nil || len(b) > 8192 || decodeStrict(b, &s) != nil {
		return s, errors.New("pull settings unavailable")
	}
	return s, nil
}

func NewPullAgent(s PullSettings) (*PullAgent, error) {
	u, e := url.Parse(s.APIBase)
	if e != nil || s.Version != 1 || !regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`).MatchString(s.Node) || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.RawPath != "" || strings.HasSuffix(u.Path, "/") || !filepath.IsAbs(s.StateDirectory) || privateDir(s.StateDirectory) != nil {
		return nil, errors.New("invalid private pull endpoint")
	}
	key, e := hex.DecodeString(s.ReceiptPrivateKey)
	if e != nil || len(key) != ed25519.PrivateKeySize || !bytes.Equal(key, ed25519.NewKeyFromSeed(key[:32])) {
		return nil, errors.New("invalid node receipt key")
	}
	lock, e := os.OpenFile(filepath.Join(s.StateDirectory, "pull.lock"), os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if e != nil {
		return nil, errors.New("private pull lock unavailable")
	}
	st, e := lock.Stat()
	if e != nil {
		lock.Close()
		return nil, errors.New("pull lock stat failed")
	}
	owner, ok := st.Sys().(*syscall.Stat_t)
	if !ok || int(owner.Uid) != os.Geteuid() || !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 {
		lock.Close()
		return nil, errors.New("unsafe pull lock")
	}
	if syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		lock.Close()
		return nil, errors.New("pull agent already active")
	}
	remote := &http.Client{Timeout: 8 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirects forbidden") }, Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, DialContext: (&net.Dialer{Timeout: 3 * time.Second}).DialContext, TLSHandshakeTimeout: 3 * time.Second, ResponseHeaderTimeout: 4 * time.Second, MaxConnsPerHost: 1, MaxIdleConnsPerHost: 1, IdleConnTimeout: 30 * time.Second}}
	socket := filepath.Join(s.StateDirectory, "control.sock")
	local := &http.Client{Timeout: 4 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("local redirects forbidden") }, Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "unix", socket)
	}, MaxConnsPerHost: 1, MaxIdleConnsPerHost: 1, IdleConnTimeout: 10 * time.Second}}
	// Do not retain the hex private key in a second settings representation.
	s.ReceiptPrivateKey = ""
	return &PullAgent{settings: s, key: ed25519.PrivateKey(key), remote: remote, local: local, now: time.Now, lock: lock}, nil
}

func (a *PullAgent) Close() {
	a.remote.CloseIdleConnections()
	a.local.CloseIdleConnections()
	if a.lock != nil {
		a.lock.Close()
		a.lock = nil
	}
}

func (a *PullAgent) Step(ctx context.Context) error {
	var h RuntimeHealth
	if e := requestJSON(ctx, a.local, http.MethodGet, "http://private/v1/status", nil, &h, 8192); e != nil {
		return errors.New("local control unavailable")
	}
	if h.Version != 1 || h.Node != a.settings.Node {
		return errors.New("local control identity mismatch")
	}
	nonceBytes := make([]byte, 16)
	if _, e := rand.Read(nonceBytes); e != nil {
		return errors.New("poll nonce unavailable")
	}
	nonce := hex.EncodeToString(nonceBytes)
	p := Poll{Version: 1, Node: a.settings.Node, Nonce: nonce, ObservedAt: a.now().Unix(), Health: h}
	raw, e := json.Marshal(p)
	if e != nil || len(raw) > 6000 {
		return errors.New("poll health exceeds bounds")
	}
	signed := Envelope{Payload: base64.StdEncoding.EncodeToString(raw), Signature: hex.EncodeToString(ed25519.Sign(a.key, append([]byte(PollDomain), raw...)))}
	var response pollResponse
	if e = requestJSON(ctx, a.remote, http.MethodPost, a.settings.APIBase+"/poll", struct {
		Node     string   `json:"node"`
		Envelope Envelope `json:"envelope"`
	}{a.settings.Node, signed}, &response, 8192); e != nil {
		return errors.New("pilot poll unavailable")
	}
	if response.Version != 1 || response.Node != a.settings.Node || response.PollNonce != nonce {
		return errors.New("pilot poll scope mismatch")
	}
	if response.Authorizations != nil {
		if !validAuthorizationRequest(*response.Authorizations) {
			return errors.New("invalid authorization targets")
		}
		var report AuthorizationReport
		if e = requestJSON(ctx, a.local, http.MethodPost, "http://private/v1/authorizations", response.Authorizations, &report, 8192); e != nil {
			return errors.New("authorization proof unavailable")
		}
		if report.Version != 1 || report.Node != a.settings.Node || report.RequestID != response.Authorizations.ID {
			return errors.New("authorization proof scope mismatch")
		}
		raw, e := json.Marshal(report)
		if e != nil || len(raw) > 8192 {
			return errors.New("authorization proof too large")
		}
		signed := Envelope{Payload: base64.StdEncoding.EncodeToString(raw), Signature: hex.EncodeToString(ed25519.Sign(a.key, append([]byte(AuthorizationProofDomain), raw...)))}
		var result struct {
			Accepted bool `json:"accepted"`
		}
		if e = requestJSON(ctx, a.remote, http.MethodPost, a.settings.APIBase+"/authorizations", struct {
			Node     string   `json:"node"`
			Envelope Envelope `json:"envelope"`
		}{a.settings.Node, signed}, &result, 1024); e != nil || !result.Accepted {
			return errors.New("authorization proof not accepted")
		}
	}
	if response.Command == nil {
		if response.Challenge != "" {
			return errors.New("unexpected receipt challenge")
		}
		return nil
	}
	if !regexp.MustCompile(`^[a-f0-9]{32}$`).MatchString(response.Challenge) {
		return errors.New("invalid receipt challenge")
	}
	// The private controller, not the web response, verifies Ed25519 command
	// authority, exact node, monotonic sequence, TTL and credential bindings.
	var ack Acknowledgement
	if e = requestJSON(ctx, a.local, http.MethodPost, "http://private/v1/execute", response.Command, &ack, 4096); e != nil {
		return errors.New("command unconfirmed; poll will reconcile")
	}
	if ack.Node != a.settings.Node {
		return errors.New("local acknowledgement scope mismatch")
	}
	r := Receipt{Version: 1, Node: a.settings.Node, Challenge: response.Challenge, CommandDigest: CommandDigest(*response.Command), ObservedAt: a.now().Unix(), Ack: ack}
	signedReceipt, e := SignReceipt(r, a.key)
	if e != nil {
		return errors.New("receipt signing failed")
	}
	var accepted receiptResponse
	if e = requestJSON(ctx, a.remote, http.MethodPost, a.settings.APIBase+"/receipt", struct {
		Node      string   `json:"node"`
		Challenge string   `json:"challenge"`
		Envelope  Envelope `json:"envelope"`
	}{a.settings.Node, response.Challenge, signedReceipt}, &accepted, 4096); e != nil {
		return errors.New("receipt unconfirmed; poll will reconcile")
	}
	if !accepted.Accepted || accepted.Node != a.settings.Node || accepted.Scope != "node_local" || accepted.LeaseID != ack.LeaseID {
		return errors.New("receipt acknowledgement mismatch")
	}
	return nil
}

// Single-flight loop with a 10s normal cadence and bounded failure backoff.
// It neither blocks proxy traffic nor changes a lease when the website is down.
func (a *PullAgent) Run(ctx context.Context, report func(error)) {
	delay := 10 * time.Second
	for ctx.Err() == nil {
		e := a.Step(ctx)
		if e != nil {
			delay *= 2
			if delay > 60*time.Second {
				delay = 60 * time.Second
			}
		} else {
			delay = 10 * time.Second
		}
		if report != nil {
			report(e)
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

func requestJSON(ctx context.Context, c *http.Client, method, target string, payload any, out any, limit int64) error {
	var body io.Reader
	if payload != nil {
		raw, e := json.Marshal(payload)
		if e != nil || len(raw) > 16384 {
			return errors.New("request bounds")
		}
		body = bytes.NewReader(raw)
	}
	q, e := http.NewRequestWithContext(ctx, method, target, body)
	if e != nil {
		return e
	}
	q.Header.Set("Accept", "application/json")
	q.Header.Set("Content-Type", "application/json")
	q.Header.Set("Cache-Control", "no-store")
	r, e := c.Do(q)
	if e != nil {
		return e
	}
	defer r.Body.Close()
	if r.StatusCode != 200 {
		return errors.New("request rejected")
	}
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		return errors.New("non-JSON response")
	}
	b, e := io.ReadAll(io.LimitReader(r.Body, limit+1))
	if e != nil || int64(len(b)) > limit {
		return errors.New("response bounds")
	}
	return decodeStrict(b, out)
}
