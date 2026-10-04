//go:build linux || darwin

package beupguard

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestPullAgentPHPDurableLedgerEndToEnd(t *testing.T) {
	bridge := os.Getenv("BEUP_PILOT_PHP_BRIDGE")
	if bridge == "" {
		t.Skip("explicit isolated PHP bridge path required")
	}
	if !filepath.IsAbs(bridge) {
		t.Fatal("bridge must be absolute")
	}
	r, _, commandKey := runtimeFixture(t, true)
	var clock atomic.Int64
	clock.Store(1800000000)
	now := func() time.Time { return time.Unix(clock.Load(), 0) }
	r.controller.now = now
	r.guard.now = now
	r.controller.boot = func() (BootStamp, error) {
		return BootStamp{"synthetic", int64(time.Second) * (clock.Load() - 1799999900)}, nil
	}
	for _, tag := range []string{"a", "b"} {
		r.guard.Bind(tag, "target", 2, "synthetic-target")
		r.guard.Bind(tag, "other", 3, "synthetic-other")
	}
	public, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	database := filepath.Join(r.settings.StateDirectory, "synthetic-ledger.sqlite")
	call := func(op string, body any) ([]byte, error) {
		input := map[string]any{"synthetic": true, "database": database, "public_key": hex.EncodeToString(public), "command_key": hex.EncodeToString(commandKey), "now": clock.Load(), "operation": op, "body": body}
		raw, _ := json.Marshal(input)
		cmd := exec.Command("php", bridge)
		cmd.Stdin = bytes.NewReader(raw)
		// Synthetic private keys travel only through stdin, never process arguments or logs.
		b, err := cmd.Output()
		if err != nil {
			return nil, fmt.Errorf("synthetic bridge failed: %w", err)
		}
		return b, nil
	}
	var dropReceipt atomic.Bool
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) {
		var body map[string]any
		if json.NewDecoder(io.LimitReader(q.Body, 16384)).Decode(&body) != nil {
			http.Error(w, "invalid", 400)
			return
		}
		op := strings.TrimPrefix(q.URL.Path, "/")
		if op != "poll" && op != "receipt" {
			http.NotFound(w, q)
			return
		}
		b, err := call(op, body)
		if err != nil {
			http.Error(w, "bridge rejected", 400)
			return
		}
		if op == "receipt" && dropReceipt.Swap(false) {
			http.Error(w, "synthetic lost response after commit", 503)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(b)
	}))
	defer server.Close()
	s := PullSettings{Version: 1, Node: "synthetic-jp", APIBase: server.URL, StateDirectory: r.settings.StateDirectory, ReceiptPrivateKey: hex.EncodeToString(key)}
	agent, e := NewPullAgent(s)
	if e != nil {
		t.Fatal(e)
	}
	defer agent.Close()
	agent.now = now
	// No insecure TLS switch: explicitly trust ONLY this synthetic test certificate.
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	agent.remote.Transport.(*http.Transport).TLSClientConfig.RootCAs = roots
	step := func() {
		t.Helper()
		if e := agent.Step(context.Background()); e != nil {
			t.Fatal(e)
		}
	}
	state := func() map[string]any {
		t.Helper()
		b, e := call("state", map[string]any{})
		if e != nil {
			t.Fatal(e)
		}
		var v map[string]any
		json.Unmarshal(b, &v)
		return v
	}
	issue := func() map[string]any {
		t.Helper()
		b, e := call("issue", map[string]any{"credential": CredentialDigest("synthetic-target"), "event_id": fmt.Sprintf("%032x", clock.Load())})
		if e != nil {
			t.Fatal(e)
		}
		var v map[string]any
		json.Unmarshal(b, &v)
		if v["action"] != "queued" {
			t.Fatal("not queued", v)
		}
		return v
	}
	checkAllowed := func(tag, label string, want error) {
		t.Helper()
		done, e := r.guard.Track(tag, label, nil)
		if e != want {
			t.Fatalf("%s/%s: %v want %v", tag, label, e, want)
		}
		if done != nil {
			done()
		}
	}
	step()
	first := issue()
	done, e := r.guard.Track("a", "target", func() {})
	if e != nil {
		t.Fatal(e)
	}
	step()
	if state()["confirmations"] != float64(0) {
		t.Fatal("closing was confirmed")
	}
	done()
	dropReceipt.Store(true)
	if e = agent.Step(context.Background()); e == nil {
		t.Fatal("lost reply reported success")
	}
	step()
	if state()["confirmations"] != float64(1) {
		t.Fatal("lost receipt retry changed count")
	}
	checkAllowed("a", "target", ErrIsolated)
	checkAllowed("b", "target", ErrIsolated)
	checkAllowed("a", "other", nil)
	clock.Add(600)
	checkAllowed("b", "target", nil)
	step()
	st := state()
	ls := st["leases"].([]any)
	if ls[0].(map[string]any)["state"] != "expired" {
		t.Fatal("expiry not acknowledged", first)
	}
	step()
	second := issue()
	if second["occurrence"] != float64(2) || second["manual"] != false {
		t.Fatal(second)
	}
	step()
	clock.Add(600)
	step()
	step()
	third := issue()
	if third["occurrence"] != float64(3) || third["manual"] != true {
		t.Fatal(third)
	}
	step()
	clock.Add(90000)
	step()
	checkAllowed("a", "target", ErrIsolated)
	_, e = call("release", map[string]any{"lease_id": third["lease_id"], "sequence": third["sequence"]})
	if e != nil {
		t.Fatal(e)
	}
	step()
	checkAllowed("a", "target", nil)
	checkAllowed("b", "target", nil)
	if state()["confirmations"] != float64(3) {
		t.Fatal("release changed strike count")
	}
	// Website unavailable cannot renew or create a lease, and no global account
	// writes exist in the bridge. Japan scope is part of each receipt response.
	server.Close()
	if agent.Step(context.Background()) == nil {
		t.Fatal("offline endpoint reported success")
	}
	checkAllowed("a", "other", nil)
}

func TestPullAgentRejectsUnsafeEndpointAndMalformedResponse(t *testing.T) {
	r, _, _ := runtimeFixture(t, false)
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	good := PullSettings{Version: 1, Node: "synthetic-jp", APIBase: "https://example.test/pilot", StateDirectory: r.settings.StateDirectory, ReceiptPrivateKey: hex.EncodeToString(key)}
	for _, target := range []string{"http://example.test", "https://user:pass@example.test", "https://example.test/?token=x", "https://example.test/#x", "https://example.test/pilot/"} {
		s := good
		s.APIBase = target
		if a, e := NewPullAgent(s); e == nil {
			a.Close()
			t.Fatal("unsafe endpoint accepted")
		}
	}
	for _, mode := range []string{"wrong_nonce", "wrong_node", "redirect", "html", "oversized", "unknown_field", "untrusted_tls"} {
		t.Run(mode, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) {
				if mode == "redirect" {
					http.Redirect(w, q, "https://example.test/", 302)
					return
				}
				if mode == "html" {
					w.Header().Set("Content-Type", "text/html")
					_, _ = w.Write([]byte("<html>login</html>"))
					return
				}
				w.Header().Set("Content-Type", "application/json")
				if mode == "oversized" {
					_, _ = w.Write(bytes.Repeat([]byte(" "), 9000))
					return
				}
				v := map[string]any{"version": 1, "node": "synthetic-jp", "poll_nonce": "wrong", "challenge": "", "command": nil, "reconcile": false}
				if mode == "wrong_node" {
					v["node"] = "synthetic-hk"
				}
				if mode == "unknown_field" {
					v["global_ban"] = true
				}
				_ = json.NewEncoder(w).Encode(v)
			}))
			defer server.Close()
			s := good
			s.APIBase = server.URL
			a, e := NewPullAgent(s)
			if e != nil {
				t.Fatal(e)
			}
			defer a.Close()
			if mode != "untrusted_tls" {
				roots := x509.NewCertPool()
				roots.AddCert(server.Certificate())
				a.remote.Transport.(*http.Transport).TLSClientConfig.RootCAs = roots
			}
			if a.Step(context.Background()) == nil {
				t.Fatal("unsafe response accepted")
			}
		})
	}
}
