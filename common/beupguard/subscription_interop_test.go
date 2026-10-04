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

func TestSubscriptionSignedProofIsolationAndManualRestorePHP(t *testing.T) {
	bridge := os.Getenv("BEUP_SUBSCRIPTION_PHP_BRIDGE")
	if bridge == "" {
		t.Skip("explicit synthetic PHP bridge required")
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
	grant := fmt.Sprintf("%032x", 1)
	for _, tag := range []string{"a", "b"} {
		r.guard.Bind(tag, "target", 2, "synthetic-target")
		r.guard.registerAuthorization(tag, "target", grant)
		r.guard.Bind(tag, "legacy", 2, "synthetic-legacy")
		r.guard.Bind(tag, "sibling", 2, "synthetic-sibling")
		r.guard.registerAuthorization(tag, "sibling", fmt.Sprintf("%032x", 2))
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
		b, e := cmd.Output()
		if e != nil {
			return nil, fmt.Errorf("synthetic bridge %s failed", op)
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
		b, e := call(op, body)
		if e != nil {
			http.Error(w, "synthetic bridge rejected", 400)
			return
		}
		if op == "receipt" && dropReceipt.Swap(false) {
			http.Error(w, "synthetic lost receipt response", 503)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(b)
	}))
	defer server.Close()
	agent, e := NewPullAgent(PullSettings{Version: 1, Node: "synthetic-jp", APIBase: server.URL, StateDirectory: r.settings.StateDirectory, ReceiptPrivateKey: hex.EncodeToString(key)})
	if e != nil {
		t.Fatal(e)
	}
	defer agent.Close()
	agent.now = now
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	agent.remote.Transport.(*http.Transport).TLSClientConfig.RootCAs = roots
	step := func() {
		t.Helper()
		if e := agent.Step(context.Background()); e != nil {
			t.Fatal(e)
		}
	}
	invoke := func(op string, body any) map[string]any {
		t.Helper()
		b, e := call(op, body)
		if e != nil {
			t.Fatal(e)
		}
		var value map[string]any
		if e = json.Unmarshal(b, &value); e != nil {
			t.Fatal(e)
		}
		return value
	}
	allowed := func(label string, want error) {
		t.Helper()
		for _, tag := range []string{"a", "b"} {
			done, e := r.guard.Track(tag, label, func() {})
			if e != want {
				t.Fatalf("%s/%s got %v want %v", tag, label, e, want)
			}
			done()
		}
	}
	step()
	denied := invoke("issue", map[string]any{"event_id": fmt.Sprintf("%032x", 11)})
	if denied["action"] != "observe" {
		t.Fatal("binding without authenticated use authorized isolation")
	}
	done, e := r.guard.Track("a", "target", func() {})
	if e != nil {
		t.Fatal(e)
	}
	clock.Add(1)
	step()
	first := invoke("issue", map[string]any{"event_id": fmt.Sprintf("%032x", 12)})
	if first["action"] != "queued" {
		t.Fatal(first)
	}
	step()
	if invoke("state", map[string]any{})["confirmations"] != float64(0) {
		t.Fatal("old session still open reported isolated")
	}
	done()
	clock.Add(1)
	dropReceipt.Store(true)
	if agent.Step(context.Background()) == nil {
		t.Fatal("lost response claimed success")
	}
	step()
	state := invoke("state", map[string]any{})
	if state["confirmations"] != float64(1) {
		t.Fatal("retry duplicated or lost isolation")
	}
	allowed("target", ErrIsolated)
	allowed("legacy", nil)
	allowed("sibling", nil)
	invoke("release", map[string]any{"lease_id": first["lease_id"], "sequence": first["sequence"]})
	step()
	allowed("target", nil)
	allowed("legacy", nil)
	allowed("sibling", nil)
	state = invoke("state", map[string]any{})
	if state["leases"].([]any)[0].(map[string]any)["state"] != "released" {
		t.Fatal("manual restoration not acknowledged")
	}
	customer := state["customer"].(map[string]any)
	if customer["banned"] != float64(0) || customer["token"] != "SYNTHETIC_LEGACY_UNCHANGED" {
		t.Fatal("legacy customer account changed")
	}
	// A separate confirmed incident after recovery still has a local fixed TTL.
	clock.Add(1)
	allowed("target", nil)
	step()
	second := invoke("issue", map[string]any{"event_id": fmt.Sprintf("%032x", 13)})
	if second["action"] != "queued" {
		t.Fatal(second)
	}
	step()
	allowed("target", ErrIsolated)
	clock.Add(600)
	allowed("target", nil)
	step()
	state = invoke("state", map[string]any{})
	if state["leases"].([]any)[1].(map[string]any)["state"] != "expired" {
		t.Fatal("local expiry unconfirmed")
	}
	server.Close()
	if agent.Step(context.Background()) == nil {
		t.Fatal("offline website accepted")
	}
	allowed("legacy", nil)
	allowed("sibling", nil)
}
