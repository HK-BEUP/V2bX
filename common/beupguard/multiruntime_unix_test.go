//go:build linux || darwin

package beupguard

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func multiFixture(t *testing.T) (string, string, RuntimeSettings, RuntimeSettings, ed25519.PrivateKey, ed25519.PrivateKey) {
	t.Helper()
	base := os.TempDir()
	if _, err := os.Stat("/private/tmp"); err == nil {
		base = "/private/tmp"
	}
	dir, err := os.MkdirTemp(base, "bm-")
	if err != nil {
		t.Fatal(err)
	}
	dir, err = filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { Set(nil); os.RemoveAll(dir) })
	sub := filepath.Join(dir, "cfg")
	if err := os.Mkdir(sub, 0700); err != nil {
		t.Fatal(err)
	}
	settings := func(name string, tags []string, auth bool) (RuntimeSettings, ed25519.PrivateKey) {
		pub, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		state := filepath.Join(dir, name)
		if err := os.Mkdir(state, 0700); err != nil {
			t.Fatal(err)
		}
		store, err := OpenFileStore(state, name, true)
		if err != nil {
			t.Fatal(err)
		}
		store.Close()
		return RuntimeSettings{Version: 1, Node: name, StateDirectory: state, CommandPublicKey: hex.EncodeToString(pub), RequiredTags: tags, AllowBlocks: true, AuthorizationOnly: auth}, key
	}
	primary, pkey := settings("attack", []string{"a", "b"}, false)
	extra, ekey := settings("grant-a", []string{"a"}, true)
	writeSettings(t, filepath.Join(dir, "primary.json"), primary)
	writeSettings(t, filepath.Join(sub, "a.json"), extra)
	t.Setenv("BEUP_GUARD_CONFIG", filepath.Join(dir, "primary.json"))
	t.Setenv("BEUP_SUBSCRIPTION_CONFIG_DIR", sub)
	return dir, sub, primary, extra, pkey, ekey
}
func writeSettings(t *testing.T, path string, settings RuntimeSettings) {
	t.Helper()
	b, err := json.Marshal(settings)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
}
func startMulti(t *testing.T) (func(), error) {
	t.Helper()
	return startFromEnvironment(func() time.Time { return time.Unix(1800000000, 0) }, func() (BootStamp, error) { return BootStamp{"synthetic", 1000000000}, nil })
}
func multiClient(t *testing.T, s RuntimeSettings) *http.Client {
	t.Helper()
	tr := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", filepath.Join(s.StateDirectory, "control.sock"))
	}}
	t.Cleanup(tr.CloseIdleConnections)
	return &http.Client{Transport: tr, Timeout: 2 * time.Second}
}
func TestMultiRuntimeSignedIsolationAndIndependentRelease(t *testing.T) {
	_, _, p, e, pk, ek := multiFixture(t)
	stop, err := startMulti(t)
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	Bind("a", "grant", 2, "synthetic-grant")
	RegisterAuthorization("a", "grant", fmt.Sprintf("%032x", 2))
	Bind("a", "legacy", 2, "legacy")
	Bind("b", "other", 3, "other")
	if !Enabled() || Current() == nil {
		t.Fatal("primary missing")
	}
	group := active.Load()
	if group.entries[1].guard.Stats().Bindings != 2 {
		t.Fatal("other inbound entered subscription scope")
	}
	proof, err := group.entries[1].guard.authorizationProof(AuthorizationRequest{1, fmt.Sprintf("%032x", 1), []AuthorizationTarget{{fmt.Sprintf("%032x", 2), Identity{2, CredentialDigest("synthetic-grant")}}}})
	if err != nil || !proof[0].Bound {
		t.Fatal("single entitled inbound did not bind", err, proof)
	}
	var closed atomic.Int64
	done, err := Track("a", "grant", func() { closed.Add(1) })
	if err != nil {
		t.Fatal(err)
	}
	pc, ec := multiClient(t, p), multiClient(t, e)
	l := Lease{ID: fmt.Sprintf("%032x", 3), Identity: Identity{2, CredentialDigest("synthetic-grant")}, StartedAt: 1800000000, ExpiresAt: 1800000600}
	for _, item := range []struct {
		s RuntimeSettings
		k ed25519.PrivateKey
		c *http.Client
	}{{p, pk, pc}, {e, ek, ec}} {
		if code, _ := rpc(t, item.c, "POST", "/v1/execute", signed(item.k, Command{1, item.s.Node, 1, 1800000000, 1800000060, "block", l})); code != 200 {
			t.Fatal("block failed", item.s.Node, code)
		}
	}
	if closed.Load() != 1 {
		t.Fatal("session close was not coalesced", closed.Load())
	}
	done()
	if code, _ := rpc(t, ec, "POST", "/v1/execute", signed(ek, Command{1, e.Node, 2, 1800000000, 1800000060, "release", l})); code != 200 {
		t.Fatal(code)
	}
	if _, err := Track("a", "grant", nil); err != ErrIsolated {
		t.Fatal("subscription release undid attack hold", err)
	}
	if group.entries[1].guard.Stats().Sessions != 0 {
		t.Fatal("failed track leaked secondary session")
	}
	if code, _ := rpc(t, pc, "POST", "/v1/execute", signed(pk, Command{1, p.Node, 2, 1800000000, 1800000060, "release", l})); code != 200 {
		t.Fatal(code)
	}
	done, err = Track("a", "grant", nil)
	if err != nil {
		t.Fatal(err)
	}
	done()
	done, err = Track("a", "legacy", nil)
	if err != nil {
		t.Fatal("legacy affected", err)
	}
	done()
	l.Identity.Credential = CredentialDigest("legacy")
	l.ID = fmt.Sprintf("%032x", 4)
	if code, _ := rpc(t, ec, "POST", "/v1/execute", signed(ek, Command{1, e.Node, 3, 1800000000, 1800000060, "block", l})); code != 403 {
		t.Fatal("legacy subscription isolation accepted", code)
	}
	UnbindTag("a")
	if group.entries[1].guard.Stats().Bindings != 0 || len(group.entries[1].guard.authorizations) != 0 {
		t.Fatal("stale authorization after inbound removal")
	}
	ResetBindings()
	if Current().Stats().Bindings != 0 {
		t.Fatal("primary bindings retained")
	}
	stop()
	stop()
	if Enabled() {
		t.Fatal("group survived shutdown")
	}
}
func TestMultiRuntimeSubscriptionOnlyAndPerInboundScope(t *testing.T) {
	_, _, _, _, _, _ = multiFixture(t)
	t.Setenv("BEUP_GUARD_CONFIG", "")
	stop, err := startMulti(t)
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	if !Enabled() || Current() != nil {
		t.Fatal("subscription-only activation failed")
	}
	Bind("a", "g", 2, "g")
	Bind("b", "other", 3, "other")
	g := active.Load().entries[0].guard
	if g.Stats().Bindings != 1 {
		t.Fatal("cross-inbound binding")
	}
	if _, err := Track("b", "other", nil); err != ErrIdentity {
		t.Fatal(err)
	}
	if g.Stats().CoverageFailures != 0 {
		t.Fatal("unrelated traffic poisoned coverage")
	}
	done, err := Track("a", "g", nil)
	if err != nil {
		t.Fatal(err)
	}
	done()
}
func TestMultiRuntimeConfigurationRejectionAndCleanup(t *testing.T) {
	for _, mode := range []string{"account-scope", "two-tags", "duplicate-node", "duplicate-journal", "duplicate-tag", "invalid-key", "symlink", "empty", "public-directory"} {
		t.Run(mode, func(t *testing.T) {
			_, sub, p, e, _, _ := multiFixture(t)
			switch mode {
			case "account-scope":
				e.AuthorizationOnly = false
			case "two-tags":
				e.RequiredTags = []string{"a", "b"}
			case "duplicate-node":
				e.Node = p.Node
			case "duplicate-journal":
				e.StateDirectory = p.StateDirectory
			case "duplicate-tag":
				other := e
				other.Node = "other"
				other.StateDirectory = filepath.Join(filepath.Dir(sub), "other")
				writeSettings(t, filepath.Join(sub, "b.json"), other)
			case "invalid-key":
				e.CommandPublicKey = "bad"
			case "symlink":
				if err := os.Symlink(filepath.Join(sub, "a.json"), filepath.Join(sub, "b.json")); err != nil {
					t.Fatal(err)
				}
			case "empty":
				t.Setenv("BEUP_GUARD_CONFIG", "")
				if err := os.Remove(filepath.Join(sub, "a.json")); err != nil {
					t.Fatal(err)
				}
			case "public-directory":
				if err := os.Chmod(sub, 0755); err != nil {
					t.Fatal(err)
				}
			}
			if mode != "empty" {
				writeSettings(t, filepath.Join(sub, "a.json"), e)
			}
			stop, err := startMulti(t)
			if err == nil {
				t.Fatal("invalid subscription settings accepted", mode)
			}
			if mode != "empty" && (!Enabled() || Current() == nil || len(active.Load().entries) != 1) {
				t.Fatal("bad subscription settings disabled existing attack protection", mode)
			}
			if mode == "empty" && Enabled() {
				t.Fatal("empty subscription activated")
			}
			stop()
			if Enabled() {
				t.Fatal("fallback guard did not close")
			}
			// Partial startup must relinquish the primary journal's lock.
			store, err := OpenFileStore(p.StateDirectory, p.Node, false)
			if err != nil {
				t.Fatal("journal lock leaked", err)
			}
			store.Close()
		})
	}
}
