//go:build linux || darwin

package beupguard

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func runtimeFixture(t *testing.T, allow bool) (*Runtime, *http.Client, ed25519.PrivateKey) {
	t.Helper()
	base := os.TempDir()
	if _, e := os.Stat("/private/tmp"); e == nil {
		base = "/private/tmp"
	}
	dir, e := os.MkdirTemp(base, "bg-")
	if e != nil {
		t.Fatal(e)
	}
	dir, e = filepath.EvalSymlinks(dir)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	_, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	s, e := OpenFileStore(dir, "synthetic-jp", true)
	if e != nil {
		t.Fatal(e)
	}
	s.Close()
	r, e := startRuntime(RuntimeSettings{Version: 1, Node: "synthetic-jp", StateDirectory: dir, CommandPublicKey: hex.EncodeToString(key.Public().(ed25519.PublicKey)), RequiredTags: []string{"a", "b"}, AllowBlocks: allow}, func() time.Time { return time.Unix(1800000000, 0) }, func() (BootStamp, error) { return BootStamp{"synthetic", 1000000000}, nil })
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(r.Close)
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", filepath.Join(dir, "control.sock"))
	}}
	client := &http.Client{Transport: transport, Timeout: 2 * time.Second}
	t.Cleanup(transport.CloseIdleConnections)
	return r, client, key
}
func rpc(t *testing.T, c *http.Client, method, path string, v any) (int, []byte) {
	t.Helper()
	var b []byte
	if v != nil {
		b, _ = json.Marshal(v)
	}
	req, _ := http.NewRequest(method, "http://private"+path, bytes.NewReader(b))
	res, e := c.Do(req)
	if e != nil {
		t.Fatal(e)
	}
	defer res.Body.Close()
	body, e := io.ReadAll(res.Body)
	if e != nil {
		t.Fatal(e)
	}
	return res.StatusCode, body
}
func TestRuntimePrivateSignedRPCAndRequiredInboundCoverage(t *testing.T) {
	r, client, key := runtimeFixture(t, true)
	_, b := rpc(t, client, "GET", "/v1/status", nil)
	var h RuntimeHealth
	json.Unmarshal(b, &h)
	if h.Ready {
		t.Fatal("missing inbounds ready")
	}
	st, e := os.Lstat(filepath.Join(r.settings.StateDirectory, "control.sock"))
	if e != nil || st.Mode().Perm() != 0600 {
		t.Fatal("socket not private", e)
	}
	l := Lease{ID: fmt.Sprintf("%032x", 1), Identity: Identity{2, CredentialDigest("synthetic")}, StartedAt: 1800000000, ExpiresAt: 1800000600}
	command := signed(key, Command{1, "synthetic-jp", 1, 1800000000, 1800000060, "block", l})
	r.guard.Bind("a", "target", 2, "synthetic")
	if code, _ := rpc(t, client, "POST", "/v1/execute", command); code != 409 {
		t.Fatal("partial scope accepted", code)
	}
	r.guard.Bind("b", "target", 2, "synthetic")
	r.guard.Bind("a", "other", 3, "other")
	if !r.health().Ready {
		t.Fatal("complete authenticated scope missing")
	}
	done, _ := r.guard.Track("a", "target", func() {})
	code, b := rpc(t, client, "POST", "/v1/execute", command)
	var ack Acknowledgement
	json.Unmarshal(b, &ack)
	if code != 200 || !ack.RejectNew || ack.ExistingClosed {
		t.Fatal("premature RPC ack", code, ack)
	}
	done()
	code, b = rpc(t, client, "POST", "/v1/execute", command)
	json.Unmarshal(b, &ack)
	if code != 200 || !ack.ExistingClosed {
		t.Fatal("replay not actual status", code, ack)
	}
	if _, e = r.guard.Track("b", "target", nil); e != ErrIsolated {
		t.Fatal(e)
	}
	if _, e = r.guard.Track("a", "other", nil); e != nil {
		t.Fatal(e)
	}
	r.guard.unbindTag("b")
	if r.health().Ready {
		t.Fatal("removed inbound still ready")
	}
	release := signed(key, Command{1, "synthetic-jp", 2, 1800000000, 1800000060, "release", l})
	if code, _ = rpc(t, client, "POST", "/v1/execute", release); code != 200 {
		t.Fatal("safety release depends on scope health", code)
	}
	if _, e = r.guard.Track("a", "target", nil); e != nil {
		t.Fatal(e)
	}
}
func TestRuntimeDefaultDisabledForgeryAndProtocolBoundaries(t *testing.T) {
	r, client, key := runtimeFixture(t, false)
	r.guard.Bind("a", "target", 2, "synthetic")
	r.guard.Bind("b", "target", 2, "synthetic")
	l := Lease{ID: fmt.Sprintf("%032x", 1), Identity: Identity{2, CredentialDigest("synthetic")}, StartedAt: 1800000000, ExpiresAt: 1800000600}
	c := signed(key, Command{1, "synthetic-jp", 1, 1800000000, 1800000060, "block", l})
	if code, _ := rpc(t, client, "POST", "/v1/execute", c); code != 409 || r.health().Ready {
		t.Fatal("disabled runtime acted")
	}
	c.Signature = hex.EncodeToString(make([]byte, 64))
	if code, _ := rpc(t, client, "POST", "/v1/execute", c); code != 403 {
		t.Fatal("forgery accepted")
	}
	for _, p := range []struct {
		method, path string
		body         any
		want         int
	}{{"POST", "/v1/execute", map[string]int{"extra": 1}, 400}, {"GET", "/v1/execute", nil, 404}, {"GET", "/v1/status?expanded=1", nil, 400}, {"POST", "/v1/execute", string(make([]byte, 5000)), 400}} {
		if code, _ := rpc(t, client, p.method, p.path, p.body); code != p.want {
			t.Fatal(p.path, code, p.want)
		}
	}
	if r.health().Sequence != 0 || r.guard.Stats().Leases != 0 {
		t.Fatal("rejected requests modified overlays")
	}
}
func TestRuntimeEnvironmentOptInOnly(t *testing.T) {
	t.Setenv("BEUP_GUARD_CONFIG", "")
	stop, e := StartFromEnvironment()
	if e != nil || Current() != nil {
		t.Fatal("guard enabled by default", e)
	}
	stop()
	t.Setenv("BEUP_GUARD_CONFIG", "relative.json")
	stop, e = StartFromEnvironment()
	if e == nil || Current() != nil {
		t.Fatal("unsafe config enabled guard")
	}
	stop()
}
