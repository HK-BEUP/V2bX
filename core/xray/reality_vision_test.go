package xray

// Real encrypted end-to-end connections. All keys are ephemeral and all
// listeners, fallback TLS and proxied destinations are loopback-only.
import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"sort"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/InazumaV/V2bX/api/panel"
	"github.com/InazumaV/V2bX/common/beupguard"
	observer "github.com/InazumaV/V2bX/common/beupobserve"
	"github.com/InazumaV/V2bX/common/beuptransfer"
	"github.com/InazumaV/V2bX/conf"
	vCore "github.com/InazumaV/V2bX/core"
	"github.com/InazumaV/V2bX/limiter"
	"github.com/xtls/reality"
	xnet "github.com/xtls/xray-core/common/net"
	xcore "github.com/xtls/xray-core/core"
	xconf "github.com/xtls/xray-core/infra/conf"
)

func TestREALITYVisionEncryptedLoopback(t *testing.T) {
	realityVisionLoopback(t, false)
}

func TestTransferREALITYVisionEncryptedLoopback(t *testing.T) {
	realityVisionLoopback(t, true)
}

func realityVisionLoopback(t *testing.T, reliable bool) {
	guard := beupguard.New(1000, nil)
	beupguard.Set(guard)
	defer beupguard.Set(nil)
	fallback := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("synthetic fallback")) }))
	fallback.EnableHTTP2 = true
	fallback.TLS = &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, CurvePreferences: []tls.CurveID{tls.X25519}}
	fallback.StartTLS()
	defer fallback.Close()
	echo, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			c, e := echo.Accept()
			if e != nil {
				return
			}
			go func() { defer c.Close(); c.SetDeadline(time.Now().Add(5 * time.Second)); io.Copy(c, c) }()
		}
	}()
	// Inner TLS application traffic exercises Vision's raw-copy transition,
	// unlike a plaintext echo inside the encrypted VLESS transport.
	innerEcho, err := tls.Listen("tcp4", "127.0.0.1:0", &tls.Config{Certificates: fallback.TLS.Certificates, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13})
	if err != nil {
		t.Fatal(err)
	}
	defer innerEcho.Close()
	innerErrors := make(chan error, 128)
	go func() {
		for {
			conn, e := innerEcho.Accept()
			if e != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				c.SetDeadline(time.Now().Add(5 * time.Second))
				_, e := io.Copy(c, c)
				if e != nil {
					select {
					case innerErrors <- e:
					default:
					}
				}
			}(conn)
		}
	}()
	reserve, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := reserve.Addr().(*net.TCPAddr).Port
	reserve.Close()
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	public := base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes())
	xc := conf.NewXrayConfig()
	xc.AssetPath = t.TempDir()
	xc.LogConfig.Level = "none"
	xc.LogConfig.AccessPath = "none"
	if os.Getenv("BEUP_SYNTHETIC_XRAY_DEBUG") == "1" {
		xc.LogConfig.Level = "debug"
	}
	proxy, err := New(&conf.CoreConfig{Type: "xray", XrayConfig: xc})
	if err != nil {
		t.Fatal(err)
	}
	if err = proxy.Start(); err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	const tag = "synthetic-reality-vision"
	const uuid = "00000000-0000-4000-8000-000000000042"
	const short = "0123456789abcdef"
	info := &panel.NodeInfo{Type: "vless", Security: panel.Reality, Common: &panel.CommonNode{ServerPort: port},
		VAllss: &panel.VAllssNode{Network: "tcp", NetworkSettings: json.RawMessage(`{}`), Flow: "xtls-rprx-vision",
			TlsSettings: panel.TlsSettings{ServerName: "localhost", Dest: "127.0.0.1", ServerPort: fmt.Sprint(fallback.Listener.Addr().(*net.TCPAddr).Port), PrivateKey: base64.RawURLEncoding.EncodeToString(key.Bytes()), ShortId: short}}}
	opts := conf.NewXrayOptions()
	opts.DisableSniffing = true
	if err = proxy.AddNode(tag, info, &conf.Options{ListenIP: "127.0.0.1", SendIP: "127.0.0.1", XrayOptions: opts}); err != nil {
		t.Fatal(err)
	}
	var transfer *beuptransfer.GuardAdapter
	if reliable {
		transfer, err = proxy.(*Xray).EnableTransferAccounting(tag, strings.Repeat("a", 32), "vless")
		if err != nil {
			t.Fatal(err)
		}
	}
	// REALITY asynchronously probes its fallback. If a client races the probe,
	// the upstream handshake waits in 5-second steps. Await the actual readiness
	// marker; do not inject a fake cache result or retry a failed client silently.
	readyKey := fallback.Listener.Addr().String() + " localhost 2"
	deadline := time.Now().Add(8 * time.Second)
	for {
		if v, ok := reality.GlobalPostHandshakeRecordsLens.Load(readyKey); ok {
			if _, done := v.([]int); done {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("fallback probe did not finish")
		}
		time.Sleep(10 * time.Millisecond)
	}
	const otherUUID = "00000000-0000-4000-8000-000000000043"
	users := []panel.UserInfo{{Id: 42, Uuid: uuid, SubscriptionGrant: "00000000000000000000000000000042"}, {Id: 42, Uuid: otherUUID}}
	limiter.Init()
	limiter.AddLimiter(tag, &conf.LimitConfig{}, users, map[int]int{})
	defer limiter.DeleteLimiter(tag)
	now := time.Now()
	o, err := observer.New(observer.Config{Node: "demo-hk", IdentityRevision: "synthetic-v1", TCPDialMetrics: os.Getenv("BEUP_SYNTHETIC_COLLECTOR_PERF") == "1", Now: func() time.Time { return now }, Bindings: map[string]map[int]string{tag: {42: fmt.Sprintf("%032d", 42)}}})
	if err != nil {
		t.Fatal(err)
	}
	observer.Set(o)
	defer observer.Set(nil)
	if _, err = proxy.AddUsers(&vCore.AddUsersParams{Tag: tag, Users: users, NodeInfo: info}); err != nil {
		t.Fatal(err)
	}
	var afterEcho func(net.Conn) error
	innerTLS := false
	connect := func(id, shortID, pub, flow string) error {
		// JSON serialization avoids accidental interpolation in client settings.
		cfg := map[string]any{"log": map[string]any{"loglevel": "none"}, "outbounds": []any{map[string]any{
			"protocol": "vless", "settings": map[string]any{"vnext": []any{map[string]any{"address": "127.0.0.1", "port": port, "users": []any{map[string]any{"id": id, "encryption": "none", "flow": flow}}}}},
			"streamSettings": map[string]any{"network": "tcp", "security": "reality", "realitySettings": map[string]any{"serverName": "localhost", "fingerprint": "chrome", "publicKey": pub, "shortId": shortID}}}}}
		if os.Getenv("BEUP_SYNTHETIC_XRAY_DEBUG") == "1" {
			cfg["log"] = map[string]any{"loglevel": "debug"}
		}
		raw, _ := json.Marshal(cfg)
		var parsed xconf.Config
		if e := json.Unmarshal(raw, &parsed); e != nil {
			return e
		}
		built, e := parsed.Build()
		if e != nil {
			return e
		}
		client, e := xcore.New(built)
		if e != nil {
			return e
		}
		defer client.Close()
		if e = client.Start(); e != nil {
			return e
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		targetPort := echo.Addr().(*net.TCPAddr).Port
		if innerTLS {
			targetPort = innerEcho.Addr().(*net.TCPAddr).Port
		}
		c, e := xcore.Dial(ctx, client, xnet.TCPDestination(xnet.ParseAddress("127.0.0.1"), xnet.Port(targetPort)))
		if e != nil {
			return e
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(3 * time.Second))
		if innerTLS {
			// Synthetic loopback-only test certificate, never production TLS.
			tc := tls.Client(c, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13})
			// Send the inner close_notify before shutting down the outer tunnel.
			// An abrupt outer TLS close after Vision's raw transition is not an
			// application TLS record and must not pollute the echo peer's checks.
			defer tc.Close()
			if e = tc.HandshakeContext(ctx); e != nil {
				return fmt.Errorf("inner TLS handshake: %w", e)
			}
			c = tc
		}
		payload := []byte("real-encrypted-vision-echo")
		if innerTLS {
			payload = bytes.Repeat([]byte("synthetic-vision-tls13-data"), 4096)
		}
		rounds := 1
		if innerTLS {
			rounds = 3 // include data after the raw-copy transition, not just setup
		}
		for round := 0; round < rounds; round++ {
			if _, e = c.Write(payload); e != nil {
				return fmt.Errorf("application write round %d: %w", round, e)
			}
			got := make([]byte, len(payload))
			if _, e = io.ReadFull(c, got); e != nil {
				return fmt.Errorf("application echo round %d: %w", round, e)
			}
			if !bytes.Equal(got, payload) {
				return fmt.Errorf("payload mismatch")
			}
		}
		if afterEcho != nil {
			return afterEcho(c)
		}
		if innerTLS {
			// xcore.Dial returns an in-process pipe: closing it immediately after
			// a TLS write can discard queued close_notify bytes. Wait for the
			// echo peer's TLS shutdown before closing this outer pipe.
			if e := c.(*tls.Conn).CloseWrite(); e != nil {
				return fmt.Errorf("inner TLS close write: %w", e)
			}
			if n, e := c.Read(make([]byte, 1)); n != 0 || e != io.EOF {
				return fmt.Errorf("inner TLS close read n=%d: %v", n, e)
			}
		}
		return nil
	}
	if os.Getenv("BEUP_SYNTHETIC_COLLECTOR_PERF") == "1" {
		// Opt-in, identical encrypted TLS1.3 request work on loopback. Measures
		// both client and server CPU/allocations, not real customer WAN latency.
		innerTLS = true
		const samples = 30
		for _, workers := range []int{1, 2} {
			for round, mode := range []string{"off", "collector", "collector_guard", "collector_guard", "collector", "off"} {
				if mode == "off" {
					observer.Set(nil)
				} else {
					observer.Set(o)
				}
				if mode == "collector_guard" {
					beupguard.Set(guard)
				} else {
					beupguard.Set(nil)
				}
				for warm := 0; warm < 2; warm++ {
					if e := connect(uuid, short, public, "xtls-rprx-vision"); e != nil {
						t.Fatal(e)
					}
				}
				runtime.GC()
				var before, after runtime.MemStats
				var cpu0, cpu1 syscall.Rusage
				runtime.ReadMemStats(&before)
				syscall.Getrusage(syscall.RUSAGE_SELF, &cpu0)
				times := make([]float64, samples)
				errs := make([]error, samples)
				jobs := make(chan int, samples)
				for i := 0; i < samples; i++ {
					jobs <- i
				}
				close(jobs)
				var wg sync.WaitGroup
				at := time.Now()
				for worker := 0; worker < workers; worker++ {
					wg.Add(1)
					go func() {
						defer wg.Done()
						for i := range jobs {
							start := time.Now()
							errs[i] = connect(uuid, short, public, "xtls-rprx-vision")
							times[i] = float64(time.Since(start).Nanoseconds()) / 1e6
						}
					}()
				}
				wg.Wait()
				elapsed := time.Since(at)
				syscall.Getrusage(syscall.RUSAGE_SELF, &cpu1)
				runtime.ReadMemStats(&after)
				for _, e := range errs {
					if e != nil {
						t.Fatalf("performance workload %s: %v", mode, e)
					}
				}
				sort.Float64s(times)
				sum := 0.0
				for _, v := range times {
					sum += v
				}
				cpu := func(v syscall.Rusage) float64 {
					return float64(v.Utime.Sec+v.Stime.Sec)*1000 + float64(v.Utime.Usec+v.Stime.Usec)/1000
				}
				v := map[string]any{"mode": mode, "round": round, "workers": workers, "connections": samples, "encrypted_echo_bytes_each": 319488, "elapsed_ms": float64(elapsed.Nanoseconds()) / 1e6, "mean_ms": sum / samples, "p50_ms": times[samples/2], "p95_ms": times[28], "process_cpu_ms": cpu(cpu1) - cpu(cpu0), "alloc_bytes": after.TotalAlloc - before.TotalAlloc, "mallocs": after.Mallocs - before.Mallocs, "gc": after.NumGC - before.NumGC, "gomaxprocs": runtime.GOMAXPROCS(0)}
				b, _ := json.Marshal(v)
				t.Log("COLLECTOR_PERF " + string(b))
			}
		}
		for len(innerErrors) > 0 {
			t.Errorf("inner TLS peer: %v", <-innerErrors)
		}
		r, e := o.Snapshot(now.Add(time.Minute))
		if e != nil || len(r) != 1 || len(r[0].Subjects) != 1 || r[0].Subjects[0].Metrics.TCPDial == nil || r[0].Subjects[0].Metrics.TCPDial.Succeeded == 0 {
			t.Fatal("performance path did not exercise TCP metrics", e)
		}
		t.Logf("COLLECTOR_PERF_QUALITY %+v", r[0].Quality)
		return
	}
	t.Run("valid", func(t *testing.T) {
		if e := connect(uuid, short, public, "xtls-rprx-vision"); e != nil {
			t.Fatal(e)
		}
	})
	t.Run("invalid-user", func(t *testing.T) {
		if connect("00000000-0000-4000-8000-000000000099", short, public, "xtls-rprx-vision") == nil {
			t.Fatal("accepted invalid user")
		}
	})
	t.Run("invalid-short-id", func(t *testing.T) {
		if connect(uuid, "ffffffffffffffff", public, "xtls-rprx-vision") == nil {
			t.Fatal("accepted invalid REALITY short ID")
		}
	})
	wrong, _ := ecdh.X25519().GenerateKey(rand.Reader)
	t.Run("invalid-key", func(t *testing.T) {
		if connect(uuid, short, base64.RawURLEncoding.EncodeToString(wrong.PublicKey().Bytes()), "xtls-rprx-vision") == nil {
			t.Fatal("accepted invalid REALITY key")
		}
	})
	t.Run("missing-vision", func(t *testing.T) {
		if connect(uuid, short, public, "") == nil {
			t.Fatal("accepted missing Vision flow")
		}
	})
	reports, err := o.Snapshot(now.Add(time.Minute))
	if err != nil || len(reports) != 1 || len(reports[0].Subjects) != 1 || reports[0].Subjects[0].Metrics.ProxyRequests != 1 {
		t.Fatal("successful authenticated request not uniquely attributed")
	}
	observer.Set(nil)
	innerTLS = true
	if os.Getenv("BEUP_SYNTHETIC_VISION_AB") == "1" {
		for _, enabled := range []bool{false, true} {
			if enabled {
				beupguard.Set(guard)
			} else {
				beupguard.Set(nil)
			}
			failures := 0
			for n := 0; n < 12; n++ {
				if e := connect(uuid, short, public, "xtls-rprx-vision"); e != nil {
					failures++
					t.Logf("AB guard=%v trial=%d: %v", enabled, n, e)
				}
			}
			t.Logf("AB guard=%v failures=%d/12", enabled, failures)
			if failures > 0 {
				t.Fail()
			}
		}
		for len(innerErrors) > 0 {
			t.Errorf("inner TLS peer: %v", <-innerErrors)
		}
		return
	}
	t.Run("inner-tls-without-guard", func(t *testing.T) {
		beupguard.Set(nil)
		defer beupguard.Set(guard)
		if e := connect(uuid, short, public, "xtls-rprx-vision"); e != nil {
			t.Fatal(e)
		}
	})
	t.Run("inner-tls-with-idle-guard", func(t *testing.T) {
		if e := connect(uuid, short, public, "xtls-rprx-vision"); e != nil {
			t.Fatal(e)
		}
	})
	leaseStart := time.Now().Unix()
	lease := beupguard.Lease{ID: fmt.Sprintf("%032x", 2), Identity: beupguard.Identity{UID: 42, Credential: beupguard.CredentialDigest(uuid)}, StartedAt: leaseStart, ExpiresAt: leaseStart + 600}
	t.Run("guard-closes-existing-encrypted-vision", func(t *testing.T) {
		defer func() { afterEcho = nil }()
		afterEcho = func(c net.Conn) error {
			n, e := guard.Apply(lease)
			if e != nil || n < 1 {
				return fmt.Errorf("guard cancel %d %v", n, e)
			}
			c.SetReadDeadline(time.Now().Add(time.Second))
			_, e = c.Read(make([]byte, 1))
			if e == nil {
				return fmt.Errorf("encrypted connection survived")
			}
			if ne, ok := e.(net.Error); ok && ne.Timeout() {
				return fmt.Errorf("encrypted connection only stalled")
			}
			return nil
		}
		if e := connect(uuid, short, public, "xtls-rprx-vision"); e != nil {
			t.Fatal(e)
		}
		afterEcho = nil
	})
	t.Run("guard-rejects-new-encrypted-vision", func(t *testing.T) {
		if connect(uuid, short, public, "xtls-rprx-vision") == nil {
			t.Fatal("isolated credential accepted")
		}
	})
	t.Run("guard-other-credential-unaffected", func(t *testing.T) {
		if e := connect(otherUUID, short, public, "xtls-rprx-vision"); e != nil {
			t.Fatal(e)
		}
	})
	t.Run("guard-release-restores-encrypted-vision", func(t *testing.T) {
		if e := guard.Release(lease.ID, lease.Identity); e != nil {
			t.Fatal(e)
		}
		if e := connect(uuid, short, public, "xtls-rprx-vision"); e != nil {
			t.Fatal(e)
		}
	})
	t.Run("observer-off", func(t *testing.T) {
		if e := connect(uuid, short, public, "xtls-rprx-vision"); e != nil {
			t.Fatal(e)
		}
	})
	if reliable {
		receiver := &transferTestReceiver{}
		box, e := beuptransfer.Open(&transferTestStore{}, receiver, "vless_42", strings.Repeat("a", 32))
		if e != nil {
			t.Fatal(e)
		}
		req := beuptransfer.DrainRequest{ID: strings.Repeat("b", 32), Identity: beuptransfer.Identity{UID: 42, Credential: beupguard.CredentialDigest(uuid)}}
		var final beuptransfer.Sample
		t.Run("transfer-closes-vision-raw-copy-and-settles", func(t *testing.T) {
			defer func() { afterEcho = nil }()
			afterEcho = func(c net.Conn) error {
				deadline := time.Now().Add(2 * time.Second)
				for {
					proof, err := box.Drain(context.Background(), req, transfer)
					if err == nil {
						final = proof.Final
						if final.Upload == 0 || final.Download == 0 {
							return fmt.Errorf("encrypted flow has no measured bytes")
						}
						break
					}
					if !errors.Is(err, beuptransfer.ErrPending) || time.Now().After(deadline) {
						return fmt.Errorf("encrypted transfer drain: %w", err)
					}
					time.Sleep(5 * time.Millisecond)
				}
				state, err := transfer.Inspect(context.Background(), req.Identity)
				if err != nil || !state.TrackingReady || !state.RejectNew || state.Outstanding != 0 {
					return fmt.Errorf("encrypted transfer not closed: %+v %v", state, err)
				}
				c.SetReadDeadline(time.Now().Add(time.Second))
				if _, err = c.Read(make([]byte, 1)); err == nil {
					return fmt.Errorf("encrypted connection survived drain")
				} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
					return fmt.Errorf("encrypted connection stalled instead of closing")
				}
				return nil
			}
			if err := connect(uuid, short, public, "xtls-rprx-vision"); err != nil {
				t.Fatal(err)
			}
		})
		afterEcho = nil
		t.Run("transfer-rejects-old-encrypted-credential", func(t *testing.T) {
			if connect(uuid, short, public, "xtls-rprx-vision") == nil {
				t.Fatal("drained encrypted credential admitted")
			}
		})
		t.Run("transfer-other-credential-still-works", func(t *testing.T) {
			if err := connect(otherUUID, short, public, "xtls-rprx-vision"); err != nil {
				t.Fatal(err)
			}
			proof, err := box.Drain(context.Background(), req, transfer)
			if err != nil || proof.Final != final {
				t.Fatal("encrypted final usage changed after drain", err)
			}
		})
	}
	if e := proxy.DelUsers(users, tag, info); e != nil {
		t.Fatal(e)
	}
	t.Run("deleted-user", func(t *testing.T) {
		if connect(uuid, short, public, "xtls-rprx-vision") == nil {
			t.Fatal("deleted account accepted")
		}
	})
}
