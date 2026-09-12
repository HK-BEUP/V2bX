package xray

// Real encrypted end-to-end connections. All keys are ephemeral and all
// listeners, fallback TLS and proxied destinations are loopback-only.
import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/InazumaV/V2bX/api/panel"
	observer "github.com/InazumaV/V2bX/common/beupobserve"
	"github.com/InazumaV/V2bX/conf"
	vCore "github.com/InazumaV/V2bX/core"
	"github.com/InazumaV/V2bX/limiter"
	"github.com/xtls/reality"
	xnet "github.com/xtls/xray-core/common/net"
	xcore "github.com/xtls/xray-core/core"
	xconf "github.com/xtls/xray-core/infra/conf"
)

func TestREALITYVisionEncryptedLoopback(t *testing.T) {
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
	users := []panel.UserInfo{{Id: 42, Uuid: uuid}}
	limiter.Init()
	limiter.AddLimiter(tag, &conf.LimitConfig{}, users, map[int]int{})
	defer limiter.DeleteLimiter(tag)
	now := time.Now()
	o, err := observer.New(observer.Config{Node: "demo-hk", IdentityRevision: "synthetic-v1", Now: func() time.Time { return now }, Bindings: map[string]map[int]string{tag: {42: fmt.Sprintf("%032d", 42)}}})
	if err != nil {
		t.Fatal(err)
	}
	observer.Set(o)
	defer observer.Set(nil)
	if _, err = proxy.AddUsers(&vCore.AddUsersParams{Tag: tag, Users: users, NodeInfo: info}); err != nil {
		t.Fatal(err)
	}
	connect := func(id, shortID, pub, flow string) error {
		// JSON serialization avoids accidental interpolation in client settings.
		cfg := map[string]any{"log": map[string]any{"loglevel": "none"}, "outbounds": []any{map[string]any{
			"protocol": "vless", "settings": map[string]any{"vnext": []any{map[string]any{"address": "127.0.0.1", "port": port, "users": []any{map[string]any{"id": id, "encryption": "none", "flow": flow}}}}},
			"streamSettings": map[string]any{"network": "tcp", "security": "reality", "realitySettings": map[string]any{"serverName": "localhost", "fingerprint": "chrome", "publicKey": pub, "shortId": shortID}}}}}
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
		c, e := xcore.Dial(ctx, client, xnet.TCPDestination(xnet.ParseAddress("127.0.0.1"), xnet.Port(echo.Addr().(*net.TCPAddr).Port)))
		if e != nil {
			return e
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(3 * time.Second))
		payload := []byte("real-encrypted-vision-echo")
		if _, e = c.Write(payload); e != nil {
			return e
		}
		got := make([]byte, len(payload))
		if _, e = io.ReadFull(c, got); e != nil {
			return e
		}
		if string(got) != string(payload) {
			return fmt.Errorf("payload mismatch")
		}
		return nil
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
	t.Run("observer-off", func(t *testing.T) {
		if e := connect(uuid, short, public, "xtls-rprx-vision"); e != nil {
			t.Fatal(e)
		}
	})
	if e := proxy.DelUsers(users, tag, info); e != nil {
		t.Fatal(e)
	}
	t.Run("deleted-user", func(t *testing.T) {
		if connect(uuid, short, public, "xtls-rprx-vision") == nil {
			t.Fatal("deleted account accepted")
		}
	})
}
