package xray

// Isolated real-core integration test: all listeners and destinations are loopback,
// credentials are synthetic, and no panel API, production user or remote target is used.
import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/proxy/vless"
	"github.com/xtls/xray-core/transport/internet/reality"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/InazumaV/V2bX/api/panel"
	"github.com/InazumaV/V2bX/common/beupobserve"
	"github.com/InazumaV/V2bX/conf"
	vCore "github.com/InazumaV/V2bX/core"
	"github.com/InazumaV/V2bX/limiter"
)

func TestObservedVLESSLoopback(t *testing.T) {
	const tag = "synthetic-vless"
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
			go func() { defer c.Close(); c.SetDeadline(time.Now().Add(3 * time.Second)); io.Copy(c, c) }()
		}
	}()
	reserve, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := reserve.Addr().(*net.TCPAddr).Port
	reserve.Close()
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
	info := &panel.NodeInfo{Type: "vless", Common: &panel.CommonNode{ServerPort: port}, VAllss: &panel.VAllssNode{Network: "tcp", NetworkSettings: json.RawMessage(`{}`)}}
	xopts := conf.NewXrayOptions()
	xopts.DisableSniffing = true
	if err = proxy.AddNode(tag, info, &conf.Options{ListenIP: "127.0.0.1", SendIP: "127.0.0.1", XrayOptions: xopts}); err != nil {
		t.Fatal(err)
	}
	users := []panel.UserInfo{
		{Id: 2, Uuid: "00000000-0000-4000-8000-000000000002"},
		{Id: 3, Uuid: "00000000-0000-4000-8000-000000000003"},
		{Id: 4, Uuid: "00000000-0000-4000-8000-000000000004"},
	}
	limiter.Init()
	limiter.AddLimiter(tag, &conf.LimitConfig{}, users, map[int]int{})
	defer limiter.DeleteLimiter(tag)
	now := time.Unix(1800000000, 0)
	o, err := observer.New(observer.Config{Node: "demo-hk", IdentityRevision: "synthetic-v1", Now: func() time.Time { return now }, Bindings: map[string]map[int]string{tag: {2: fmt.Sprintf("%032d", 2), 3: fmt.Sprintf("%032d", 3)}}})
	if err != nil {
		t.Fatal(err)
	}
	observer.Set(o)
	defer observer.Set(nil)
	if n, e := proxy.AddUsers(&vCore.AddUsersParams{Tag: tag, Users: users, NodeInfo: info}); e != nil || n != 3 {
		t.Fatalf("add synthetic users: %d %v", n, e)
	}
	for _, u := range users {
		if e := vlessEcho(port, echo.Addr().(*net.TCPAddr).Port, u.Uuid); e != nil {
			t.Fatal(e)
		}
	}
	if e := vlessEcho(port, echo.Addr().(*net.TCPAddr).Port, "00000000-0000-4000-8000-000000000099"); e == nil {
		t.Fatal("invalid credential accepted")
	}
	reports, e := o.Snapshot(now.Add(time.Minute))
	if e != nil || len(reports) != 1 {
		t.Fatalf("snapshot: %v", e)
	}
	r := reports[0]
	if len(r.Subjects) != 2 || r.Quality.UnmappedRequests != 1 || r.Quality.DroppedRequests != 0 || r.Complete {
		t.Fatalf("bad observed attribution: %+v", r.Quality)
	}
	for _, s := range r.Subjects {
		if s.Metrics.ProxyRequests != 1 || s.Metrics.TCPRequests != 1 || s.Metrics.FailedConnections != nil {
			t.Fatal("bad observed metrics")
		}
	}
	wire, _ := json.Marshal(r)
	for _, u := range users {
		if strings.Contains(string(wire), u.Uuid) {
			t.Fatal("credential exported")
		}
	}
	if strings.Contains(string(wire), "127.0.0.1") {
		t.Fatal("destination exported")
	}
	// Change only the signed registry view: the actual proxy and AddUsers list
	// stay running. UID 4 was already authenticated but formerly unregistered.
	now = now.Add(time.Minute)
	if e := o.ReplaceRegistry("synthetic-v2", map[string]map[int]string{tag: {4: fmt.Sprintf("%032d", 4)}}); e != nil {
		t.Fatal(e)
	}
	for _, u := range users {
		if e := vlessEcho(port, echo.Addr().(*net.TCPAddr).Port, u.Uuid); e != nil {
			t.Fatal("registry refresh interrupted proxy", e)
		}
	}
	changed, e := o.Snapshot(now.Add(time.Minute))
	if e != nil || len(changed) != 1 || len(changed[0].Subjects) != 1 || changed[0].Subjects[0].Subject != fmt.Sprintf("%032d", 4) || changed[0].Quality.UnmappedRequests != 2 || !changed[0].Quality.PartialWindow {
		t.Fatal("real core hot mapping mismatch")
	}
	// Disabling the observer must not disable otherwise valid proxy traffic.
	observer.Set(nil)
	if e := vlessEcho(port, echo.Addr().(*net.TCPAddr).Port, users[0].Uuid); e != nil {
		t.Fatal("disabled telemetry interrupted proxy", e)
	}
	if e := proxy.DelUsers(users[:1], tag, info); e != nil {
		t.Fatal(e)
	}
	if e := vlessEcho(port, echo.Addr().(*net.TCPAddr).Port, users[0].Uuid); e == nil {
		t.Fatal("deleted credential accepted")
	}
}

func vlessEcho(proxyPort, destPort int, credential string) error {
	c, e := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", proxyPort), 2*time.Second)
	if e != nil {
		return e
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(2 * time.Second))
	id, e := hex.DecodeString(strings.ReplaceAll(credential, "-", ""))
	if e != nil {
		return e
	}
	b := append([]byte{0}, id...)
	b = append(b, 0, 1, byte(destPort>>8), byte(destPort), 1, 127, 0, 0, 1)
	b = append(b, []byte("synthetic-observer-echo")...)
	if _, e = c.Write(b); e != nil {
		return e
	}
	header := make([]byte, 2)
	if _, e = io.ReadFull(c, header); e != nil {
		return e
	}
	if header[0] != 0 {
		return fmt.Errorf("unexpected response")
	}
	if _, e = io.CopyN(io.Discard, c, int64(header[1])); e != nil {
		return e
	}
	out := make([]byte, len("synthetic-observer-echo"))
	if _, e = io.ReadFull(c, out); e != nil {
		return e
	}
	if string(out) != "synthetic-observer-echo" {
		return fmt.Errorf("echo mismatch")
	}
	return nil
}

// Build the exact public protocol profile observed in the site's node table.
// Synthetic key and loopback destination only. This validates configuration
// construction and account flow; it is not a REALITY TLS handshake test.
func TestWebsiteVLESSRealityVisionProfile(t *testing.T) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	info := &panel.NodeInfo{Type: "vless", Security: panel.Reality,
		Common: &panel.CommonNode{ServerPort: 19001},
		VAllss: &panel.VAllssNode{Network: "tcp", NetworkSettings: json.RawMessage("{}"), Flow: "xtls-rprx-vision",
			TlsSettings: panel.TlsSettings{ServerName: "localhost", Dest: "127.0.0.1", ServerPort: "19443",
				PrivateKey: base64.RawURLEncoding.EncodeToString(key.Bytes()), ShortId: "0123456789abcdef"}}}
	opts := conf.NewXrayOptions()
	in, err := buildInbound(&conf.Options{ListenIP: "127.0.0.1", SendIP: "127.0.0.1", XrayOptions: opts}, info, "site-profile")
	if err != nil {
		t.Fatal(err)
	}
	instance, err := in.ReceiverSettings.GetInstance()
	if err != nil {
		t.Fatal(err)
	}
	receiver, ok := instance.(*proxyman.ReceiverConfig)
	if !ok || receiver.StreamSettings == nil {
		t.Fatal("receiver missing")
	}
	stream := receiver.StreamSettings
	if stream.ProtocolName != "tcp" || len(stream.SecuritySettings) != 1 {
		t.Fatal("TCP/security settings changed")
	}
	security, err := stream.SecuritySettings[0].GetInstance()
	if err != nil {
		t.Fatal(err)
	}
	rc, ok := security.(*reality.Config)
	if !ok || len(rc.PrivateKey) != 32 || len(rc.ShortIds) != 1 || len(rc.ServerNames) != 1 || rc.ServerNames[0] != "localhost" {
		t.Fatal("REALITY settings changed")
	}
	users := buildVlessUsers("site-profile", []panel.UserInfo{{Id: 123, Uuid: "00000000-0000-4000-8000-000000000123"}}, info.VAllss.Flow)
	if len(users) != 1 {
		t.Fatal("user missing")
	}
	account, err := users[0].ToMemoryUser()
	if err != nil {
		t.Fatal(err)
	}
	va, ok := account.Account.(*vless.MemoryAccount)
	if !ok || va.Flow != "xtls-rprx-vision" {
		t.Fatal("Vision flow was lost")
	}
}
