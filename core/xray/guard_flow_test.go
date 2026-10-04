package xray

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/InazumaV/V2bX/api/panel"
	"github.com/InazumaV/V2bX/common/beupguard"
	"github.com/InazumaV/V2bX/conf"
	vCore "github.com/InazumaV/V2bX/core"
	"github.com/InazumaV/V2bX/limiter"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Synthetic users and loopback-only endpoints; no panel, external scan or DB.
func TestGuardVLESSRejectDisconnectRestoreAndOtherAccount(t *testing.T) {
	g := beupguard.New(1000, nil)
	tags := []string{"guard-synthetic-a", "guard-synthetic-b", "guard-synthetic-c", "guard-synthetic-d"}
	if err := g.RequireTags(tags); err != nil {
		t.Fatal(err)
	}
	dir, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	if e = os.Chmod(dir, 0700); e != nil {
		t.Fatal(e)
	}
	store, e := beupguard.OpenFileStore(dir, "loopback-test", true)
	if e != nil {
		t.Fatal(e)
	}
	defer store.Close()
	pub, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	started := time.Now()
	controller, e := beupguard.OpenController(g, "loopback-test", pub, store, nil, func() (beupguard.BootStamp, error) {
		return beupguard.BootStamp{ID: "synthetic-loopback-boot", Nanos: time.Since(started).Nanoseconds()}, nil
	})
	if e != nil {
		t.Fatal(e)
	}
	sign := func(seq uint64, op string, l beupguard.Lease) beupguard.Envelope {
		now := time.Now().Unix()
		b, _ := json.Marshal(beupguard.Command{Version: 1, Node: "loopback-test", Sequence: seq, IssuedAt: now, NotAfter: now + 60, Operation: op, Lease: l})
		return beupguard.Envelope{Payload: base64.StdEncoding.EncodeToString(b), Signature: hex.EncodeToString(ed25519.Sign(key, append([]byte(beupguard.CommandDomain), b...)))}
	}
	beupguard.Set(g)
	defer beupguard.Set(nil)
	echo, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer echo.Close()
	go func() {
		for {
			c, e := echo.Accept()
			if e != nil {
				return
			}
			go func() { defer c.Close(); c.SetDeadline(time.Now().Add(15 * time.Second)); io.Copy(c, c) }()
		}
	}()
	xc := conf.NewXrayConfig()
	xc.AssetPath = t.TempDir()
	xc.LogConfig.Level = "none"
	xc.LogConfig.AccessPath = "none"
	p, e := New(&conf.CoreConfig{Type: "xray", XrayConfig: xc})
	if e != nil {
		t.Fatal(e)
	}
	if e = p.Start(); e != nil {
		t.Fatal(e)
	}
	defer p.Close()
	users := []panel.UserInfo{{Id: 2, Uuid: "00000000-0000-4000-8000-000000000002", SubscriptionGrant: "00000000000000000000000000000002"}, {Id: 3, Uuid: "00000000-0000-4000-8000-000000000003"}, {Id: 2, Uuid: "00000000-0000-4000-8000-000000000004"}, {Id: 2, Uuid: "00000000-0000-4000-8000-000000000005", SubscriptionGrant: "00000000000000000000000000000005"}}
	limiter.Init()
	ports := []int{}
	for _, tag := range tags {
		l, e := net.Listen("tcp4", "127.0.0.1:0")
		if e != nil {
			t.Fatal(e)
		}
		port := l.Addr().(*net.TCPAddr).Port
		l.Close()
		ports = append(ports, port)
		info := &panel.NodeInfo{Type: "vless", Common: &panel.CommonNode{ServerPort: port}, VAllss: &panel.VAllssNode{Network: "tcp", NetworkSettings: json.RawMessage(`{}`)}}
		opts := conf.NewXrayOptions()
		opts.DisableSniffing = true
		if e = p.AddNode(tag, info, &conf.Options{ListenIP: "127.0.0.1", SendIP: "127.0.0.1", XrayOptions: opts}); e != nil {
			t.Fatal(e)
		}
		limiter.AddLimiter(tag, &conf.LimitConfig{}, users, map[int]int{})
		defer limiter.DeleteLimiter(tag)
		if _, e = p.AddUsers(&vCore.AddUsersParams{Tag: tag, Users: users, NodeInfo: info}); e != nil {
			t.Fatal(e)
		}
	}
	connect := func(port, uid int) (net.Conn, error) {
		c, e := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", port), time.Second)
		if e != nil {
			return nil, e
		}
		c.SetDeadline(time.Now().Add(2 * time.Second))
		id, _ := hex.DecodeString(strings.ReplaceAll(users[uid-2].Uuid, "-", ""))
		dest := echo.Addr().(*net.TCPAddr).Port
		b := append([]byte{0}, id...)
		b = append(b, 0, 1, byte(dest>>8), byte(dest), 1, 127, 0, 0, 1)
		b = append(b, 42)
		if _, e = c.Write(b); e != nil {
			c.Close()
			return nil, e
		}
		buf := make([]byte, 3)
		if _, e = io.ReadFull(c, buf); e != nil {
			c.Close()
			return nil, e
		}
		if buf[0] != 0 || buf[1] != 0 || buf[2] != 42 {
			c.Close()
			return nil, fmt.Errorf("bad echo")
		}
		return c, nil
	}
	old := []net.Conn{}
	for _, port := range ports {
		c, e := connect(port, 2)
		if e != nil {
			t.Fatal(e)
		}
		defer c.Close()
		old = append(old, c)
	}
	other, e := connect(ports[0], 3)
	if e != nil {
		t.Fatal(e)
	}
	defer other.Close()
	now := time.Now().Unix()
	lease := beupguard.Lease{ID: fmt.Sprintf("%032x", 1), Identity: beupguard.Identity{UID: 2, Credential: beupguard.CredentialDigest(users[0].Uuid)}, StartedAt: now, ExpiresAt: now + 600}
	command := sign(1, "block", lease)
	ack, e := controller.Execute(command)
	if e != nil || !ack.RejectNew || !ack.TrackingReady || !ack.IdentityBound {
		t.Fatalf("apply %+v %v", ack, e)
	}
	for _, c := range old {
		c.SetReadDeadline(time.Now().Add(time.Second))
		if _, e := c.Read(make([]byte, 1)); e == nil {
			t.Fatal("old session survived")
		} else if ne, ok := e.(net.Error); ok && ne.Timeout() {
			t.Fatal("old session merely stalled")
		}
	}
	deadline := time.Now().Add(time.Second)
	for g.Outstanding(lease.Identity) > 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if g.Outstanding(lease.Identity) != 0 {
		t.Fatal("handler did not finish")
	}
	ack, e = controller.Execute(command)
	if e != nil || !ack.ExistingClosed || ack.Outstanding != 0 {
		t.Fatal("real signed acknowledgement failed", ack, e)
	}
	for _, port := range ports {
		if c, e := connect(port, 2); e == nil {
			c.Close()
			t.Fatal("new session accepted while blocked")
		}
	}
	if _, e = other.Write([]byte{43}); e != nil {
		t.Fatal(e)
	}
	buf := []byte{0}
	if _, e = io.ReadFull(other, buf); e != nil || buf[0] != 43 {
		t.Fatal("other existing session affected", e)
	}
	if c, e := connect(ports[1], 3); e != nil {
		t.Fatal("other new session affected", e)
	} else {
		c.Close()
	}
	for _, port := range ports {
		for _, alias := range []int{4, 5} {
			if conn, err := connect(port, alias); err != nil {
				t.Fatal("same owner legacy or sibling credential affected", err)
			} else {
				conn.Close()
			}
		}
	}
	if os.Getenv("BEUP_SYNTHETIC_REAL_TTL") == "1" {
		// Opt-in native acceptance: no clock injection, no panel/agent or network
		// outside the loopback namespace. Exercise the actual 600-second lease.
		t.Log("real 600-second local expiry started; no controller traffic required")
		time.Sleep(time.Until(time.Unix(lease.ExpiresAt, 0)) + time.Second)
		for _, port := range ports {
			if c, e := connect(port, 2); e != nil {
				t.Fatal("local expiry did not restore inbound", e)
			} else {
				c.Close()
			}
		}
		ack, e = controller.Execute(command)
		if e != nil || ack.RejectNew || ack.State != "ended" {
			t.Fatal("expired replay must not restart lease", ack, e)
		}
		t.Log("real local expiry restored all four synthetic inbounds")
		return
	}
	if _, e = controller.Execute(sign(2, "release", lease)); e != nil {
		t.Fatal(e)
	}
	for _, port := range ports {
		if c, e := connect(port, 2); e != nil {
			t.Fatal("release did not restore", e)
		} else {
			c.Close()
		}
	}
}
