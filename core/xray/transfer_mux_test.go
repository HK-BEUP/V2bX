package xray

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/InazumaV/V2bX/api/panel"
	"github.com/InazumaV/V2bX/common/beupguard"
	"github.com/InazumaV/V2bX/common/beuptransfer"
	"github.com/InazumaV/V2bX/conf"
	vCore "github.com/InazumaV/V2bX/core"
	"github.com/InazumaV/V2bX/limiter"
)

// A real authenticated Mux tunnel with no substreams must not be mistaken for
// zero live connections; a drain waits for its tracked worker and monitor.
func TestTransferIdleMuxDrains(t *testing.T) {
	const tag = "transfer-idle-mux"
	const credential = "00000000-0000-4000-8000-000000000002"
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	xc := conf.NewXrayConfig()
	xc.AssetPath = t.TempDir()
	xc.LogConfig.Level = "none"
	xc.LogConfig.AccessPath = "none"
	core, err := New(&conf.CoreConfig{Type: "xray", XrayConfig: xc})
	if err != nil {
		t.Fatal(err)
	}
	if err = core.Start(); err != nil {
		t.Fatal(err)
	}
	defer core.Close()
	x := core.(*Xray)
	info := &panel.NodeInfo{Type: "vless", Common: &panel.CommonNode{ServerPort: port}, VAllss: &panel.VAllssNode{Network: "tcp", NetworkSettings: json.RawMessage(`{}`)}}
	if err = core.AddNode(tag, info, &conf.Options{ListenIP: "127.0.0.1", SendIP: "127.0.0.1", XrayOptions: conf.NewXrayOptions()}); err != nil {
		t.Fatal(err)
	}
	epoch := strings.Repeat("a", 32)
	adapter, err := x.EnableTransferAccounting(tag, epoch, "vless")
	if err != nil {
		t.Fatal(err)
	}
	users := []panel.UserInfo{{Id: 2, Uuid: credential}}
	limiter.Init()
	limiter.AddLimiter(tag, &conf.LimitConfig{}, users, map[int]int{})
	defer limiter.DeleteLimiter(tag)
	if _, err = core.AddUsers(&vCore.AddUsersParams{Tag: tag, Users: users, NodeInfo: info}); err != nil {
		t.Fatal(err)
	}
	c, err := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", port), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	uuid, _ := hex.DecodeString(strings.ReplaceAll(credential, "-", ""))
	wire := append([]byte{0}, uuid...)
	wire = append(wire, 0, 3)
	if _, err = c.Write(wire); err != nil {
		t.Fatal(err)
	}
	id := beuptransfer.Identity{UID: 2, Credential: beupguard.CredentialDigest(credential)}
	until := time.Now().Add(2 * time.Second)
	for {
		status, _ := adapter.Inspect(context.Background(), id)
		if status.Outstanding > 0 && status.TrackingReady {
			break
		}
		if time.Now().After(until) {
			t.Fatalf("idle Mux authentication not tracked: %+v", status)
		}
		time.Sleep(5 * time.Millisecond)
	}
	box, err := beuptransfer.Open(&transferTestStore{}, &transferTestReceiver{}, "vless-100", epoch)
	if err != nil {
		t.Fatal(err)
	}
	until = time.Now().Add(3 * time.Second)
	for {
		proof, e := box.Drain(context.Background(), beuptransfer.DrainRequest{ID: strings.Repeat("f", 32), Identity: id}, adapter)
		if e == nil {
			if proof.Final.Upload != 0 || proof.Final.Download != 0 {
				t.Fatal("idle tunnel manufactured usage")
			}
			break
		}
		if time.Now().After(until) {
			t.Fatal("idle mux did not drain", e)
		}
		time.Sleep(5 * time.Millisecond)
	}
	c.SetReadDeadline(time.Now().Add(time.Second))
	_, err = io.ReadAll(c)
	if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
		t.Fatal("authenticated Mux connection remained open")
	}
}
