package xray

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
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
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/mux"
	xnet "github.com/xtls/xray-core/common/net"
)

func TestTransferActiveMuxTailAndUDP(t *testing.T) {
	for _, network := range []string{"tcp", "udp"} {
		t.Run(network, func(t *testing.T) {
			const credential = "00000000-0000-4000-8000-000000000002"
			var port int
			var closeEcho func()
			if network == "tcp" {
				l, e := net.Listen("tcp4", "127.0.0.1:0")
				if e != nil {
					t.Fatal(e)
				}
				port = l.Addr().(*net.TCPAddr).Port
				closeEcho = func() { l.Close() }
				go func() {
					for {
						c, e := l.Accept()
						if e != nil {
							return
						}
						go func() { defer c.Close(); c.SetDeadline(time.Now().Add(5 * time.Second)); io.Copy(c, c) }()
					}
				}()
			} else {
				l, e := net.ListenPacket("udp4", "127.0.0.1:0")
				if e != nil {
					t.Fatal(e)
				}
				port = l.LocalAddr().(*net.UDPAddr).Port
				closeEcho = func() { l.Close() }
				go func() {
					for {
						b := make([]byte, 2048)
						n, a, e := l.ReadFrom(b)
						if e != nil {
							return
						}
						l.WriteTo(b[:n], a)
					}
				}()
			}
			defer closeEcho()
			reserve, e := net.Listen("tcp4", "127.0.0.1:0")
			if e != nil {
				t.Fatal(e)
			}
			proxy := reserve.Addr().(*net.TCPAddr).Port
			reserve.Close()
			xc := conf.NewXrayConfig()
			xc.AssetPath = t.TempDir()
			xc.LogConfig.Level = "none"
			xc.LogConfig.AccessPath = "none"
			core, e := New(&conf.CoreConfig{Type: "xray", XrayConfig: xc})
			if e != nil {
				t.Fatal(e)
			}
			if e = core.Start(); e != nil {
				t.Fatal(e)
			}
			defer core.Close()
			tag := "active-mux-" + network
			info := &panel.NodeInfo{Type: "vless", Common: &panel.CommonNode{ServerPort: proxy}, VAllss: &panel.VAllssNode{Network: "tcp", NetworkSettings: json.RawMessage(`{}`)}}
			if e = core.AddNode(tag, info, &conf.Options{ListenIP: "127.0.0.1", SendIP: "127.0.0.1", XrayOptions: conf.NewXrayOptions(), ReportMinTraffic: 1024}); e != nil {
				t.Fatal(e)
			}
			adapter, e := core.(*Xray).EnableTransferAccounting(tag, strings.Repeat("a", 32), "vless")
			if e != nil {
				t.Fatal(e)
			}
			users := []panel.UserInfo{{Id: 2, Uuid: credential}}
			limiter.Init()
			limiter.AddLimiter(tag, &conf.LimitConfig{}, users, map[int]int{})
			defer limiter.DeleteLimiter(tag)
			if _, e = core.AddUsers(&vCore.AddUsersParams{Tag: tag, Users: users, NodeInfo: info}); e != nil {
				t.Fatal(e)
			}
			c, e := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", proxy), time.Second)
			if e != nil {
				t.Fatal(e)
			}
			defer c.Close()
			c.SetDeadline(time.Now().Add(4 * time.Second))
			id, _ := hex.DecodeString(strings.ReplaceAll(credential, "-", ""))
			wire := append([]byte{0}, id...)
			wire = append(wire, 0, 3)
			if _, e = c.Write(wire); e != nil {
				t.Fatal(e)
			}
			reader := &buf.BufferedReader{Reader: buf.NewReader(c)}
			payload := []byte("synthetic-mux-tail-traffic")
			for sid := uint16(1); sid <= 2; sid++ {
				dest := xnet.TCPDestination(xnet.LocalHostIP, xnet.Port(port))
				if network == "udp" {
					dest = xnet.UDPDestination(xnet.LocalHostIP, xnet.Port(port))
				}
				frame := buf.New()
				meta := mux.FrameMetadata{Target: dest, SessionID: sid, SessionStatus: mux.SessionStatusNew, Option: mux.OptionData}
				if network == "udp" {
					frame.UDP = &dest
					meta.GlobalID = [8]byte{9, 8, 7, 6, 5, 4, 3, byte(sid)}
				}
				if e = meta.WriteTo(frame); e != nil {
					t.Fatal(e)
				}
				var size [2]byte
				binary.BigEndian.PutUint16(size[:], uint16(len(payload)))
				frame.Write(size[:])
				frame.Write(payload)
				if _, e = c.Write(frame.Bytes()); e != nil {
					t.Fatal(e)
				}
				frame.Release()
				if sid == 1 {
					var header [2]byte
					if _, e = io.ReadFull(reader, header[:]); e != nil {
						t.Fatal(e)
					}
					if header[0] != 0 || header[1] != 0 {
						t.Fatal("unexpected VLESS response")
					}
				}
				var response mux.FrameMetadata
				if e = response.Unmarshal(reader, false); e != nil {
					t.Fatal(e)
				}
				if response.SessionID != sid || !response.Option.Has(mux.OptionData) {
					t.Fatalf("unexpected Mux response %+v", response)
				}
				if _, e = io.ReadFull(reader, size[:]); e != nil {
					t.Fatal(e)
				}
				back := make([]byte, binary.BigEndian.Uint16(size[:]))
				if _, e = io.ReadFull(reader, back); e != nil || string(back) != string(payload) {
					t.Fatal("Mux echo mismatch", e)
				}
				if network == "udp" {
					mux.XUDPManager.Lock()
					_, cached := mux.XUDPManager.Map[meta.GlobalID]
					mux.XUDPManager.Unlock()
					if cached {
						t.Fatal("reliable UDP escaped tunnel ownership")
					}
				}
			}
			r := &transferTestReceiver{}
			box, e := beuptransfer.Open(&transferTestStore{}, r, "vless_42", strings.Repeat("a", 32))
			if e != nil {
				t.Fatal(e)
			}
			req := beuptransfer.DrainRequest{ID: strings.Repeat("b", 32), Identity: beuptransfer.Identity{UID: 2, Credential: beupguard.CredentialDigest(credential)}}
			until := time.Now().Add(3 * time.Second)
			for {
				proof, e := box.Drain(context.Background(), req, adapter)
				if e == nil {
					if proof.Final.Upload != int64(2*len(payload)) || proof.Final.Download != int64(2*len(payload)) {
						t.Fatalf("mux tail mismatch %+v", proof.Final)
					}
					break
				}
				if !errors.Is(e, beuptransfer.ErrPending) || time.Now().After(until) {
					t.Fatal("active mux drain failed", e)
				}
				time.Sleep(5 * time.Millisecond)
			}
			if _, e = c.Read(make([]byte, 1)); e == nil {
				t.Fatal("Mux transport remained open")
			}
			status, _ := adapter.Inspect(context.Background(), req.Identity)
			if status.Outstanding != 0 || !status.TrackingReady || !status.RejectNew {
				t.Fatalf("incomplete Mux drain %+v", status)
			}
			beforeU, beforeD := r.up, r.down
			time.Sleep(20 * time.Millisecond)
			if _, e = box.Drain(context.Background(), req, adapter); e != nil || r.up != beforeU || r.down != beforeD {
				t.Fatal("late or double tail accounting", e)
			}
		})
	}
}
