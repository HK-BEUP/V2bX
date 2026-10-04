package xray

import (
	"context"
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
)

type transferTestStore struct{ data []byte }

func (s *transferTestStore) Load() ([]byte, error) { return append([]byte{}, s.data...), nil }
func (s *transferTestStore) Save(b []byte) error   { s.data = append([]byte{}, b...); return nil }

type transferTestReceiver struct {
	up, down int64
	seen     map[uint64]string
}

func (r *transferTestReceiver) Commit(_ context.Context, b beuptransfer.Batch) (beuptransfer.Ack, error) {
	if r.seen == nil {
		r.seen = map[uint64]string{}
	}
	if old, ok := r.seen[b.Sequence]; ok {
		if old != b.Digest {
			return beuptransfer.Ack{}, errors.New("batch conflict")
		}
	} else {
		for _, v := range b.Entries {
			r.up += v.Upload
			r.down += v.Download
		}
		r.seen[b.Sequence] = b.Digest
	}
	return beuptransfer.Ack{Scope: b.Scope, Epoch: b.Epoch, Sequence: b.Sequence, Digest: b.Digest}, nil
}

// Real VLESS TCP, real Xray dispatcher and real bidirectional socket closure.
// Every endpoint is loopback and every credential is synthetic. No panel API.
func TestTransferVLESSFinalAccountingLoopback(t *testing.T) {
	const tag = "transfer-vless-loopback"
	const credential = "00000000-0000-4000-8000-000000000002"
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
			go func() { defer c.Close(); c.SetDeadline(time.Now().Add(5 * time.Second)); _, _ = io.Copy(c, c) }()
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
	opts := conf.NewXrayOptions()
	opts.DisableSniffing = false
	if err = core.AddNode(tag, info, &conf.Options{ListenIP: "127.0.0.1", SendIP: "127.0.0.1", ReportMinTraffic: 1024, XrayOptions: opts}); err != nil {
		t.Fatal(err)
	}
	epoch := strings.Repeat("1", 32)
	adapter, err := x.EnableTransferAccounting(tag, epoch, "vless")
	if err != nil {
		t.Fatal(err)
	}
	users := []panel.UserInfo{{Id: 2, Uuid: credential}, {Id: 3, Uuid: "00000000-0000-4000-8000-000000000003"}}
	limiter.Init()
	limiter.AddLimiter(tag, &conf.LimitConfig{}, users, map[int]int{})
	defer limiter.DeleteLimiter(tag)
	if _, err = core.AddUsers(&vCore.AddUsersParams{Tag: tag, Users: users, NodeInfo: info}); err != nil {
		t.Fatal(err)
	}
	if _, err = x.EnableTransferAccounting(tag, epoch, "vless"); err == nil {
		t.Fatal("live re-enable accepted")
	}
	dest := echo.Addr().(*net.TCPAddr).Port
	c, err := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", port), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(4 * time.Second))
	id, _ := hex.DecodeString(strings.ReplaceAll(credential, "-", ""))
	wire := append([]byte{0}, id...)
	wire = append(wire, 0, 1, byte(dest>>8), byte(dest), 1, 127, 0, 0, 1)
	payload := []byte("small-tail-below-threshold")
	wire = append(wire, payload...)
	if _, err = c.Write(wire); err != nil {
		t.Fatal(err)
	}
	header := make([]byte, 2)
	if _, err = io.ReadFull(c, header); err != nil {
		t.Fatal(err)
	}
	if _, err = io.CopyN(io.Discard, c, int64(header[1])); err != nil {
		t.Fatal(err)
	}
	back := make([]byte, len(payload))
	if _, err = io.ReadFull(c, back); err != nil || string(back) != string(payload) {
		t.Fatal("echo failed", err)
	}
	if _, err = core.GetUserTrafficSlice(tag, true); err == nil {
		t.Fatal("legacy path reset cumulative counters")
	}
	r := &transferTestReceiver{}
	box, err := beuptransfer.Open(&transferTestStore{}, r, "vless_42", epoch)
	if err != nil {
		t.Fatal(err)
	}
	request := beuptransfer.DrainRequest{ID: strings.Repeat("2", 32), Identity: beuptransfer.Identity{UID: 2, Credential: beupguard.CredentialDigest(credential)}}
	var proof *beuptransfer.DrainProof
	until := time.Now().Add(3 * time.Second)
	for {
		proof, err = box.Drain(context.Background(), request, adapter)
		if err == nil {
			break
		}
		if !errors.Is(err, beuptransfer.ErrPending) || time.Now().After(until) {
			t.Fatal("drain failed", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if proof.Final.Upload != int64(len(payload)) || proof.Final.Download != int64(len(payload)) {
		t.Fatalf("tail accounting mismatch: %+v", proof.Final)
	}
	if r.up != int64(len(payload)) || r.down != int64(len(payload)) {
		t.Fatal("final usage not committed once")
	}
	if _, err = c.Read(make([]byte, 1)); err == nil {
		t.Fatal("old connection still readable")
	}
	if err = vlessEcho(port, dest, credential); err == nil {
		t.Fatal("fenced credential reconnected")
	}
	if err = core.DelUsers(users[:1], tag, info); err != nil {
		t.Fatal(err)
	}
	rows, err := adapter.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, v := range rows {
		if v.UID == 2 {
			found = v.Upload == int64(len(payload)) && v.Download == int64(len(payload))
		}
	}
	if !found {
		t.Fatal("DelUsers deleted final traffic")
	}
	if err = vlessEcho(port, dest, users[1].Uuid); err != nil {
		t.Fatal("migration blocked unrelated credential", err)
	}
	if _, err = box.Drain(context.Background(), request, adapter); err != nil {
		t.Fatal("final proof replay failed", err)
	}
}
