//go:build beupqa

package node

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/InazumaV/V2bX/api/panel"
	"github.com/InazumaV/V2bX/common/beupguard"
	"github.com/InazumaV/V2bX/common/beuptransfer"
	"github.com/InazumaV/V2bX/conf"
	vCore "github.com/InazumaV/V2bX/core"
	xcore "github.com/InazumaV/V2bX/core/xray"
	"github.com/InazumaV/V2bX/limiter"
)

const qaUUID = "00000000-0000-4000-8000-000000000002"
const qaOther = "00000000-0000-4000-8000-000000000003"

type controllerPanel struct {
	mu                    sync.Mutex
	key                   []byte
	epoch                 string
	port                  int
	users                 []panel.UserInfo
	batches               map[uint64]string
	totals                map[int64][2]int64
	commands              []beuptransfer.Command
	drains                int
	missingEpoch, loseAck bool
	legacyCalls           int
}

func qaMAC(direction, purpose, scope, at, nonce string, body, key []byte) string {
	h := hmac.New(sha256.New, key)
	hash := sha256.Sum256(body)
	fmt.Fprintf(h, "beup-node-%s-v1\n%s\n%s\n%s\n%s\n%x\n", direction, purpose, scope, at, nonce, hash)
	return hex.EncodeToString(h.Sum(nil))
}
func (p *controllerPanel) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	defer p.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	switch r.URL.Path {
	case "/api/v1/server/UniProxy/config":
		json.NewEncoder(w).Encode(map[string]any{"server_port": p.port, "tls": 0, "network": "tcp", "network_settings": map[string]any{}, "routes": []any{}, "base_config": map[string]any{"push_interval": 1, "pull_interval": 1}})
		return
	case "/api/v1/server/UniProxy/user":
		if r.Header.Get("X-Beup-Traffic-Epoch") != p.epoch {
			http.Error(w, "epoch missing", 409)
			return
		}
		if !p.missingEpoch {
			w.Header().Set("X-Beup-Traffic-Epoch", p.epoch)
		}
		json.NewEncoder(w).Encode(map[string]any{"users": p.users})
		return
	case "/api/v1/server/UniProxy/alivelist":
		io.WriteString(w, `{"alive":{}}`)
		return
	case "/api/v1/server/UniProxy/alive":
		io.WriteString(w, `{"data":true}`)
		return
	case "/api/v1/server/UniProxy/push":
		p.legacyCalls++
		http.Error(w, "legacy refused", 409)
		return
	}
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) != 6 || parts[3] != "accounts-node-settlement" || parts[4] != "vless-42" {
		http.NotFound(w, r)
		return
	}
	purpose := parts[5]
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "body", 400)
		return
	}
	at, nonce := r.Header.Get("X-Beup-Time"), r.Header.Get("X-Beup-Nonce")
	if !hmac.Equal([]byte(r.Header.Get("X-Beup-Signature")), []byte(qaMAC("request", purpose, "vless-42", at, nonce, body, p.key))) {
		http.Error(w, "signature", 401)
		return
	}
	var response any
	switch purpose {
	case "traffic":
		var b beuptransfer.Batch
		if json.Unmarshal(body, &b) != nil || b.Digest != b.Hash() || b.Scope != "vless-42" || b.Epoch != p.epoch {
			http.Error(w, "batch", 400)
			return
		}
		if prior, ok := p.batches[b.Sequence]; ok {
			if prior != b.Digest {
				http.Error(w, "conflict", 409)
				return
			}
		} else {
			for _, e := range b.Entries {
				v := p.totals[e.UID]
				v[0] += e.Upload
				v[1] += e.Download
				p.totals[e.UID] = v
			}
			p.batches[b.Sequence] = b.Digest
		}
		if p.loseAck {
			p.loseAck = false
			http.Error(w, "synthetic lost reply", 503)
			return
		}
		response = beuptransfer.Ack{Scope: b.Scope, Epoch: b.Epoch, Sequence: b.Sequence, Digest: b.Digest}
	case "control":
		response = map[string]any{"scope": "vless-42", "epoch": p.epoch, "commands": p.commands}
	case "drain":
		var v struct {
			Challenge string                  `json:"challenge"`
			Proof     beuptransfer.DrainProof `json:"proof"`
		}
		if json.Unmarshal(body, &v) != nil {
			http.Error(w, "drain", 400)
			return
		}
		p.drains++
		response = beuptransfer.DrainAck{TransferID: v.Proof.Request.ID, Scope: v.Proof.Scope, Epoch: v.Proof.Epoch, Challenge: v.Challenge, Receipt: v.Proof.Receipt}
	default:
		http.Error(w, "unexpected", 400)
		return
	}
	b, _ := json.Marshal(response)
	now := strconv.FormatInt(time.Now().Unix(), 10)
	w.Header().Set("X-Beup-Time", now)
	w.Header().Set("X-Beup-Nonce", nonce)
	w.Header().Set("X-Beup-Signature", qaMAC("response", purpose, "vless-42", now, nonce, b, p.key))
	w.Write(b)
}
func qaPort(t *testing.T) int {
	t.Helper()
	l, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	p := l.Addr().(*net.TCPAddr).Port
	l.Close()
	return p
}
func qaEcho(t *testing.T) (int, func()) {
	t.Helper()
	l, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	go func() {
		for {
			c, e := l.Accept()
			if e != nil {
				return
			}
			go func() { defer c.Close(); c.SetDeadline(time.Now().Add(10 * time.Second)); io.Copy(c, c) }()
		}
	}()
	return l.Addr().(*net.TCPAddr).Port, func() { l.Close() }
}
func qaFlow(port, dest int, id string) (net.Conn, error) {
	c, e := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", port), time.Second)
	if e != nil {
		return nil, e
	}
	c.SetDeadline(time.Now().Add(3 * time.Second))
	raw, _ := hex.DecodeString(strings.ReplaceAll(id, "-", ""))
	b := append([]byte{0}, raw...)
	b = append(b, 0, 1, byte(dest>>8), byte(dest), 1, 127, 0, 0, 1)
	b = append(b, []byte("synthetic-tail-accounting")...)
	if _, e = c.Write(b); e == nil {
		v := make([]byte, 2+len("synthetic-tail-accounting"))
		_, e = io.ReadFull(c, v)
		if e == nil && string(v[2:]) != "synthetic-tail-accounting" {
			e = fmt.Errorf("bad echo")
		}
	}
	if e != nil {
		c.Close()
		return nil, e
	}
	return c, nil
}

func TestTransferControllerLifecycleLoopback(t *testing.T) {
	limiter.Init()
	p := &controllerPanel{key: []byte(strings.Repeat("k", 32)), epoch: strings.Repeat("a", 32), port: qaPort(t), users: []panel.UserInfo{{Id: 2, Uuid: qaUUID}, {Id: 3, Uuid: qaOther}}, batches: map[uint64]string{}, totals: map[int64][2]int64{}, commands: []beuptransfer.Command{}}
	srv := httptest.NewTLSServer(p)
	defer srv.Close()
	oldTransport := http.DefaultTransport
	tr := oldTransport.(*http.Transport).Clone()
	roots := x509.NewCertPool()
	roots.AddCert(srv.Certificate())
	tr.TLSClientConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
	http.DefaultTransport = tr
	defer func() { http.DefaultTransport = oldTransport; tr.CloseIdleConnections() }()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	os.Chmod(dir, 0700)
	if err = os.WriteFile(filepath.Join(dir, "accounting.key"), p.key, 0600); err != nil {
		t.Fatal(err)
	}
	xc := conf.NewXrayConfig()
	xc.AssetPath = t.TempDir()
	xc.LogConfig.Level = "none"
	xc.LogConfig.AccessPath = "none"
	core, err := xcore.New(&conf.CoreConfig{Type: "xray", XrayConfig: xc})
	if err != nil {
		t.Fatal(err)
	}
	if err = core.Start(); err != nil {
		t.Fatal(err)
	}
	defer core.Close()
	makeController := func() *Controller {
		api, e := panel.New(&conf.ApiConfig{APIHost: srv.URL, NodeType: "vless", NodeID: 42, Timeout: 2})
		if e != nil {
			t.Fatal(e)
		}
		if e = api.TrustLoopbackQA(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}))); e != nil {
			t.Fatal(e)
		}
		return NewController(core, api, &conf.Options{Name: "controller-synthetic", ReportMinTraffic: 1024, Core: "xray", ListenIP: "127.0.0.1", SendIP: "127.0.0.1", XrayOptions: conf.NewXrayOptions(), CertConfig: conf.NewCertConfig(), TransferAccounting: &conf.TransferAccountingConfig{Epoch: p.epoch, Directory: dir}})
	}
	c := makeController()
	if err = c.Start(); err != nil {
		t.Fatal(err)
	}
	stop := func(c *Controller) {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if e := c.transfer.worker.Close(ctx); e != nil {
			t.Fatal(e)
		}
	}
	stop(c)
	if c.userReportPeriodic != nil || c.nodeInfoMonitorPeriodic != nil {
		t.Fatal("legacy task started")
	}
	if err = c.reportUserTrafficTask(); err == nil {
		t.Fatal("legacy reset path accessible")
	}
	dest, closeEcho := qaEcho(t)
	defer closeEcho()
	flow, err := qaFlow(p.port, dest, qaUUID)
	if err != nil {
		t.Fatal(err)
	}
	defer flow.Close()
	// Remote commits but response is lost. Retry must resend exact pending data.
	p.mu.Lock()
	p.loseAck = true
	p.mu.Unlock()
	if err = c.transfer.runtime.Step(context.Background()); err == nil {
		t.Fatal("lost reply treated as committed")
	}
	if err = c.transfer.runtime.Step(context.Background()); err != nil {
		t.Fatal(err)
	}
	p.mu.Lock()
	v := p.totals[2]
	p.mu.Unlock()
	if v != [2]int64{25, 25} {
		t.Fatalf("tail duplicated or missing: %v", v)
	}
	// Authoritative empty list actually removes credentials, while counters survive.
	if err = c.applyTransferUsers([]panel.UserInfo{}); err != nil {
		t.Fatal(err)
	}
	if len(c.userList) != 0 {
		t.Fatal("empty list ignored")
	}
	if n, e := qaFlow(p.port, dest, qaOther); e == nil {
		n.Close()
		t.Fatal("removed user reconnected")
	}
	flow.Close()
	if err = c.Close(); err != nil {
		t.Fatal(err)
	}
	if err = c.Close(); err != nil {
		t.Fatal("close not idempotent", err)
	}
	var journal struct {
		Session struct {
			Sealed bool `json:"sealed"`
		} `json:"counter_session"`
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "journal.json"))
	if json.Unmarshal(raw, &journal) != nil || !journal.Session.Sealed {
		t.Fatal("shutdown was not durably sealed")
	}
	// Start another actual controller over the same logical accounting generation.
	next := makeController()
	if err = next.Start(); err != nil {
		t.Fatal("clean restart rejected", err)
	}
	stop(next)
	flow, err = qaFlow(p.port, dest, qaUUID)
	if err != nil {
		t.Fatal(err)
	}
	defer flow.Close()
	// Real signed drain command closes the already connected VLESS stream.
	p.mu.Lock()
	p.commands = []beuptransfer.Command{{Kind: "drain", Request: beuptransfer.DrainRequest{ID: strings.Repeat("b", 32), Identity: beuptransfer.Identity{UID: 2, Credential: beupguard.CredentialDigest(qaUUID)}}, Scope: "vless-42", Epoch: p.epoch, Challenge: strings.Repeat("c", 32)}}
	p.mu.Unlock()
	deadline := time.Now().Add(3 * time.Second)
	for {
		err = next.transfer.runtime.Step(context.Background())
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal(err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, err = flow.Read(make([]byte, 1)); err == nil {
		t.Fatal("old socket survived drain")
	}
	if n, e := qaFlow(p.port, dest, qaUUID); e == nil {
		n.Close()
		t.Fatal("old credential reconnected")
	}
	other, err := qaFlow(p.port, dest, qaOther)
	if err != nil {
		t.Fatal("other user interrupted", err)
	}
	other.Close()
	if err = next.Close(); err != nil {
		t.Fatal(err)
	}
	p.mu.Lock()
	v = p.totals[2]
	legacy, drains := p.legacyCalls, p.drains
	p.mu.Unlock()
	if v != [2]int64{50, 50} || legacy != 0 || drains < 1 {
		t.Fatalf("accounting/restart/drain mismatch %v legacy=%d drains=%d", v, legacy, drains)
	}

	// A stale panel may still offer a migrated UUID after restart; local holds win.
	third := makeController()
	if err = third.Start(); err != nil {
		t.Fatal(err)
	}
	stop(third)
	if n, e := qaFlow(p.port, dest, qaUUID); e == nil {
		n.Close()
		t.Fatal("drain hold lost on clean restart")
	}
	if err = third.Close(); err != nil {
		t.Fatal(err)
	}
	// Missing panel admission fails before accepting users, preserving the journal.
	before, _ := os.ReadFile(filepath.Join(dir, "journal.json"))
	p.mu.Lock()
	p.missingEpoch = true
	p.mu.Unlock()
	if err = makeController().Start(); err == nil {
		t.Fatal("unacknowledged generation admitted users")
	}
	after, _ := os.ReadFile(filepath.Join(dir, "journal.json"))
	if string(before) != string(after) {
		t.Fatal("admission failure changed durable state")
	}
	p.mu.Lock()
	p.missingEpoch = false
	p.mu.Unlock()
	// An abnormal restart restores ordinary service but cannot assert final usage.
	var state map[string]any
	if json.Unmarshal(before, &state) != nil {
		t.Fatal("journal")
	}
	state["counter_session"].(map[string]any)["sealed"] = false
	previousProcess := state["counter_session"].(map[string]any)["process"]
	dirty, _ := json.Marshal(state)
	os.WriteFile(filepath.Join(dir, "journal.json"), dirty, 0600)
	recovered := makeController()
	if err = recovered.Start(); err != nil {
		t.Fatal("ordinary recovery failed", err)
	}
	stop(recovered)
	if !recovered.transfer.session.Uncertain() {
		t.Fatal("uncertain tail not retained")
	}
	id := beuptransfer.Identity{UID: 3, Credential: beupguard.CredentialDigest(qaOther)}
	quality, err := recovered.transfer.session.Inspect(context.Background(), id)
	if err != nil || quality.TrackingReady {
		t.Fatal("uncertain epoch offered migration proof", err)
	}
	other, err = qaFlow(p.port, dest, qaOther)
	if err != nil {
		t.Fatal("ordinary service not restored", err)
	}
	other.Close()
	if n, e := qaFlow(p.port, dest, qaUUID); e == nil {
		n.Close()
		t.Fatal("recovery released old migration hold")
	}
	if err = recovered.Close(); err != nil {
		t.Fatal("current process could not seal while retaining uncertainty", err)
	}
	after, _ = os.ReadFile(filepath.Join(dir, "journal.json"))
	if json.Unmarshal(after, &state) != nil {
		t.Fatal("recovered journal")
	}
	recovery := state["counter_session"].(map[string]any)["unclean_recovery"].(map[string]any)
	if recovery["previous_process"] != previousProcess || recovery["count"] != float64(1) {
		t.Fatal("recovery provenance missing")
	}
	p.mu.Lock()
	v = p.totals[2]
	otherUsage := p.totals[3]
	p.mu.Unlock()
	if v != [2]int64{50, 50} || otherUsage != [2]int64{50, 50} {
		t.Fatalf("recovery lost or rebilled known usage: %v %v", v, otherUsage)
	}
	again := makeController()
	if err = again.Start(); err != nil {
		t.Fatal(err)
	}
	stop(again)
	if !again.transfer.session.Uncertain() {
		t.Fatal("normal reboot erased historical uncertainty")
	}
	if err = again.Close(); err != nil {
		t.Fatal(err)
	}

}

// Compile-time confirmation that the concrete node core retains the original API.
var _ vCore.Core = (*xcore.Xray)(nil)
