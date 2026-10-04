//go:build beupqa

package node

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/InazumaV/V2bX/api/panel"
	"github.com/InazumaV/V2bX/common/beuptransfer"
	"github.com/InazumaV/V2bX/conf"
	xcore "github.com/InazumaV/V2bX/core/xray"
	"github.com/InazumaV/V2bX/limiter"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

type legacyPanel struct {
	mu             sync.Mutex
	port           int
	users          []panel.UserInfo
	hold           bool
	seen           map[string]string
	totals         map[int64][2]int64
	reports, other int
}

func (p *legacyPanel) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	defer p.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	if r.Header.Get("X-Beup-Traffic-Epoch") != "" {
		p.other++
		http.Error(w, "mixed", 409)
		return
	}
	switch r.URL.Path {
	case "/api/v1/server/UniProxy/config":
		json.NewEncoder(w).Encode(map[string]any{"server_port": p.port, "tls": 0, "network": "tcp", "network_settings": map[string]any{}, "routes": []any{}, "base_config": map[string]any{"push_interval": 60, "pull_interval": 60}})
	case "/api/v1/server/UniProxy/user":
		json.NewEncoder(w).Encode(map[string]any{"users": p.users})
	case "/api/v1/server/UniProxy/alivelist":
		io.WriteString(w, `{"alive":{}}`)
	case "/api/v1/server/UniProxy/alive":
		io.WriteString(w, `{"data":true}`)
	case "/api/v1/server/UniProxy/push":
		p.reports++
		id, digest := r.Header.Get("X-Beup-Report-Id"), r.Header.Get("X-Beup-Report-Digest")
		var rows map[int64][2]int64
		if json.NewDecoder(r.Body).Decode(&rows) != nil || len(id) != 32 {
			http.Error(w, "body", 400)
			return
		}
		ids := []int64{}
		for uid := range rows {
			ids = append(ids, uid)
		}
		sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
		canonical := fmt.Sprintf("beup-legacy-report-v1\nvless-42\n%s\n", id)
		for _, uid := range ids {
			v := rows[uid]
			canonical += fmt.Sprintf("%d:%d:%d\n", uid, v[0], v[1])
		}
		hash := sha256.Sum256([]byte(canonical))
		if hex.EncodeToString(hash[:]) != digest {
			http.Error(w, "digest", 409)
			return
		}
		if prior, ok := p.seen[id]; ok && prior != digest {
			http.Error(w, "conflict", 409)
			return
		}
		if !p.hold {
			if _, ok := p.seen[id]; !ok {
				p.seen[id] = digest
				for uid, v := range rows {
					old := p.totals[uid]
					p.totals[uid] = [2]int64{old[0] + v[0], old[1] + v[1]}
				}
			}
		} else {
			w.WriteHeader(202)
		}
		json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"request_id": id, "digest": digest, "committed": !p.hold}})
	default:
		p.other++
		http.NotFound(w, r)
	}
}
func TestLegacyControllerQueueTailReloadRestart(t *testing.T) {
	limiter.Init()
	p := &legacyPanel{port: qaPort(t), users: []panel.UserInfo{{Id: 2, Uuid: qaUUID}, {Id: 3, Uuid: qaOther}}, hold: true, seen: map[string]string{}, totals: map[int64][2]int64{}}
	srv := httptest.NewTLSServer(p)
	defer srv.Close()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	os.Chmod(dir, 0700)
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
		return NewController(core, api, &conf.Options{Name: "legacy-synthetic", ReportMinTraffic: 0, Core: "xray", ListenIP: "127.0.0.1", SendIP: "127.0.0.1", XrayOptions: conf.NewXrayOptions(), CertConfig: conf.NewCertConfig(), LegacyAccounting: &conf.LegacyAccountingConfig{Directory: dir}})
	}
	stopWorker := func(c *Controller) {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if e := c.transfer.worker.Close(ctx); e != nil {
			t.Fatal(e)
		}
	}
	c := makeController()
	if err = c.Start(); err != nil {
		t.Fatal(err)
	}
	stopWorker(c)
	defer func() { p.mu.Lock(); p.hold = false; p.mu.Unlock(); c.Close() }()
	if c.userReportPeriodic != nil || c.nodeInfoMonitorPeriodic != nil || c.transfer.runtime != nil {
		t.Fatal("extra old reset or new control loop started")
	}
	if c.reportUserTrafficTask() == nil {
		t.Fatal("reset reporter still accessible")
	}
	dest, closeEcho := qaEcho(t)
	defer closeEcho()
	flow, err := qaFlow(p.port, dest, qaUUID)
	if err != nil {
		t.Fatal(err)
	}
	defer flow.Close()
	// Polling cannot manufacture success, nor multiply reports when interval is not due.
	if err = c.legacyStep(context.Background()); err != nil {
		t.Fatal(err)
	}
	p.mu.Lock()
	if len(p.seen) != 0 {
		t.Fatal("accepted claimed committed")
	}
	p.hold = false
	p.mu.Unlock()
	c.transfer.lastReport = time.Time{}
	if err = c.legacyStep(context.Background()); err != nil {
		t.Fatal(err)
	}
	p.mu.Lock()
	count := p.reports
	v := p.totals[2]
	p.mu.Unlock()
	if v != [2]int64{25, 25} {
		t.Fatal("usage wrong", v)
	}
	if err = c.legacyStep(context.Background()); err != nil {
		t.Fatal(err)
	}
	p.mu.Lock()
	if p.reports != count {
		t.Fatal("ignored configured report interval")
	}
	p.mu.Unlock()
	// A changed panel port seals current counters before rebuilding the inbound.
	p.mu.Lock()
	oldPort := p.port
	p.port = qaPort(t)
	p.mu.Unlock()
	c.transfer.lastPull = time.Time{}
	if err = c.legacyStep(context.Background()); err != nil {
		t.Fatal("reload", err)
	}
	if n, e := qaFlow(oldPort, dest, qaUUID); e == nil {
		n.Close()
		t.Fatal("old inbound survived reload")
	}
	flow2, err := qaFlow(p.port, dest, qaUUID)
	if err != nil {
		t.Fatal("new inbound", err)
	}
	defer flow2.Close()
	// Shutdown must stop connections but preserve the pending tail across HTTP 202.
	p.mu.Lock()
	p.hold = true
	p.mu.Unlock()
	if err = c.transfer.session.Seal(context.Background()); !errors.Is(err, beuptransfer.ErrPending) {
		t.Fatal("tail seal", err)
	}
	if n, e := qaFlow(p.port, dest, qaUUID); e == nil {
		n.Close()
		t.Fatal("quiesced inbound admitted connection")
	}
	p.mu.Lock()
	p.hold = false
	p.mu.Unlock()
	if err = c.transfer.session.Seal(context.Background()); err != nil {
		t.Fatal("async final ACK", err)
	}
	if err = c.Close(); err != nil {
		t.Fatal(err)
	}
	c = makeController()
	if err = c.Start(); err != nil {
		t.Fatal("clean restart", err)
	}
	stopWorker(c)
	flow3, err := qaFlow(p.port, dest, qaUUID)
	if err != nil {
		t.Fatal(err)
	}
	defer flow3.Close()
	// Empty authoritative user list removes access and final bytes survive removal.
	p.mu.Lock()
	p.users = []panel.UserInfo{}
	p.mu.Unlock()
	c.transfer.lastPull = time.Time{}
	c.transfer.lastReport = time.Time{}
	if err = c.legacyStep(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(c.userList) != 0 {
		t.Fatal("empty list ignored")
	}
	if n, e := qaFlow(p.port, dest, qaOther); e == nil {
		n.Close()
		t.Fatal("removed credential reconnected")
	}
	if err = c.Close(); err != nil {
		t.Fatal(err)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.totals[2] != [2]int64{75, 75} || p.other != 0 {
		t.Fatal("restart double count or new endpoint called", p.totals, p.other)
	}
	raw, e := os.ReadFile(filepath.Join(dir, "journal.json"))
	if e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(string(raw), `"sealed":true`) {
		t.Fatal("final journal unsealed")
	}
}

// Reproduce the production first-report lock-contention path without a server change.
func TestLegacyInitialBusyPreservesController(t *testing.T) {
 limiter.Init()
 p := &legacyPanel{port: qaPort(t), users: []panel.UserInfo{{Id: 2, Uuid: qaUUID}}, seen: map[string]string{}, totals: map[int64][2]int64{}}
 first := true
 srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
  if r.URL.Path == "/api/v1/server/UniProxy/push" && first { first = false; w.WriteHeader(409); io.WriteString(w, `{"code":"traffic_settling"}`); return }
  p.ServeHTTP(w, r)
 }))
 defer srv.Close()
 dir, err := filepath.EvalSymlinks(t.TempDir()); if err != nil { t.Fatal(err) }; os.Chmod(dir, 0700)
 xc := conf.NewXrayConfig(); xc.AssetPath=t.TempDir(); xc.LogConfig.Level="none"; xc.LogConfig.AccessPath="none"
 core, err := xcore.New(&conf.CoreConfig{Type:"xray",XrayConfig:xc}); if err!=nil {t.Fatal(err)}
 if err=core.Start();err!=nil{t.Fatal(err)};defer core.Close()
 makeController:=func()*Controller{
  api,e:=panel.New(&conf.ApiConfig{APIHost:srv.URL,NodeType:"vless",NodeID:42,Timeout:2});if e!=nil{t.Fatal(e)}
  if e=api.TrustLoopbackQA(string(pem.EncodeToMemory(&pem.Block{Type:"CERTIFICATE",Bytes:srv.Certificate().Raw})));e!=nil{t.Fatal(e)}
  return NewController(core,api,&conf.Options{Name:"initial-busy-synthetic",ReportMinTraffic:0,Core:"xray",ListenIP:"127.0.0.1",SendIP:"127.0.0.1",XrayOptions:conf.NewXrayOptions(),CertConfig:conf.NewCertConfig(),LegacyAccounting:&conf.LegacyAccountingConfig{Directory:dir}})
 }
 c:=makeController();err=c.Start()
 if err!=nil {t.Fatalf("busy lock must retain controller: %v",err)}
 if c.transfer==nil || c.transfer.finished || c.transfer.worker==nil {t.Fatal("controller closed on transient lock contention")}
 raw,e:=os.ReadFile(filepath.Join(dir,"journal.json"));if e!=nil{t.Fatal(e)}
 var journal map[string]any; if e=json.Unmarshal(raw,&journal);e!=nil{t.Fatal(e)}
 if journal["pending"]==nil {t.Fatal("pending report lost")}
 if e=c.Close();e!=nil{t.Fatal(e)}
 raw,e=os.ReadFile(filepath.Join(dir,"journal.json"));if e!=nil || !strings.Contains(string(raw),`"sealed":true`){t.Fatal("final journal not sealed")}

 if p.other!=0 {t.Fatal("new protocol called")}
 t.Log("An initial traffic_settling 409 keeps the controller running and report durable; seal completes without restart")
}

func TestLegacyInitialUserBusyPreservesController(t *testing.T) {
 limiter.Init()
 p := &legacyPanel{port: qaPort(t), users: []panel.UserInfo{{Id: 2, Uuid: qaUUID}}, seen: map[string]string{}, totals: map[int64][2]int64{}}
 first := true
 srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
  if r.URL.Path == "/api/v1/server/UniProxy/user" && first { first = false; w.WriteHeader(409); io.WriteString(w, `{"code":"traffic_settling"}`); return }
  p.ServeHTTP(w, r)
 }))
 defer srv.Close()
 dir, err := filepath.EvalSymlinks(t.TempDir()); if err != nil { t.Fatal(err) }; os.Chmod(dir, 0700)
 xc := conf.NewXrayConfig(); xc.AssetPath=t.TempDir(); xc.LogConfig.Level="none"; xc.LogConfig.AccessPath="none"
 core, err := xcore.New(&conf.CoreConfig{Type:"xray",XrayConfig:xc}); if err!=nil {t.Fatal(err)}
 if err=core.Start();err!=nil{t.Fatal(err)};defer core.Close()
 makeController:=func()*Controller{
  api,e:=panel.New(&conf.ApiConfig{APIHost:srv.URL,NodeType:"vless",NodeID:42,Timeout:2});if e!=nil{t.Fatal(e)}
  if e=api.TrustLoopbackQA(string(pem.EncodeToMemory(&pem.Block{Type:"CERTIFICATE",Bytes:srv.Certificate().Raw})));e!=nil{t.Fatal(e)}
  return NewController(core,api,&conf.Options{Name:"initial-busy-synthetic",ReportMinTraffic:0,Core:"xray",ListenIP:"127.0.0.1",SendIP:"127.0.0.1",XrayOptions:conf.NewXrayOptions(),CertConfig:conf.NewCertConfig(),LegacyAccounting:&conf.LegacyAccountingConfig{Directory:dir}})
 }
 c:=makeController();err=c.Start()
 if err!=nil {t.Fatalf("busy lock must retain controller: %v",err)}
 if c.transfer==nil || c.transfer.finished || c.transfer.worker==nil {t.Fatal("controller closed on transient lock contention")}
 raw,e:=os.ReadFile(filepath.Join(dir,"journal.json"));if e!=nil{t.Fatal(e)}
 var journal map[string]any; if e=json.Unmarshal(raw,&journal);e!=nil{t.Fatal(e)}
 if journal["last_ack"]==nil {t.Fatal("report not acknowledged after valid admission")}
 if e=c.Close();e!=nil{t.Fatal(e)}
 raw,e=os.ReadFile(filepath.Join(dir,"journal.json"));if e!=nil || !strings.Contains(string(raw),`"sealed":true`){t.Fatal("final journal not sealed")}

 if p.other!=0 {t.Fatal("new protocol called")}
 t.Log("An initial traffic_settling 409 keeps the controller running and report durable; seal completes without restart")
}

func TestLegacyInitialUserBusyDeadline(t *testing.T) {
 srv:=httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){w.WriteHeader(409);io.WriteString(w,`{"code":"traffic_settling"}`)}));defer srv.Close()
 api,err:=panel.New(&conf.ApiConfig{APIHost:srv.URL,NodeType:"vless",NodeID:42,Timeout:2});if err!=nil{t.Fatal(err)}
 if err=api.TrustLoopbackQA(string(pem.EncodeToMemory(&pem.Block{Type:"CERTIFICATE",Bytes:srv.Certificate().Raw})));err!=nil{t.Fatal(err)}
 if err=api.EnableLegacyAccounting();err!=nil{t.Fatal(err)}
 ctx,cancel:=context.WithTimeout(context.Background(),50*time.Millisecond);defer cancel()
 c:=&Controller{apiClient:api};users,err:=c.initialLegacyUsers(ctx)
 if !errors.Is(err,context.DeadlineExceeded)||users!=nil{t.Fatalf("deadline did not fail closed: %v",err)}
}
