//go:build beupqa

package node

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/InazumaV/V2bX/api/panel"
	"github.com/InazumaV/V2bX/conf"
	xcore "github.com/InazumaV/V2bX/core/xray"
	"github.com/InazumaV/V2bX/limiter"
)

func TestTransferControllerPHPHost(t *testing.T) {
	script := os.Getenv("BEUP_TRANSFER_PHP_CONTROLLER_QA")
	if script == "" {
		t.Skip("explicit synthetic PHP fixture required")
	}
	port := qaPort(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "php", script, strconv.Itoa(port))
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	input, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	output, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		input.Close()
		if e := cmd.Wait(); e != nil {
			t.Errorf("synthetic PHP fixture: %v %s", e, stderr.String())
		}
	}()
	lines := bufio.NewReader(output)
	line, err := lines.ReadString('\n')
	if err != nil || line != "READY\n" {
		t.Fatalf("PHP not ready: %v %s %s", err, line, stderr.String())
	}
	var mu sync.Mutex
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		body, e := io.ReadAll(r.Body)
		if e != nil {
			http.Error(w, "fixture read", 500)
			return
		}
		wire, _ := json.Marshal(map[string]any{"uri": r.URL.RequestURI(), "method": r.Method, "headers": r.Header, "body": string(body)})
		if _, e = input.Write(append(wire, '\n')); e != nil {
			http.Error(w, "fixture write", 500)
			return
		}
		line, e := lines.ReadString('\n')
		if e != nil {
			http.Error(w, "fixture reply", 500)
			return
		}
		var reply struct {
			Status  int                 `json:"status"`
			Headers map[string][]string `json:"headers"`
			Body    string              `json:"body"`
		}
		if json.Unmarshal([]byte(line), &reply) != nil {
			http.Error(w, "fixture decode", 500)
			return
		}
		for k, vs := range reply.Headers {
			for _, v := range vs {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(reply.Status)
		io.WriteString(w, reply.Body)
	}))
	defer srv.Close()
	old := http.DefaultTransport
	tr := old.(*http.Transport).Clone()
	roots := x509.NewCertPool()
	roots.AddCert(srv.Certificate())
	tr.TLSClientConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
	http.DefaultTransport = tr
	defer func() { http.DefaultTransport = old; tr.CloseIdleConnections() }()
	limiter.Init()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	os.Chmod(dir, 0700)
	if err = os.WriteFile(filepath.Join(dir, "accounting.key"), bytes.Repeat([]byte{9}, 32), 0600); err != nil {
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

	// The deployed inventory includes five processes shared with an unchanged panel.
	// The other controller must retain ordinary legacy accounting and connections.
	legacyPort := qaPort(t)
	legacyFixture := &controllerPanel{epoch: "", port: legacyPort, users: []panel.UserInfo{{Id: 3, Uuid: qaOther}}}
	var legacyReports atomic.Int32
	legacyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/server/UniProxy/push" {
			io.Copy(io.Discard, r.Body)
			legacyReports.Add(1)
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, `{"data":true}`)
			return
		}
		legacyFixture.ServeHTTP(w, r)
	}))
	defer legacyServer.Close()
	legacyAPI, e := panel.New(&conf.ApiConfig{APIHost: legacyServer.URL, NodeType: "vless", NodeID: 46, Timeout: 2})
	if e != nil {
		t.Fatal(e)
	}
	legacy := NewController(core, legacyAPI, &conf.Options{Name: "other-panel-synthetic", Core: "xray", ListenIP: "127.0.0.1", SendIP: "127.0.0.1", XrayOptions: conf.NewXrayOptions(), CertConfig: conf.NewCertConfig()})
	if e = legacy.Start(); e != nil {
		t.Fatal("shared legacy controller", e)
	}
	defer legacy.Close()
	api, err := panel.New(&conf.ApiConfig{APIHost: srv.URL, NodeType: "vless", NodeID: 42, Timeout: 2})
	if err != nil {
		t.Fatal(err)
	}
	if err = api.TrustLoopbackQA(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}))); err != nil {
		t.Fatal(err)
	}
	c := NewController(core, api, &conf.Options{Name: "php-host-synthetic", Core: "xray", ListenIP: "127.0.0.1", SendIP: "127.0.0.1", XrayOptions: conf.NewXrayOptions(), CertConfig: conf.NewCertConfig(), TransferAccounting: &conf.TransferAccountingConfig{Epoch: strings.Repeat("a", 32), Directory: dir}})
	if err = c.Start(); err != nil {
		t.Fatal("actual PHP controller rejected startup", err)
	}
	closed := false
	defer func() {
		if !closed {
			c.Close()
		}
	}()
	if err = c.transfer.worker.Close(ctx); err != nil {
		t.Fatal(err)
	}
	dest, stopEcho := qaEcho(t)
	defer stopEcho()
	flow, err := qaFlow(port, dest, qaUUID)
	if err != nil {
		t.Fatal(err)
	}
	defer flow.Close()
	if err = c.transfer.runtime.Step(ctx); err != nil {
		t.Fatal("actual PHP traffic/control exchange", err)
	}
	if err = c.Close(); err != nil {
		t.Fatal(err)
	}
	closed = true

	otherFlow, e := qaFlow(legacyPort, dest, qaOther)
	if e != nil {
		t.Fatal("shared legacy connection lost after reliable close", e)
	}
	defer otherFlow.Close()
	if e = legacy.reportUserTrafficTask(); e != nil {
		t.Fatal("other panel legacy accounting changed", e)
	}
	if legacyReports.Load() == 0 {
		t.Fatal("shared legacy panel did not receive usage")
	}
	response, err := srv.Client().Get(srv.URL + "/qa-summary")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var summary struct {
		Scope                     string
		Identities, U, D, Batches int
	}
	if err = json.NewDecoder(response.Body).Decode(&summary); err != nil {
		t.Fatal(err)
	}
	if summary.Scope != "vless-42" || summary.Identities != 1 || summary.U != len("synthetic-tail-accounting") || summary.D != summary.U || summary.Batches < 1 {
		t.Fatalf("unexpected actual PHP ledger: %+v", summary)
	}
}
