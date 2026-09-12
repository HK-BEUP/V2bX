package observer

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func settings(endpoint string) Settings {
	return Settings{Enabled: true, Mode: "observe", Node: "demo-hk", IdentityRevision: "synthetic-v1", Endpoint: endpoint, ObservationKey: strings.Repeat("synthetic-only-", 3), Bindings: map[string]map[int]string{"tag": {2: testSubject}}}
}
func currentReport() Report {
	return Report{Version: 1, Profile: Profile, IdentityRevision: "synthetic-v1", BatchID: strings.Repeat("a", 32), WindowStart: time.Now().Unix()/60*60 - 60, WindowEnd: time.Now().Unix() / 60 * 60, Subjects: []Sample{}}
}
func TestHTTPDeliveryRetryAndSignature(t *testing.T) {
	var requests atomic.Int64
	var initial []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(io.LimitReader(r.Body, 262145))
		hash := sha256.Sum256(b)
		h := hmac.New(sha256.New, []byte(settings("").ObservationKey))
		h.Write([]byte("POST\n/api/v1/attack-guard/observation\ndemo-hk\n" + r.Header.Get("X-Guard-Timestamp") + "\n" + hex.EncodeToString(hash[:])))
		if r.Header.Get("X-Guard-Signature") != hex.EncodeToString(h.Sum(nil)) {
			t.Error("bad signature")
		}
		if requests.Add(1) == 1 {
			initial = b
			w.WriteHeader(503)
			return
		}
		if string(initial) != string(b) {
			t.Error("retry changed batch")
		}
		io.WriteString(w, `{"data":{"observation_only":true}}`)
	}))
	defer srv.Close()
	r, e := NewRuntime(settings(srv.URL + "/api/v1/attack-guard/observation"))
	if e != nil {
		t.Fatal(e)
	}
	if !r.send(context.Background(), currentReport()) || requests.Load() != 2 || r.Sent.Load() != 1 {
		t.Fatal("delivery retry")
	}
}
func TestRedirectAuthAndHTMLFailClosed(t *testing.T) {
	for _, status := range []int{302, 401, 200} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			var requests atomic.Int64
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				w.Header().Set("Location", "http://127.0.0.1:1/credential-leak")
				w.WriteHeader(status)
				io.WriteString(w, "not an observation acknowledgement")
			}))
			defer srv.Close()
			r, _ := NewRuntime(settings(srv.URL + "/api/v1/attack-guard/observation"))
			if r.send(context.Background(), currentReport()) || requests.Load() != 1 || r.Failed.Load() != 1 {
				t.Fatal("unsafe response accepted/retried")
			}
		})
	}
}
func TestRuntimeBoundsExpiryAndEndpoints(t *testing.T) {
	for _, url := range []string{"http://public.example.test/api/v1/attack-guard/observation", "https://user:pass@example.test/api/v1/attack-guard/observation", "https://example.test/api/v1/attack-guard/report", "https://example.test/api/v1/attack-guard/observation?token=x"} {
		if _, e := NewRuntime(settings(url)); e == nil {
			t.Fatal("unsafe endpoint")
		}
	}
	r, _ := NewRuntime(settings("http://127.0.0.1:1/api/v1/attack-guard/observation"))
	for i := 0; i < 64; i++ {
		if !r.Enqueue(currentReport()) {
			t.Fatal("queue capacity")
		}
	}
	if r.Enqueue(currentReport()) || r.QueueDropped.Load() != 1 {
		t.Fatal("unbounded queue")
	}
	old := currentReport()
	old.WindowEnd -= 180
	if r.send(context.Background(), old) || r.Expired.Load() != 1 {
		t.Fatal("expired report sent")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done := make(chan bool)
	go func() { r.Run(ctx); done <- true }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("shutdown hangs")
	}
}
func TestPrivateConfigAndDisabledStartup(t *testing.T) {
	dir := t.TempDir()
	if e := os.Chmod(dir, 0700); e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(dir, "observation.json")
	b, _ := json.Marshal(settings("http://127.0.0.1:1/api/v1/attack-guard/observation"))
	if e := os.WriteFile(path, b, 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := LoadSettings(path); e != nil {
		t.Fatal(e)
	}
	os.Chmod(path, 0644)
	if _, e := LoadSettings(path); e == nil {
		t.Fatal("public config accepted")
	}
	os.Chmod(path, 0600)
	link := filepath.Join(dir, "linked.json")
	os.Symlink(path, link)
	if _, e := LoadSettings(link); e == nil {
		t.Fatal("symlink config accepted")
	}
	t.Setenv("BEUP_OBSERVATION_CONFIG", "")
	stop, e := StartFromEnvironment()
	if e != nil {
		t.Fatal(e)
	}
	stop()
	t.Setenv("BEUP_OBSERVATION_CONFIG", path)
	stop, e = StartFromEnvironment()
	if e != nil {
		t.Fatal(e)
	}
	stop()
	stop()
	if active.Load() != nil {
		t.Fatal("shutdown leaves observer")
	}
}

func TestReloadAndAccountIdentityConsistency(t *testing.T) {
	_, e := New(Config{Node: "demo-hk", IdentityRevision: "synthetic-v1", Bindings: map[string]map[int]string{"a": {2: strings.Repeat("a", 32)}, "b": {2: strings.Repeat("b", 32)}}})
	if e == nil {
		t.Fatal("one UID accepted with conflicting subjects")
	}
	now := time.Unix(1800000000, 0)
	o, e := New(Config{Node: "demo-hk", IdentityRevision: "synthetic-v1", Now: func() time.Time { return now }, Bindings: map[string]map[int]string{"tag": {2: testSubject}}})
	if e != nil {
		t.Fatal(e)
	}
	Set(o)
	defer Set(nil)
	o.Bind("tag", "synthetic-label", 2)
	o.Observe("tag", "synthetic-label", "tcp", "example.test", 443)
	Reset()
	o.Observe("tag", "synthetic-label", "tcp", "example.test", 443)
	r, e := o.Snapshot(now.Add(time.Minute))
	if e != nil {
		t.Fatal(e)
	}
	if len(r[0].Subjects) != 0 || !r[0].Quality.PartialWindow || r[0].Quality.UnmappedRequests != 1 {
		t.Fatal("reload retained stale binding or complete counters")
	}
}
