package panel

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/InazumaV/V2bX/conf"
)

func TestReliablePanelCancellationAndNoLegacySend(t *testing.T) {
	var pushes atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "push") {
			pushes.Add(1)
			w.WriteHeader(200)
			return
		}
		io.Copy(io.Discard, r.Body)
		select {
		case <-r.Context().Done():
		case <-time.After(2 * time.Second):
		}
	}))
	defer srv.Close()
	c, err := New(&conf.ApiConfig{APIHost: srv.URL, NodeType: "vless", NodeID: 42})
	if err != nil {
		t.Fatal(err)
	}
	c.client.SetTransport(srv.Client().Transport)
	c.client.SetRetryCount(0)
	if err = c.SetTrafficEpoch(strings.Repeat("a", 32)); err != nil {
		t.Fatal(err)
	}
	methods := map[string]func(context.Context) error{
		"config":     func(ctx context.Context) error { _, e := c.GetNodeInfoContext(ctx); return e },
		"users":      func(ctx context.Context) error { _, e := c.GetUserListContext(ctx); return e },
		"alive-list": func(ctx context.Context) error { _, e := c.GetUserAliveContext(ctx); return e },
		"online": func(ctx context.Context) error {
			v := map[int][]string{}
			return c.ReportNodeOnlineUsersContext(ctx, &v)
		},
	}
	for name, fn := range methods {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
			defer cancel()
			start := time.Now()
			if fn(ctx) == nil {
				t.Fatal("cancelled request reported success")
			}
			if time.Since(start) > time.Second {
				t.Fatal("request did not cancel promptly")
			}
		})
	}
	if err = c.ReportUserTraffic([]UserTraffic{{UID: 2, Upload: 1}}); err == nil || pushes.Load() != 0 {
		t.Fatal("legacy traffic reached network")
	}
}

func TestFailedNodeConfigurationDoesNotPoisonCache(t *testing.T) {
	var requests int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.Header().Set("ETag", "untrusted")
		w.WriteHeader(503)
		w.Write([]byte(`{"error":"temporary"}`))
	}))
	defer srv.Close()
	c, _ := New(&conf.ApiConfig{APIHost: srv.URL, NodeType: "vless", NodeID: 42})
	c.client.SetRetryCount(0)
	for i := 0; i < 2; i++ {
		if _, err := c.GetNodeInfo(); err == nil {
			t.Fatal("failed response accepted as unchanged")
		}
		if c.nodeEtag != "" || c.responseBodyHash != "" {
			t.Fatal("failed response cached")
		}
	}
	if requests != 2 {
		t.Fatal("second request skipped")
	}
}
