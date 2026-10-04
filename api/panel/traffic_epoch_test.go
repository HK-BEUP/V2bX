package panel

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/InazumaV/V2bX/conf"
)

func TestTrafficEpochAdmissionAcknowledgement(t *testing.T) {
	for _, mode := range []string{"200", "empty", "304", "missing", "wrong", "304-missing"} {
		t.Run(mode, func(t *testing.T) {
			epoch := strings.Repeat("a", 32)
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/api/v1/server/UniProxy/user" || r.Header.Get("X-Beup-Traffic-Epoch") != epoch {
					t.Error("missing admission binding")
				}
				if mode != "missing" && mode != "304-missing" {
					v := epoch
					if mode == "wrong" {
						v = strings.Repeat("b", 32)
					}
					w.Header().Set("X-Beup-Traffic-Epoch", v)
				}
				w.Header().Set("ETag", "synthetic-current")
				if strings.HasPrefix(mode, "304") {
					w.WriteHeader(304)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				if mode == "empty" {
					_, _ = w.Write([]byte(`{"users":[]}`))
					return
				}
				_, _ = w.Write([]byte(`{"users":[{"id":7,"uuid":"00000000-0000-4000-8000-000000000007"}]}`))
			}))
			defer srv.Close()
			c, err := New(&conf.ApiConfig{APIHost: srv.URL, NodeType: "vless", NodeID: 99})
			if err != nil {
				t.Fatal(err)
			}
			c.client.SetTransport(srv.Client().Transport)
			c.client.SetRetryCount(0)
			if err = c.SetTrafficEpoch(epoch); err != nil {
				t.Fatal(err)
			}
			users, err := c.GetUserList()
			if mode == "missing" || mode == "wrong" || mode == "304-missing" {
				if err == nil || c.userEtag != "" {
					t.Fatal("unconfirmed generation accepted/cached")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if mode == "empty" && (users == nil || len(users) != 0) {
				t.Fatal("authoritative empty list confused with unchanged")
			}
			if mode == "304" && users != nil {
				t.Fatal("304 was not unchanged")
			}
			if mode == "200" && len(users) != 1 {
				t.Fatal("users not returned")
			}
		})
	}
}

func TestTrafficEpochConfigurationAndLegacy(t *testing.T) {
	for _, host := range []string{"http://example.invalid", "https://user:pass@example.invalid", "https://example.invalid/?token=x", "https://example.invalid/#x"} {
		c, _ := New(&conf.ApiConfig{APIHost: host, NodeType: "vless", NodeID: 99})
		if err := c.SetTrafficEpoch(strings.Repeat("a", 32)); err == nil {
			t.Fatal("unsafe endpoint accepted")
		}
	}
	c, _ := New(&conf.ApiConfig{APIHost: "https://example.invalid", NodeType: "vless", NodeID: 99})
	c.userEtag = "old"
	if c.SetTrafficEpoch(strings.Repeat("A", 32)) == nil {
		t.Fatal("noncanonical epoch accepted")
	}
	if c.SetTrafficEpoch(strings.Repeat("a", 32)) != nil || c.userEtag != "" {
		t.Fatal("new generation kept stale ETag")
	}
	if c.SetTrafficEpoch(strings.Repeat("b", 32)) == nil {
		t.Fatal("live generation replaced")
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Beup-Traffic-Epoch") != "" {
			t.Error("legacy request changed")
		}
		_, _ = w.Write([]byte(`{"users":[]}`))
	}))
	defer srv.Close()
	c, _ = New(&conf.ApiConfig{APIHost: srv.URL, NodeType: "vless", NodeID: 99})
	if users, err := c.GetUserList(); err != nil || users == nil {
		t.Fatal("legacy empty response regressed", err)
	}
}
