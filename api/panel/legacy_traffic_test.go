package panel

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/InazumaV/V2bX/common/beuptransfer"
	"github.com/InazumaV/V2bX/conf"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestLegacyAcknowledgementBoundary(t *testing.T) {
	b := beuptransfer.Batch{Version: 1, Scope: "vless-42", Epoch: strings.Repeat("a", 32), Sequence: 1, Entries: []beuptransfer.Sample{{UID: 7, Credential: strings.Repeat("b", 64), Upload: 13, Download: 24}}}
	b.Digest = b.Hash()
	for _, mode := range []string{"pending", "committed", "old-true", "wrong-id", "wrong-digest", "accepted-true", "ok-false", "rejected", "settling", "other-conflict", "redirect"} {
		t.Run(mode, func(t *testing.T) {
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/api/v1/server/UniProxy/push" || r.Header.Get("X-Beup-Legacy-Accounting") != "1" || r.Header.Get("X-Beup-Traffic-Epoch") != "" || r.URL.Query().Get("node_id") != "42" {
					t.Error("wrong old endpoint binding")
				}
				id, digest, want, _ := beuptransfer.LegacyPayload(b)
				var got map[int64][2]int64
				if json.NewDecoder(r.Body).Decode(&got) != nil || got[7] != want[7] || r.Header.Get("X-Beup-Report-Id") != id || r.Header.Get("X-Beup-Report-Digest") != digest {
					t.Error("body identity changed")
				}
				w.Header().Set("Content-Type", "application/json")
				if mode == "redirect" {
					w.Header().Set("Location", "https://example.invalid")
					w.WriteHeader(302)
					return
				}
				if mode == "settling" || mode == "other-conflict" {
					w.WriteHeader(409)
					code := "traffic_settling"
					if mode == "other-conflict" { code = "legacy_report_conflict" }
					json.NewEncoder(w).Encode(map[string]string{"code":code})
					return
				}
				if mode == "rejected" {
					w.WriteHeader(409)
					return
				}
				if mode == "old-true" {
					w.Write([]byte(`{"data":true}`))
					return
				}
				if mode == "wrong-id" {
					id = strings.Repeat("0", 32)
				}
				if mode == "wrong-digest" {
					digest = strings.Repeat("0", 64)
				}
				done := mode != "pending" && mode != "ok-false"
				if mode == "pending" || mode == "accepted-true" {
					w.WriteHeader(202)
				}
				json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"request_id": id, "digest": digest, "committed": done}})
			}))
			defer srv.Close()
			c, err := New(&conf.ApiConfig{APIHost: srv.URL, NodeType: "vless", NodeID: 42})
			if err != nil {
				t.Fatal(err)
			}
			c.client.SetTransport(srv.Client().Transport)
			c.client.SetRetryCount(0)
			if err = c.EnableLegacyAccounting(); err != nil {
				t.Fatal(err)
			}
			ack, err := c.Commit(context.Background(), b)
			if mode == "committed" {
				if err != nil || ack.Digest != b.Digest {
					t.Fatal(err)
				}
			} else if mode == "pending" || mode == "settling" {
				if !errors.Is(err, beuptransfer.ErrPending) {
					t.Fatal(err)
				}
			} else if err == nil {
				t.Fatal("unsafe acknowledgement accepted")
			}
		})
	}
}
func TestLegacyModeCannotMixOrResetCounters(t *testing.T) {
	for _, host := range []string{"http://example.invalid", "https://u:p@example.invalid", "https://example.invalid/path"} {
		c, _ := New(&conf.ApiConfig{APIHost: host, NodeType: "vless", NodeID: 42})
		if c.EnableLegacyAccounting() == nil {
			t.Fatal("unsafe origin")
		}
	}
	c, _ := New(&conf.ApiConfig{APIHost: "https://example.invalid", NodeType: "vless", NodeID: 42})
	if c.EnableLegacyAccounting() != nil {
		t.Fatal("enable")
	}
	if c.SetTrafficEpoch(strings.Repeat("a", 32)) == nil {
		t.Fatal("mixed billing")
	}
	c, _ = New(&conf.ApiConfig{APIHost: "https://example.invalid", NodeType: "vless", NodeID: 42})
	c.SetTrafficEpoch(strings.Repeat("a", 32))
	if c.EnableLegacyAccounting() == nil {
		t.Fatal("mixed billing")
	}
}

func TestLegacyUserAdmissionBusyOnly(t *testing.T) {
 for _,code:=range []string{"traffic_settling","epoch_active","legacy_report_conflict","oversized"}{t.Run(code,func(t *testing.T){
  srv:=httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){w.WriteHeader(409);if code=="oversized"{w.Write([]byte(strings.Repeat(" ",1025)+`{"code":"traffic_settling"}`));return};json.NewEncoder(w).Encode(map[string]string{"code":code})}));defer srv.Close()
  c,err:=New(&conf.ApiConfig{APIHost:srv.URL,NodeType:"vless",NodeID:42});if err!=nil{t.Fatal(err)};c.client.SetTransport(srv.Client().Transport);c.client.SetRetryCount(0);if err=c.EnableLegacyAccounting();err!=nil{t.Fatal(err)}
  users,err:=c.GetUserListContext(context.Background());if err==nil||users!=nil{t.Fatal("error accepted as user list")};if errors.Is(err,ErrLegacySettlementBusy)!=(code=="traffic_settling"){t.Fatal("wrong retry classification",err)}
 })}
}
