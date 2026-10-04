package panel

import (
	"encoding/json"
	"github.com/InazumaV/V2bX/conf"
	"math"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSubscriptionCredentialsAggregateAtRealHTTPBoundary(t *testing.T) {
	var got map[int][]int64
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/server/UniProxy/push" {
			t.Errorf("wrong path")
		}
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Error(err)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"data":true}`))
	}))
	defer s.Close()
	c, err := New(&conf.ApiConfig{APIHost: s.URL, NodeType: "vless", NodeID: 1, Key: "SYNTHETIC"})
	if err != nil {
		t.Fatal(err)
	}
	if err = c.ReportUserTraffic([]UserTraffic{{UID: 21, Upload: 11, Download: 19}, {UID: 21, Upload: 7, Download: 13}, {UID: 22, Upload: 3, Download: 5}}); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[21][0] != 18 || got[21][1] != 32 || got[22][1] != 5 {
		t.Fatalf("traffic lost: %#v", got)
	}
}
func TestInvalidCredentialCountersDoNotSendPartialBilling(t *testing.T) {
	for _, rows := range [][]UserTraffic{{{UID: 0, Upload: 1}}, {{UID: 1, Upload: -1}}, {{UID: 1, Upload: math.MaxInt64}, {UID: 1, Upload: 1}}} {
		if _, e := aggregateUserTraffic(rows); e == nil {
			t.Fatal("invalid aggregate accepted")
		}
	}
}
