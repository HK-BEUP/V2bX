package dispatcher

import (
	"context"
	beupobserve "github.com/InazumaV/V2bX/common/beupobserve"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"testing"
	"time"
)

func TestObserverUsesAuthenticatedSessionNotSource(t *testing.T) {
	now := time.Unix(1800000000, 0)
	o, err := beupobserve.New(beupobserve.Config{Node: "demo-hk", IdentityRevision: "synthetic-v1", Bindings: map[string]map[int]string{"test-inbound": {2: "00000000000000000000000000000002"}}, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	beupobserve.Set(o)
	defer beupobserve.Set(nil)
	beupobserve.Bind("test-inbound", "private-test-tag", 2)
	dest := net.TCPDestination(net.ParseAddress("192.0.2.10"), 443)
	// Shared relay source is deliberately identical for authenticated/unknown users.
	source := net.TCPDestination(net.ParseAddress("198.51.100.9"), 50000)
	for _, label := range []string{"private-test-tag", "unknown-label"} {
		ctx := session.ContextWithInbound(context.Background(), &session.Inbound{Tag: "test-inbound", User: &protocol.MemoryUser{Email: label}, Source: source})
		observeAuthenticatedRequest(ctx, dest)
	}
	observeAuthenticatedRequest(context.Background(), dest)
	reports, err := o.Snapshot(now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if len(reports[0].Subjects) != 1 || reports[0].Subjects[0].Metrics.ProxyRequests != 1 || reports[0].Quality.UnmappedRequests != 1 {
		t.Fatal("source-IP attribution or missing authenticated request")
	}
	if reports[0].Complete || reports[0].Subjects[0].Metrics.FailedConnections != nil {
		t.Fatal("fabricated dial result")
	}
}
