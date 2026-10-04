package xray

import (
	"context"
	observer "github.com/InazumaV/V2bX/common/beupobserve"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/transport/internet"
	"net"
	"testing"
	"time"
)

func TestActualTCPDialOutcomesAreAuthenticatedAndClassified(t *testing.T) {
	now := time.Unix(1800000000, 0)
	o, e := observer.New(observer.Config{Node: "synthetic-jp", IdentityRevision: "synthetic-v1", Bindings: map[string]map[int]string{"a": {2: "00000000000000000000000000000002"}}, Now: func() time.Time { return now }, TCPDialMetrics: true})
	if e != nil {
		t.Fatal(e)
	}
	o.Bind("a", "synthetic-label", 2)
	observer.Set(o)
	defer observer.Set(nil)
	internet.SetDialOutcomeHandler(recordAuthenticatedDial)
	l, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	dest := xnet.TCPDestination(xnet.ParseAddress("127.0.0.1"), xnet.Port(l.Addr().(*net.TCPAddr).Port))
	ctx := session.ContextWithInbound(context.Background(), &session.Inbound{Name: "vless", Tag: "a", User: &protocol.MemoryUser{Email: "synthetic-label"}})
	dialer := &internet.DefaultSystemDialer{}
	c, e := dialer.Dial(ctx, nil, dest, nil)
	if e != nil {
		t.Fatal(e)
	}
	c.Close()
	l.Close()
	if c, e = dialer.Dial(ctx, nil, dest, nil); e == nil {
		c.Close()
		t.Fatal("closed loopback port unexpectedly accepted")
	}
	// The same actual refusal without an authenticated inbound is not
	// assigned to an arbitrary customer (or to the last authenticated user).
	_, _ = dialer.Dial(context.Background(), nil, dest, nil)
	r, e := o.Snapshot(now.Add(time.Minute))
	if e != nil || len(r) != 1 || len(r[0].Subjects) != 1 {
		t.Fatal(r, e)
	}
	d := r[0].Subjects[0].Metrics.TCPDial
	if d == nil || d.Attempts != 2 || d.Succeeded != 1 || d.Refused != 1 || d.OtherErrors != 0 || d.MaxRefusedTargetPorts != 1 {
		t.Fatal("not actual classified TCP outcomes", d)
	}
}
