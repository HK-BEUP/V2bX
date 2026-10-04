package dispatcher

import (
	"context"
	"sync"

	"github.com/InazumaV/V2bX/common/beuptransfer"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/transport"
)

type transferTasks struct {
	adapter *beuptransfer.GuardAdapter
	label   string
	close   func()
}

func (t transferTasks) Begin() (func(), error) { return t.adapter.Track(t.label, t.close) }

// Before sniffing and before attaching counters; the parent and task.Run's
// parallel children must all finish before final accounting can be accepted.
func beginTransferDispatch(ctx context.Context, destination net.Destination, link *transport.Link) (context.Context, func(), error) {
	in := session.InboundFromContext(ctx)
	if in == nil {
		return ctx, func() {}, nil
	}
	a := beuptransfer.ForTag(in.Tag)
	if a == nil {
		return ctx, func() {}, nil
	}
	if in.Name != "vless" || in.User == nil || in.Conn == nil {
		a.NoteCoverageFailure()
		return ctx, func() {}, nil
	}
	next, cancel := context.WithCancel(ctx)
	var once sync.Once
	closeFlow := func() {
		once.Do(func() { cancel(); _ = in.Conn.Close(); common.Interrupt(link.Reader); common.Interrupt(link.Writer) })
	}
	finish, err := a.Track(in.User.Email, closeFlow)
	if err != nil {
		closeFlow()
		return ctx, func() {}, err
	}
	next = task.WithLifecycle(next, transferTasks{a, in.User.Email, closeFlow})
	return next, func() { cancel(); finish() }, nil
}
