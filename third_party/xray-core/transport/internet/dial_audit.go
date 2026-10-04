package internet

import (
	"context"
	"github.com/xtls/xray-core/common/net"
	"sync/atomic"
)

// DialOutcome is emitted only after a real TCP DialContext completes. UDP
// association creation, proxy logical requests and HTTP requests are not TCP
// dial outcomes. The handler must be nonblocking and must never retain payloads.
type DialOutcome struct {
	Destination net.Destination
	Remote      net.Addr
	Error       error
}
type DialOutcomeHandler func(context.Context, DialOutcome)

var dialOutcomeHandler atomic.Pointer[DialOutcomeHandler]

// Optional and off by default. It does not replace the existing system dialer,
// DNS client, controllers, socket options, connection or return value.
func SetDialOutcomeHandler(handler DialOutcomeHandler) {
	if handler == nil {
		dialOutcomeHandler.Store(nil)
		return
	}
	dialOutcomeHandler.Store(&handler)
}
func reportDialOutcome(ctx context.Context, destination net.Destination, conn net.Conn, err error) {
	if destination.Network != net.Network_TCP {
		return
	}
	h := dialOutcomeHandler.Load()
	if h == nil {
		return
	}
	outcome := DialOutcome{Destination: destination, Error: err}
	if conn != nil {
		outcome.Remote = conn.RemoteAddr()
	}
	(*h)(ctx, outcome)
}
