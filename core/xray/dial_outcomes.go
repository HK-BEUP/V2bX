package xray

import (
	"context"
	"errors"
	observer "github.com/InazumaV/V2bX/common/beupobserve"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/transport/internet"
	"net"
	"syscall"
)

func init() { internet.SetDialOutcomeHandler(recordAuthenticatedDial) }
func recordAuthenticatedDial(ctx context.Context, result internet.DialOutcome) {
	in := session.InboundFromContext(ctx)
	if in == nil || in.Name != "vless" || in.User == nil || in.User.Email == "" {
		return
	}
	address := result.Destination.Address.String()
	port := uint16(result.Destination.Port)
	outcome := observer.DialOtherError
	if remote, ok := result.Remote.(*net.TCPAddr); ok && remote.IP != nil {
		address = remote.IP.String()
		port = uint16(remote.Port)
	}
	if result.Error == nil {
		outcome = observer.DialSucceeded
	} else {
		var op *net.OpError
		actualIP := false
		if errors.As(result.Error, &op) {
			if remote, ok := op.Addr.(*net.TCPAddr); ok && remote.IP != nil {
				address = remote.IP.String()
				port = uint16(remote.Port)
				actualIP = true
			}
		}
		var ne net.Error
		switch {
		case errors.Is(result.Error, context.Canceled):
			outcome = observer.DialCancelled
		case errors.Is(result.Error, syscall.ECONNREFUSED) && actualIP:
			outcome = observer.DialRefused
		case errors.Is(result.Error, context.DeadlineExceeded):
			outcome = observer.DialTimedOut
		case errors.As(result.Error, &ne) && ne.Timeout():
			outcome = observer.DialTimedOut
		}
	}
	observer.RecordDial(in.Tag, in.User.Email, address, port, outcome)
}
