package dispatcher

import (
	"context"
	"sync"

	"github.com/InazumaV/V2bX/common/beuptransfer"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/task"
)

func NewTransferCredentialTracker(a *beuptransfer.GuardAdapter) *session.CredentialTracker {
	return &session.CredentialTracker{Begin: func(ctx context.Context, command byte) (context.Context, func(), error) {
		in := session.InboundFromContext(ctx)
		if in == nil || in.Name != "vless" || in.User == nil || in.Conn == nil {
			a.NoteCoverageFailure()
			return ctx, func() {}, nil
		}
		// TCP, UDP and Mux have owned child lifecycles. Reverse tunnels remain unsupported.
		if command != byte(protocol.RequestCommandTCP) && command != byte(protocol.RequestCommandUDP) && command != byte(protocol.RequestCommandMux) {
			a.NoteIdentityCoverageFailure(in.User.Email)
		}
		next, cancel := context.WithCancel(ctx)
		var once sync.Once
		closeFlow := func() { once.Do(func() { cancel(); _ = in.Conn.Close() }) }
		finish, err := a.Track(in.User.Email, closeFlow)
		if err != nil {
			closeFlow()
			return ctx, func() {}, err
		}
		next = task.WithLifecycle(next, transferTasks{a, in.User.Email, closeFlow})
		return next, func() { cancel(); finish() }, nil
	}}
}
