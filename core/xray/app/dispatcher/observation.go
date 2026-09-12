package dispatcher

import (
	"context"
	beupobserve "github.com/InazumaV/V2bX/common/beupobserve"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
)

// Called once at each dispatch entry, before policy/route/dial. These are logical
// authenticated requests, not successful network connections or HTTP requests.
func observeAuthenticatedRequest(ctx context.Context, destination net.Destination) {
	if !destination.IsValid() {
		return
	}
	in := session.InboundFromContext(ctx)
	if in == nil || in.User == nil || in.User.Email == "" {
		return
	}
	beupobserve.Record(in.Tag, in.User.Email, destination.Network.SystemString(), destination.Address.String(), uint16(destination.Port))
}
