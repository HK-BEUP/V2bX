package dispatcher

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/InazumaV/V2bX/common/beupguard"
	"github.com/InazumaV/V2bX/common/beuptransfer"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
)

func TestAuthenticatedTransferLifetime(t *testing.T) {
	for _, command := range []byte{1, 3, 4} {
		t.Run(map[byte]string{1: "idle-tcp", 3: "idle-mux", 4: "unsupported-reverse"}[command], func(t *testing.T) {
			a, err := beuptransfer.NewGuardAdapter("auth", strings.Repeat("a", 32), func(context.Context) ([]beuptransfer.Sample, error) { return nil, nil })
			if err != nil {
				t.Fatal(err)
			}
			credential := "00000000-0000-4000-8000-000000000002"
			if err = a.Bind("source", 2, credential); err != nil {
				t.Fatal(err)
			}
			if err = a.Bind("other", 3, "00000000-0000-4000-8000-000000000003"); err != nil {
				t.Fatal(err)
			}
			server, peer := net.Pipe()
			defer server.Close()
			defer peer.Close()
			ctx := session.ContextWithInbound(context.Background(), &session.Inbound{Tag: "auth", Name: "vless", User: &protocol.MemoryUser{Email: "source"}, Conn: server})
			_, finish, err := NewTransferCredentialTracker(a).Begin(ctx, command)
			if err != nil {
				t.Fatal(err)
			}
			id := beuptransfer.Identity{UID: 2, Credential: beupguard.CredentialDigest(credential)}
			status, _ := a.Inspect(context.Background(), id)
			if status.Outstanding != 1 {
				t.Fatal("authenticated idle handler untracked")
			}
			if (command == 4) == status.TrackingReady {
				t.Fatal("unsupported command must block only its identity")
			}
			other, _ := a.Inspect(context.Background(), beuptransfer.Identity{UID: 3, Credential: beupguard.CredentialDigest("00000000-0000-4000-8000-000000000003")})
			if !other.TrackingReady {
				t.Fatal("unrelated identity lost coverage")
			}
			if err = a.Fence(context.Background(), id); err != nil {
				t.Fatal(err)
			}
			peer.SetReadDeadline(time.Now().Add(time.Second))
			if _, err = peer.Read(make([]byte, 1)); err == nil {
				t.Fatal("idle connection stayed open")
			}
			status, _ = a.Inspect(context.Background(), id)
			if status.Outstanding != 1 {
				t.Fatal("close alone marked handler finished")
			}
			finish()
			status, _ = a.Inspect(context.Background(), id)
			if status.Outstanding != 0 {
				t.Fatal("handler finish not observed")
			}
		})
	}
}
