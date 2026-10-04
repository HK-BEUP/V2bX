package xray

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/proxy"
)

// Test the direction-specific readiness independently from REALITY's unsafe
// TLS internals, so its ordering and write-failure behavior can run under race.
func TestVisionDownlinkReadiness(t *testing.T) {
	for _, tc := range []struct {
		name                                      string
		uplink, transition, writeFails, wantReady bool
	}{
		{"successful-downlink", false, true, false, true},
		{"failed-downlink", false, true, true, false},
		{"uplink-is-not-downlink", true, true, false, false},
		{"not-transitioned", false, false, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := &session.Inbound{CanSpliceCopy: 1, VisionDownlinkReady: new(atomic.Bool)}
			ctx := session.ContextWithInbound(context.Background(), in)
			state := &proxy.TrafficState{}
			state.Inbound.DownlinkWriterDirectCopy = tc.transition
			state.Outbound.UplinkWriterDirectCopy = tc.transition
			conn := &readinessConn{write: func(p []byte) (int, error) {
				if in.VisionDownlinkReady.Load() {
					t.Error("published before write completed")
				}
				if tc.writeFails {
					return 0, errors.New("synthetic write failure")
				}
				return len(p), nil
			}}
			w := proxy.NewVisionWriter(buf.NewWriter(conn), state, tc.uplink, ctx, conn, nil, nil)
			b := buf.New()
			b.WriteString("synthetic payload")
			err := w.WriteMultiBuffer(buf.MultiBuffer{b})
			if (err != nil) != tc.writeFails {
				t.Fatalf("write failure=%v err=%v", tc.writeFails, err)
			}
			if got := in.VisionDownlinkReady.Load(); got != tc.wantReady {
				t.Fatalf("ready=%v want=%v", got, tc.wantReady)
			}
		})
	}
}

type readinessConn struct{ write func([]byte) (int, error) }

func (c *readinessConn) Write(b []byte) (int, error)    { return c.write(b) }
func (*readinessConn) Read([]byte) (int, error)         { return 0, net.ErrClosed }
func (*readinessConn) Close() error                     { return nil }
func (*readinessConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (*readinessConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (*readinessConn) SetDeadline(time.Time) error      { return nil }
func (*readinessConn) SetReadDeadline(time.Time) error  { return nil }
func (*readinessConn) SetWriteDeadline(time.Time) error { return nil }
