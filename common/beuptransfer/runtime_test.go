package beuptransfer

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

type controlFixture struct {
	commands []Command
	probes   []ProbeStatus
	polls    int
	failure  error
}

func (c *controlFixture) Poll(context.Context, string) ([]Command, error) {
	c.polls++
	return c.commands, c.failure
}
func (c *controlFixture) Probe(_ context.Context, _ Command, s ProbeStatus) error {
	c.probes = append(c.probes, s)
	return c.failure
}

type drainFixture struct {
	proofs []DrainProof
	fail   bool
}

func (d *drainFixture) Report(_ context.Context, c string, p DrainProof) (DrainAck, error) {
	d.proofs = append(d.proofs, p)
	if d.fail {
		return DrainAck{}, errors.New("response lost")
	}
	return DrainAck{p.Request.ID, p.Scope, p.Epoch, c, p.Receipt}, nil
}
func commandFixture(kind string, req DrainRequest) Command {
	c := Command{kind, req, "vless_42", testEpoch, strings.Repeat("f", 32), nil}
	if kind == "probe" {
		id := strings.Repeat("e", 32)
		c.ProofID = &id
	}
	return c
}

func TestRuntimeProbeNeverDisconnects(t *testing.T) {
	for _, mode := range []string{"idle", "active", "incomplete", "wrong-epoch", "poisoned", "journal-full", "retired-identity", "offline"} {
		t.Run(mode, func(t *testing.T) {
			box, _, receiver := setup(t)
			a, req := driver()
			c := &controlFixture{commands: []Command{commandFixture("probe", req)}}
			d := &drainFixture{}
			r, err := NewRuntime("vless_42", testEpoch, box, a, c, d)
			if err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "active":
				a.status.Outstanding = 2
			case "incomplete":
				a.status.TrackingReady = false
			case "wrong-epoch":
				a.status.Epoch = strings.Repeat("2", 32)
			case "poisoned":
				box.poisoned = true
			case "journal-full":
				for n := 0; n < 1000; n++ {
					id := strings.Repeat("0", 28) + strings.Repeat("a", 4)
					id = id[:28] + fmtHex(n)
					box.state.Drains[id] = drainRecord{Request: DrainRequest{id, Identity{int64(n + 100), testCredential}}}
				}
			case "retired-identity":
				other := req
				other.ID = strings.Repeat("4", 32)
				box.state.Drains[other.ID] = drainRecord{Request: other}
			case "offline":
				receiver.offline = true
			}
			err = r.Step(ctx)
			if a.calls != 0 || len(d.proofs) != 0 {
				t.Fatal("probe disconnected a user")
			}
			if mode == "wrong-epoch" || mode == "offline" || mode == "poisoned" {
				if err == nil || len(c.probes) != 0 {
					t.Fatal("unverified runtime sent capability")
				}
				return
			}
			if err != nil || len(c.probes) != 1 {
				t.Fatal(err, "missing observation")
			}
			p := c.probes[0]
			if mode == "idle" && !p.TrackingReady {
				t.Fatal("idle not observed")
			}
			if mode == "active" && p.Outstanding != 2 {
				t.Fatal("active connections hidden")
			}
			if (mode == "incomplete" || mode == "journal-full" || mode == "retired-identity") && p.TrackingReady {
				t.Fatal("incomplete scope marked ready")
			}
		})
	}
}
func fmtHex(n int) string {
	const digits = "0123456789abcdef"
	return string([]byte{digits[n>>12&15], digits[n>>8&15], digits[n>>4&15], digits[n&15]})
}

func TestRuntimeDrainPersistsAndRetriesFinalReceipt(t *testing.T) {
	box, _, receiver := setup(t)
	a, req := driver()
	c := &controlFixture{commands: []Command{commandFixture("drain", req)}}
	d := &drainFixture{fail: true}
	r, _ := NewRuntime("vless_42", testEpoch, box, a, c, d)
	if r.Step(ctx) == nil || len(d.proofs) != 1 || box.state.Drains[req.ID].Proof == nil || !a.status.RejectNew {
		t.Fatal("lost final response did not preserve fence/proof")
	}
	d.fail = false
	if err := r.Step(ctx); err != nil {
		t.Fatal(err)
	}
	if receiver.up != 70 || receiver.down != 80 || len(d.proofs) != 2 || d.proofs[0] != d.proofs[1] {
		t.Fatal("retry double counted or rebound proof")
	}
	a.rows[0].Upload++
	if err := r.Step(ctx); err == nil {
		t.Fatal("late usage silently accepted")
	}
}
func TestRuntimeChecksWholeCommandBatchBeforeDisconnect(t *testing.T) {
	for _, mode := range []string{"duplicate", "scope", "epoch", "challenge", "unknown-kind", "proof-on-drain"} {
		t.Run(mode, func(t *testing.T) {
			box, _, _ := setup(t)
			a, req := driver()
			first := commandFixture("drain", req)
			bad := first
			bad.Request.ID = strings.Repeat("9", 32)
			switch mode {
			case "duplicate":
				bad = first
			case "scope":
				bad.Scope = "other"
			case "epoch":
				bad.Epoch = strings.Repeat("2", 32)
			case "challenge":
				bad.Challenge = ""
			case "unknown-kind":
				bad.Kind = "delete"
			case "proof-on-drain":
				s := strings.Repeat("d", 32)
				bad.ProofID = &s
			}
			c := &controlFixture{commands: []Command{first, bad}}
			d := &drainFixture{}
			r, _ := NewRuntime("vless_42", testEpoch, box, a, c, d)
			if r.Step(ctx) == nil || a.calls != 0 || len(d.proofs) != 0 {
				t.Fatal("partially executed invalid command batch")
			}
		})
	}
}
func TestRuntimeCyclesAreSerialized(t *testing.T) {
	box, _, receiver := setup(t)
	a, _ := driver()
	c := &controlFixture{}
	r, _ := NewRuntime("vless_42", testEpoch, box, a, c, &drainFixture{})
	var wg sync.WaitGroup
	for n := 0; n < 8; n++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if e := r.Step(ctx); e != nil {
				t.Error(e)
			}
		}()
	}
	wg.Wait()
	if receiver.up != 70 || receiver.down != 80 || c.polls != 8 {
		t.Fatal("overlapping cycles altered accounting")
	}
}
func TestHTTPControlRequiresScopedCommands(t *testing.T) {
	for _, mode := range []string{"valid", "wrong-scope", "wrong-epoch", "duplicate", "wrong-purpose", "unknown-field", "unsigned"} {
		t.Run(mode, func(t *testing.T) {
			key := bytes.Repeat([]byte{9}, 32)
			c, _ := NewHTTPControl("https://panel.example.invalid/control", "https://panel.example.invalid/probe", "vless_42", key)
			c.poll.now = func() time.Time { return time.Unix(1800000000, 0) }
			_, req := driver()
			cmd := commandFixture("probe", req)
			c.poll.client.Transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
				body, _ := io.ReadAll(request.Body)
				at, nonce := request.Header.Get("X-Beup-Time"), request.Header.Get("X-Beup-Nonce")
				if request.Header.Get("X-Beup-Signature") != wirePurposeMAC("request", "control", "vless_42", at, nonce, body, key) {
					t.Fatal("wrong request domain")
				}
				commands := []Command{cmd}
				switch mode {
				case "wrong-scope":
					commands[0].Scope = "elsewhere"
				case "wrong-epoch":
					commands[0].Epoch = strings.Repeat("2", 32)
				case "duplicate":
					commands = append(commands, cmd)
				}
				response, _ := json.Marshal(map[string]any{"scope": "vless_42", "epoch": testEpoch, "commands": commands})
				if mode == "unknown-field" {
					response = append(response[:len(response)-1], []byte(",\"extra\":true}")...)
				}
				purpose := "control"
				if mode == "wrong-purpose" {
					purpose = "traffic"
				}
				h := http.Header{}
				h.Set("X-Beup-Time", at)
				h.Set("X-Beup-Nonce", nonce)
				if mode != "unsigned" {
					h.Set("X-Beup-Signature", wirePurposeMAC("response", purpose, "vless_42", at, nonce, response, key))
				}
				return &http.Response{StatusCode: 200, Header: h, Body: io.NopCloser(bytes.NewReader(response)), Request: request}, nil
			})
			got, err := c.Poll(ctx, testEpoch)
			if mode == "valid" {
				if err != nil || len(got) != 1 {
					t.Fatal(err)
				}
			} else if err == nil {
				t.Fatal("untrusted control accepted")
			}
		})
	}
}

func TestHTTPProbeBindsAcknowledgement(t *testing.T) {
	for _, mode := range []string{"valid", "proof", "transfer", "challenge", "epoch", "unsigned", "extra"} {
		t.Run(mode, func(t *testing.T) {
			key := bytes.Repeat([]byte{9}, 32)
			c, _ := NewHTTPControl("https://panel.example.invalid/control", "https://panel.example.invalid/probe", "vless_42", key)
			c.probe.now = func() time.Time { return time.Unix(1800000000, 0) }
			_, req := driver()
			cmd := commandFixture("probe", req)
			c.probe.client.Transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
				body, _ := io.ReadAll(request.Body)
				at, nonce := request.Header.Get("X-Beup-Time"), request.Header.Get("X-Beup-Nonce")
				if request.Header.Get("X-Beup-Signature") != wirePurposeMAC("request", "probe", "vless_42", at, nonce, body, key) {
					t.Fatal("probe domain mismatch")
				}
				ack := ProbeAck{cmd.Scope, cmd.Epoch, cmd.Request.ID, *cmd.ProofID, cmd.Challenge}
				switch mode {
				case "proof":
					ack.ProofID = strings.Repeat("8", 32)
				case "transfer":
					ack.TransferID = strings.Repeat("8", 32)
				case "challenge":
					ack.Challenge = strings.Repeat("8", 32)
				case "epoch":
					ack.Epoch = strings.Repeat("8", 32)
				}
				response, _ := json.Marshal(ack)
				if mode == "extra" {
					response = append(response[:len(response)-1], []byte(",\"extra\":true}")...)
				}
				h := http.Header{}
				h.Set("X-Beup-Time", at)
				h.Set("X-Beup-Nonce", nonce)
				if mode != "unsigned" {
					h.Set("X-Beup-Signature", wirePurposeMAC("response", "probe", "vless_42", at, nonce, response, key))
				}
				return &http.Response{StatusCode: 200, Header: h, Body: io.NopCloser(bytes.NewReader(response)), Request: request}, nil
			})
			err := c.Probe(ctx, cmd, ProbeStatus{TrackingReady: true, Bindings: 1})
			if (mode == "valid") != (err == nil) {
				t.Fatal(mode, err)
			}
		})
	}
}
