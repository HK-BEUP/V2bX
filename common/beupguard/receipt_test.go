package beupguard

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestReceiptProtocol(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	r := Receipt{Version: 1, Node: "synthetic-japan", Challenge: strings.Repeat("3", 32), CommandDigest: strings.Repeat("4", 64), ObservedAt: 1800000060, Ack: Acknowledgement{Node: "synthetic-japan"}}
	e, err := SignReceipt(r, key)
	if err != nil {
		t.Fatal(err)
	}
	if len(e.Signature) != 128 || len(CommandDigest(Envelope{Payload: "a", Signature: "b"})) != 64 {
		t.Fatal("invalid encoding")
	}
	for _, mutate := range []func(*Receipt){func(r *Receipt) { r.Node = "synthetic-hk" }, func(r *Receipt) { r.Challenge = "bad" }, func(r *Receipt) { r.CommandDigest = "bad" }, func(r *Receipt) { r.Version = 2 }, func(r *Receipt) { r.ObservedAt = 0 }} {
		bad := r
		mutate(&bad)
		if _, err := SignReceipt(bad, key); err == nil {
			t.Fatal("invalid receipt accepted")
		}
	}
	if _, err := SignReceipt(r, nil); err == nil {
		t.Fatal("invalid key")
	}
	_ = pub
}

// Optional cross-language compatibility check; never a runtime PHP dependency.
func TestPHPReceiptInterop(t *testing.T) {
	path := os.Getenv("BEUP_PILOT_PHP_TEST")
	if path == "" {
		t.Skip("explicit local PHP test script required")
	}
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	ack := Acknowledgement{Node: "synthetic-japan", Sequence: 1, LeaseID: strings.Repeat("a", 32), State: "isolated", RejectNew: true, ExistingClosed: true, ExpiresAt: 1800000660, TrackingReady: true, IdentityBound: true, CurrentLeaseID: strings.Repeat("a", 32)}
	digest := strings.Repeat("4", 64)
	r, err := SignReceipt(Receipt{Version: 1, Node: ack.Node, Challenge: strings.Repeat("3", 32), CommandDigest: digest, ObservedAt: 1800000060, Ack: ack}, key)
	if err != nil {
		t.Fatal(err)
	}
	input, _ := json.Marshal(map[string]any{"receipt": r, "public_key": hex.EncodeToString(pub), "command_digest": digest})
	cmd := exec.Command("php", path, "interop")
	cmd.Stdin = bytes.NewReader(input)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("PHP checks failed: %v %s", err, output)
	}
	var result struct {
		OK      bool     `json:"ok"`
		Checks  int      `json:"checks"`
		Command Envelope `json:"command"`
		Public  string   `json:"command_public_key"`
	}
	if json.Unmarshal(output, &result) != nil || !result.OK || result.Checks < 30 {
		t.Fatal("invalid PHP check result")
	}
	commandPublic, err := hex.DecodeString(result.Public)
	if err != nil {
		t.Fatal(err)
	}
	c, err := verifyEnvelope(result.Command, ack.Node, ed25519.PublicKey(commandPublic))
	if err != nil {
		t.Fatal("PHP command rejected by Go", err)
	}
	if c.Lease.Identity.UID != 42 || c.Lease.ExpiresAt-c.Lease.StartedAt != 600 || c.Lease.Manual {
		t.Fatal("PHP command changed scope or duration")
	}
	t.Logf("PHP signed command / Go signed receipt interoperable; PHP checks=%d", result.Checks)
}
