package beuptransfer

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestPHPWireCompatibility(t *testing.T) {
	script := os.Getenv("BEUP_TRANSFER_PHP_QA")
	if script == "" {
		t.Skip("explicit local synthetic PHP probe required")
	}
	r, err := NewHTTPReceiver("https://panel.example.invalid/traffic", "vless-100", bytes.Repeat([]byte{9}, 32))
	if err != nil {
		t.Fatal(err)
	}
	r.now = func() time.Time { return time.Unix(1800000000, 0) }
	r.client.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		body, _ := io.ReadAll(req.Body)
		input, _ := json.Marshal(map[string]any{"body": string(body), "headers": map[string]string{"time": req.Header.Get("X-Beup-Time"), "nonce": req.Header.Get("X-Beup-Nonce"), "signature": req.Header.Get("X-Beup-Signature")}})
		cmd := exec.CommandContext(req.Context(), "php", script)
		cmd.Stdin = bytes.NewReader(input)
		output, err := cmd.CombinedOutput()
		if err != nil {
			return nil, fmt.Errorf("PHP synthetic probe failed: %s", output)
		}
		var wire map[string]string
		if err = json.Unmarshal(output, &wire); err != nil {
			return nil, err
		}
		header := http.Header{}
		header.Set("X-Beup-Time", wire["time"])
		header.Set("X-Beup-Nonce", wire["nonce"])
		header.Set("X-Beup-Signature", wire["signature"])
		return &http.Response{StatusCode: 200, Header: header, Body: io.NopCloser(strings.NewReader(wire["body"])), Request: req}, nil
	})
	for _, entries := range [][]Sample{{}, {{UID: 9007199254740993, Credential: strings.Repeat("b", 64), Upload: 9223372036854775806, Download: 123}}} {
		b := Batch{Version: 1, Scope: r.scope, Epoch: strings.Repeat("a", 32), Sequence: 9007199254740991, Entries: entries}
		b.Digest = b.Hash()
		ack, err := r.Commit(context.Background(), b)
		if err != nil || ack != ackFor(b) {
			t.Fatalf("Go/PHP signed receipt mismatch: %v", err)
		}
	}
}
