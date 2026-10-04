package beuptransfer

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestHTTPDrainReceiptBinding(t *testing.T) {
	for _, mode := range []string{"valid", "wrong-transfer", "wrong-challenge", "wrong-epoch", "wrong-sequence", "wrong-purpose", "extra-field", "unsigned"} {
		t.Run(mode, func(t *testing.T) {
			key := bytes.Repeat([]byte{9}, 32)
			r, err := NewHTTPDrainReporter("https://panel.example.invalid/drain", "vless-100", key)
			if err != nil {
				t.Fatal(err)
			}
			r.wire.now = func() time.Time { return time.Unix(1800000000, 0) }
			id := Identity{123, strings.Repeat("b", 64)}
			request := DrainRequest{strings.Repeat("f", 32), id}
			epoch := strings.Repeat("a", 32)
			challenge := strings.Repeat("e", 32)
			p := DrainProof{Request: request, Scope: r.wire.scope, Epoch: epoch, Final: Sample{id.UID, id.Credential, 10, 20}, Receipt: Ack{r.wire.scope, epoch, 7, strings.Repeat("d", 64)}}
			r.wire.client.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
				body, _ := io.ReadAll(req.Body)
				at, nonce := req.Header.Get("X-Beup-Time"), req.Header.Get("X-Beup-Nonce")
				if req.Header.Get("X-Beup-Signature") != wirePurposeMAC("request", "drain", r.wire.scope, at, nonce, body, key) {
					t.Fatal("drain request domain separation")
				}
				ack := DrainAck{request.ID, p.Scope, epoch, challenge, p.Receipt}
				switch mode {
				case "wrong-transfer":
					ack.TransferID = strings.Repeat("0", 32)
				case "wrong-challenge":
					ack.Challenge = strings.Repeat("0", 32)
				case "wrong-epoch":
					ack.Epoch = strings.Repeat("0", 32)
				case "wrong-sequence":
					ack.Receipt.Sequence++
				}
				response, _ := json.Marshal(ack)
				if mode == "extra-field" {
					response = append(response[:len(response)-1], []byte(",\"ok\":true}")...)
				}
				purpose := "drain"
				if mode == "wrong-purpose" {
					purpose = "traffic"
				}
				h := http.Header{}
				h.Set("X-Beup-Time", at)
				h.Set("X-Beup-Nonce", nonce)
				h.Set("X-Beup-Signature", wirePurposeMAC("response", purpose, r.wire.scope, at, nonce, response, key))
				if mode == "unsigned" {
					h.Del("X-Beup-Signature")
				}
				return &http.Response{StatusCode: 200, Header: h, Body: io.NopCloser(bytes.NewReader(response)), Request: req}, nil
			})
			_, err = r.Report(context.Background(), challenge, p)
			if mode == "valid" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil {
				t.Fatal("rebound proof accepted")
			}
		})
	}
}
