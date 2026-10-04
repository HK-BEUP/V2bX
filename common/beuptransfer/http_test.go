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

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestHTTPAuthenticatedReceipt(t *testing.T) {
	for _, mode := range []string{"valid", "lost-response", "wrong-key", "wrong-nonce", "stale", "future", "wrong-digest", "trailing", "unknown-field", "redirect", "large"} {
		t.Run(mode, func(t *testing.T) {
			key := bytes.Repeat([]byte{9}, 32)
			r, err := NewHTTPReceiver("https://panel.example.invalid/traffic", "vless-100", key)
			if err != nil {
				t.Fatal(err)
			}
			r.now = func() time.Time { return time.Unix(1800000000, 0) }
			b := Batch{Version: 1, Scope: r.scope, Epoch: strings.Repeat("a", 32), Sequence: 1, Entries: []Sample{{UID: 123, Credential: strings.Repeat("b", 64), Upload: 1, Download: 5}}}
			b.Digest = b.Hash()
			r.client.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
				body, _ := io.ReadAll(req.Body)
				at, nonce := req.Header.Get("X-Beup-Time"), req.Header.Get("X-Beup-Nonce")
				if req.Method != "POST" || req.Header.Get("X-Beup-Scope") != r.scope || req.Header.Get("X-Beup-Signature") != wireMAC("request", r.scope, at, nonce, body, key) {
					t.Fatal("request authentication")
				}
				ack := ackFor(b)
				if mode == "wrong-digest" {
					ack.Digest = strings.Repeat("c", 64)
				}
				response, _ := json.Marshal(ack)
				if mode == "trailing" {
					response = append(response, []byte("{}")...)
				}
				if mode == "unknown-field" {
					response = append(response[:len(response)-1], []byte(",\"untrusted\":true}")...)
				}
				if mode == "large" {
					response = bytes.Repeat([]byte("a"), 17000)
				}
				if mode == "wrong-nonce" {
					nonce = strings.Repeat("d", 32)
				}
				if mode == "stale" {
					at = "1799999800"
				}
				if mode == "future" {
					at = "1800000200"
				}
				secret := key
				if mode == "wrong-key" {
					secret = bytes.Repeat([]byte{7}, 32)
				}
				h := http.Header{}
				h.Set("X-Beup-Time", at)
				h.Set("X-Beup-Nonce", nonce)
				h.Set("X-Beup-Signature", wireMAC("response", r.scope, at, nonce, response, secret))
				status := 200
				if mode == "redirect" {
					status = 302
					h.Set("Location", "https://elsewhere.example.invalid/")
				}
				if mode == "lost-response" {
					status = 502
				}
				return &http.Response{StatusCode: status, Header: h, Body: io.NopCloser(bytes.NewReader(response)), Request: req}, nil
			})
			ack, err := r.Commit(context.Background(), b)
			if mode == "valid" {
				if err != nil || ack != ackFor(b) {
					t.Fatalf("%v", err)
				}
			} else if err == nil {
				t.Fatal("untrusted response accepted")
			}
		})
	}
}

func TestHTTPRejectsInsecureConfiguration(t *testing.T) {
	for _, endpoint := range []string{"http://panel.example.invalid/traffic", "https://user:pass@panel.example.invalid/traffic", "https://panel.example.invalid/traffic?secret=1", "https://panel.example.invalid/traffic#fragment"} {
		if _, err := NewHTTPReceiver(endpoint, "vless-100", bytes.Repeat([]byte{1}, 32)); err == nil {
			t.Fatal(endpoint)
		}
	}
}
