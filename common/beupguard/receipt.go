package beupguard

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
)

// Receipt keys are node-local and independent from observation signing keys.
// The relay must obtain the acknowledgement from the private Unix controller.
// These helpers do not enable a listener, issue commands or generate a key.
const ReceiptDomain = "BEUP-ACCOUNT-ISOLATION-RECEIPT-V1\n"

type Receipt struct {
	Version       int             `json:"version"`
	Node          string          `json:"node"`
	Challenge     string          `json:"challenge"`
	CommandDigest string          `json:"command_digest"`
	ObservedAt    int64           `json:"observed_at"`
	Ack           Acknowledgement `json:"ack"`
}

func CommandDigest(e Envelope) string {
	h := sha256.Sum256([]byte(e.Payload + "\n" + e.Signature))
	return hex.EncodeToString(h[:])
}

func SignReceipt(r Receipt, key ed25519.PrivateKey) (Envelope, error) {
	if len(key) != ed25519.PrivateKeySize || r.Version != 1 || r.Node != r.Ack.Node || !regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`).MatchString(r.Node) || !regexp.MustCompile(`^[a-f0-9]{32}$`).MatchString(r.Challenge) || !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(r.CommandDigest) || r.ObservedAt < 1 {
		return Envelope{}, errors.New("invalid isolation receipt")
	}
	p, e := json.Marshal(r)
	if e != nil || len(p) > 2048 {
		return Envelope{}, errors.New("invalid isolation receipt payload")
	}
	return Envelope{Payload: base64.StdEncoding.EncodeToString(p), Signature: hex.EncodeToString(ed25519.Sign(key, append([]byte(ReceiptDomain), p...)))}, nil
}
