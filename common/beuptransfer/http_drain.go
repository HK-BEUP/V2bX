package beuptransfer

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
)

type DrainAck struct {
	TransferID string `json:"transfer_id"`
	Scope      string `json:"scope"`
	Epoch      string `json:"epoch"`
	Challenge  string `json:"challenge"`
	Receipt    Ack    `json:"receipt"`
}

type HTTPDrainReporter struct{ wire *HTTPReceiver }

func NewHTTPDrainReporter(endpoint, scope string, key []byte) (*HTTPDrainReporter, error) {
	wire, err := NewHTTPReceiver(endpoint, scope, key)
	if err != nil {
		return nil, err
	}
	return &HTTPDrainReporter{wire: wire}, nil
}

// Report must be called with a freshly rechecked Outbox.Drain result. It does
// not close sessions or manufacture proof, and never reuses an old signature.
func (r *HTTPDrainReporter) Report(ctx context.Context, challenge string, p DrainProof) (DrainAck, error) {
	if !validHex(challenge, 16) || !validRequest(p.Request) || p.Scope != r.wire.scope || !validHex(p.Epoch, 16) || p.Final.UID != p.Request.Identity.UID || p.Final.Credential != p.Request.Identity.Credential || p.Final.Upload < 0 || p.Final.Download < 0 || p.Receipt.Scope != p.Scope || p.Receipt.Epoch != p.Epoch || p.Receipt.Sequence < 1 || p.Receipt.Sequence > 1<<53 || !validHex(p.Receipt.Digest, 32) {
		return DrainAck{}, errors.New("invalid identity-bound drain proof")
	}
	body, err := json.Marshal(struct {
		Challenge string     `json:"challenge"`
		Proof     DrainProof `json:"proof"`
	}{challenge, p})
	if err != nil {
		return DrainAck{}, err
	}
	response, err := r.wire.post(ctx, "drain", body)
	if err != nil {
		return DrainAck{}, err
	}
	var ack DrainAck
	decoder := json.NewDecoder(bytes.NewReader(response))
	decoder.DisallowUnknownFields()
	expected := DrainAck{p.Request.ID, p.Scope, p.Epoch, challenge, p.Receipt}
	if decoder.Decode(&ack) != nil || decoder.Decode(new(any)) != io.EOF || ack != expected {
		return DrainAck{}, errors.New("drain receipt mismatch")
	}
	return ack, nil
}
