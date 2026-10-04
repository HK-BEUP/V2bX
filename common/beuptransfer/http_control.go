package beuptransfer

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
)

type Command struct {
	Kind      string       `json:"kind"`
	Request   DrainRequest `json:"request"`
	Scope     string       `json:"scope"`
	Epoch     string       `json:"epoch"`
	Challenge string       `json:"challenge"`
	ProofID   *string      `json:"proof_id"`
}

func (c Command) valid(scope, epoch string) bool {
	if c.Scope != scope || c.Epoch != epoch || !validHex(epoch, 16) || !validHex(c.Challenge, 16) || !validRequest(c.Request) {
		return false
	}
	return (c.Kind == "probe" && c.ProofID != nil && validHex(*c.ProofID, 16)) || (c.Kind == "drain" && c.ProofID == nil)
}

type ProbeStatus struct {
	TrackingReady bool `json:"tracking_ready"`
	RejectNew     bool `json:"reject_new"`
	Bindings      int  `json:"bindings"`
	Outstanding   int  `json:"outstanding"`
}
type ProbeAck struct {
	Scope      string `json:"scope"`
	Epoch      string `json:"epoch"`
	TransferID string `json:"transfer_id"`
	ProofID    string `json:"proof_id"`
	Challenge  string `json:"challenge"`
}
type HTTPControl struct{ poll, probe *HTTPReceiver }

func NewHTTPControl(controlEndpoint, probeEndpoint, scope string, key []byte) (*HTTPControl, error) {
	poll, err := NewHTTPReceiver(controlEndpoint, scope, key)
	if err != nil {
		return nil, err
	}
	probe, err := NewHTTPReceiver(probeEndpoint, scope, key)
	if err != nil {
		return nil, err
	}
	return &HTTPControl{poll, probe}, nil
}
func strictResponse(body []byte, target any) error {
	d := json.NewDecoder(bytes.NewReader(body))
	d.DisallowUnknownFields()
	if d.Decode(target) != nil || d.Decode(new(any)) != io.EOF {
		return errors.New("invalid node control response")
	}
	return nil
}
func (c *HTTPControl) Poll(ctx context.Context, epoch string) ([]Command, error) {
	if !validHex(epoch, 16) {
		return nil, ErrEpoch
	}
	body, _ := json.Marshal(struct {
		Scope string `json:"scope"`
		Epoch string `json:"epoch"`
	}{c.poll.scope, epoch})
	response, err := c.poll.post(ctx, "control", body)
	if err != nil {
		return nil, err
	}
	var wire struct {
		Scope    string    `json:"scope"`
		Epoch    string    `json:"epoch"`
		Commands []Command `json:"commands"`
	}
	if strictResponse(response, &wire) != nil || wire.Scope != c.poll.scope || wire.Epoch != epoch || wire.Commands == nil || len(wire.Commands) > 32 {
		return nil, errors.New("node commands mismatch")
	}
	seen := map[string]bool{}
	for _, cmd := range wire.Commands {
		if !cmd.valid(c.poll.scope, epoch) || seen[cmd.Request.ID] {
			return nil, errors.New("invalid or duplicate node command")
		}
		seen[cmd.Request.ID] = true
	}
	return wire.Commands, nil
}
func (c *HTTPControl) Probe(ctx context.Context, cmd Command, s ProbeStatus) error {
	if !cmd.valid(c.probe.scope, cmd.Epoch) || cmd.Kind != "probe" || s.Bindings < 0 || s.Bindings > 10000 || s.Outstanding < 0 || s.Outstanding > 10000000 {
		return ErrCoverage
	}
	body, err := json.Marshal(struct {
		Command Command     `json:"command"`
		Status  ProbeStatus `json:"status"`
	}{cmd, s})
	if err != nil {
		return err
	}
	response, err := c.probe.post(ctx, "probe", body)
	if err != nil {
		return err
	}
	var ack ProbeAck
	if strictResponse(response, &ack) != nil || ack != (ProbeAck{cmd.Scope, cmd.Epoch, cmd.Request.ID, *cmd.ProofID, cmd.Challenge}) {
		return errors.New("node probe acknowledgement mismatch")
	}
	return nil
}
