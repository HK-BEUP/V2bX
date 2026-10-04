package panel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"

	"github.com/InazumaV/V2bX/common/beuptransfer"
	"github.com/go-resty/resty/v2"
)

var ErrLegacySettlementBusy = errors.New("legacy settlement temporarily busy")

func (c *Client) EnableLegacyAccounting() error {
	u, err := url.Parse(c.APIHost)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") || c.NodeType != "vless" || c.NodeId <= 0 || c.trafficEpoch != "" {
		return errors.New("invalid legacy accounting origin or mixed mode")
	}
	c.legacyAccounting = true
	c.client.SetRedirectPolicy(resty.NoRedirectPolicy())
	c.client.SetLogger(accountingLogger{})
	c.client.SetHeader("X-Beup-Legacy-Accounting", "1")
	c.userEtag = ""
	return nil
}

// Commit sends through the original authenticated UniProxy endpoint and keeps
// the outbox pending until usage and both existing statistics jobs commit.
func (c *Client) Commit(ctx context.Context, b beuptransfer.Batch) (beuptransfer.Ack, error) {
	empty := beuptransfer.Ack{}
	if !c.legacyAccounting || c.trafficEpoch != "" || b.Scope != fmt.Sprintf("vless-%d", c.NodeId) {
		return empty, errors.New("legacy accounting scope mismatch")
	}
	id, digest, data, err := beuptransfer.LegacyPayload(b)
	if err != nil {
		return empty, err
	}
	response, err := c.client.R().SetContext(ctx).SetHeader("X-Beup-Report-Id", id).SetHeader("X-Beup-Report-Digest", digest).SetBody(data).Post("/api/v1/server/UniProxy/push")
	if err != nil || response == nil {
		return empty, errors.New("legacy traffic request failed; pending report retained")
	}
	// A busy settlement lock has not committed this report. Keep the same
	// durable report pending instead of closing a just-started controller.
	if response.StatusCode() == 409 {
		var busy struct { Code string `json:"code"` }
		if json.Unmarshal(response.Body(), &busy) == nil && busy.Code == "traffic_settling" {
			return empty, beuptransfer.ErrPending
		}
	}
	if response.StatusCode() != 200 && response.StatusCode() != 202 {
		return empty, errors.New("legacy traffic not accepted; pending report retained")
	}
	var reply struct {
		Data struct {
			RequestID string `json:"request_id"`
			Digest    string `json:"digest"`
			Committed bool   `json:"committed"`
		} `json:"data"`
	}
	if err = json.Unmarshal(response.Body(), &reply); err != nil || reply.Data.RequestID != id || reply.Data.Digest != digest {
		return empty, errors.New("legacy traffic acknowledgement mismatch")
	}
	if response.StatusCode() == 202 && !reply.Data.Committed {
		return empty, beuptransfer.ErrPending
	}
	if response.StatusCode() != 200 || !reply.Data.Committed {
		return empty, errors.New("legacy traffic not committed")
	}
	return beuptransfer.Ack{Scope: b.Scope, Epoch: b.Epoch, Sequence: b.Sequence, Digest: b.Digest}, nil
}
