package panel

import (
	"encoding/hex"
	"errors"
	"github.com/go-resty/resty/v2"
	log "github.com/sirupsen/logrus"
	"net/url"
)

// SetTrafficEpoch runs once before starting the controller. The panel must
// confirm the exact generation on every 200/304 before any users are admitted.
func (c *Client) SetTrafficEpoch(epoch string) error {
	b, err := hex.DecodeString(epoch)
	u, urlErr := url.Parse(c.APIHost)
	if err != nil || len(b) != 16 || hex.EncodeToString(b) != epoch || urlErr != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || c.NodeType != "vless" || c.trafficEpoch != "" || c.legacyAccounting {
		return errors.New("invalid accounting generation or secure panel scope")
	}
	c.client.SetRedirectPolicy(resty.NoRedirectPolicy())
	c.client.SetLogger(accountingLogger{})
	c.client.SetHeader("X-Beup-Traffic-Epoch", epoch)
	c.trafficEpoch = epoch
	c.userEtag = ""
	return nil
}

// Invalidate only the local user cache after an incomplete apply, so retries fetch a full list.
func (c *Client) ForgetUserList() { c.userEtag = "" }

// Never put API query tokens into retry/debug/error logs in reliable mode.
type accountingLogger struct{}

func (accountingLogger) Errorf(string, ...interface{}) { log.Error("Reliable panel request failed") }
func (accountingLogger) Warnf(string, ...interface{})  { log.Warn("Reliable panel request retry") }
func (accountingLogger) Debugf(string, ...interface{}) {}
