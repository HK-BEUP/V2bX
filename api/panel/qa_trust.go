//go:build beupqa

package panel

import (
 "crypto/x509"
 "errors"
 "net/url"
)

// Compiled only in the explicitly tagged local acceptance build. Normal
// production binaries have no test trust hook and retain system TLS roots.
func (c *Client) TrustLoopbackQA(certificatePEM string) error {
 u,err:=url.Parse(c.APIHost);if err!=nil||u.Scheme!="https"||u.Hostname()!="127.0.0.1" {return errors.New("QA trust restricted to loopback")}
 roots:=x509.NewCertPool();if !roots.AppendCertsFromPEM([]byte(certificatePEM)){return errors.New("QA certificate invalid")}
 c.client.SetRootCertificateFromString(certificatePEM)
 c.client.SetRetryCount(0)
 return nil
}
