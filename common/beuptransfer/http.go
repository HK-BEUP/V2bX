package beuptransfer

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// HTTPReceiver requires a unique accounting key per scope, independent of the
// existing shared API token. TLS verification and redirects cannot be disabled.
type HTTPReceiver struct {
	endpoint, scope string
	key             []byte
	client          *http.Client
	now             func() time.Time
}

func NewHTTPReceiver(endpoint, scope string, key []byte) (*HTTPReceiver, error) {
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || !scopePattern.MatchString(scope) || len(key) != 32 {
		return nil, errors.New("accounting requires HTTPS, an explicit scope and a dedicated 32-byte key")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.ResponseHeaderTimeout = 10 * time.Second
	return &HTTPReceiver{endpoint: endpoint, scope: scope, key: append([]byte(nil), key...), now: time.Now,
		client: &http.Client{Timeout: 15 * time.Second, Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}

func wireMAC(direction, scope, at, nonce string, body, key []byte) string {
	return wirePurposeMAC(direction, "traffic", scope, at, nonce, body, key)
}

func wirePurposeMAC(direction, purpose, scope, at, nonce string, body, key []byte) string {
	hash := sha256.Sum256(body)
	m := hmac.New(sha256.New, key)
	fmt.Fprintf(m, "beup-node-%s-v1\n%s\n%s\n%s\n%s\n%x\n", direction, purpose, scope, at, nonce, hash)
	return hex.EncodeToString(m.Sum(nil))
}

func (r *HTTPReceiver) Commit(ctx context.Context, b Batch) (Ack, error) {
	if b.Version != 1 || b.Scope != r.scope || !validHex(b.Epoch, 16) || b.Sequence < 1 || b.Sequence > 1<<53 || b.Digest != b.Hash() {
		return Ack{}, errors.New("invalid accounting batch")
	}
	ordered, err := samples(b.Entries)
	if err != nil {
		return Ack{}, err
	}
	for i := range ordered {
		if ordered[i] != b.Entries[i] {
			return Ack{}, errors.New("unordered accounting batch")
		}
	}
	body, err := json.Marshal(b)
	if err != nil || len(body) > 4<<20 {
		return Ack{}, errors.New("oversized accounting batch")
	}
	response, err := r.post(ctx, "traffic", body)
	if err != nil { return Ack{}, err }
	var ack Ack
	decoder := json.NewDecoder(bytes.NewReader(response))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&ack) != nil || decoder.Decode(new(any)) != io.EOF || ack != ackFor(b) {
		return Ack{}, errors.New("accounting acknowledgement mismatch")
	}
	return ack, nil
}

func (r *HTTPReceiver) post(ctx context.Context, purpose string, body []byte) ([]byte, error) {
	if (purpose != "traffic" && purpose != "drain" && purpose != "control" && purpose != "probe") || len(body)>4<<20 { return nil, errors.New("invalid receipt purpose or payload") }
	var err error
	nonceBytes := make([]byte, 16)
	if _, err = rand.Read(nonceBytes); err != nil {
		return nil, err
	}
	nonce := hex.EncodeToString(nonceBytes)
	at := strconv.FormatInt(r.now().Unix(), 10)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Beup-Scope", r.scope)
	req.Header.Set("X-Beup-Time", at)
	req.Header.Set("X-Beup-Nonce", nonce)
	req.Header.Set("X-Beup-Signature", wirePurposeMAC("request", purpose, r.scope, at, nonce, body, r.key))
	res, err := r.client.Do(req)
	if err != nil {
		return nil, errors.New("accounting delivery failed; journal retained")
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, errors.New("accounting receiver did not commit; journal retained")
	}
	response, err := io.ReadAll(io.LimitReader(res.Body, (16<<10)+1))
	if err != nil || len(response) > 16<<10 {
		return nil, errors.New("invalid accounting response")
	}
	responseAt, responseNonce, signature := res.Header.Get("X-Beup-Time"), res.Header.Get("X-Beup-Nonce"), res.Header.Get("X-Beup-Signature")
	seconds, err := strconv.ParseInt(responseAt, 10, 64)
	now := r.now().Unix()
	if err != nil || len(responseAt) != 10 || strconv.FormatInt(seconds, 10) != responseAt || seconds < now-120 || seconds > now+120 || responseNonce != nonce || !validHex(signature, 32) || !hmac.Equal([]byte(signature), []byte(wirePurposeMAC("response", purpose, r.scope, responseAt, nonce, response, r.key))) {
		return nil, errors.New("untrusted accounting acknowledgement")
	}
	return response, nil
}
