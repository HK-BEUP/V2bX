package observer

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"time"
)

type RegistrationSource struct {
	Path            string `json:"path"`
	PublicKey       string `json:"public_key"`
	MinimumSequence int64  `json:"minimum_sequence"`
}
type registrationClaims struct {
	Version          int                       `json:"version"`
	Node             string                    `json:"node"`
	Sequence         int64                     `json:"sequence"`
	IssuedAt         int64                     `json:"issued_at"`
	ExpiresAt        int64                     `json:"expires_at"`
	IdentityRevision string                    `json:"identity_revision"`
	Endpoint         string                    `json:"endpoint"`
	KeyID            string                    `json:"key_id"`
	ObservationKey   string                    `json:"observation_key"`
	Bindings         map[string]map[int]string `json:"bindings"`
}

func privateRegistration(path string) ([]byte, error) {
	fail := errors.New("private signed registration unavailable")
	if !filepath.IsAbs(path) {
		return nil, fail
	}
	dir := filepath.Dir(path)
	real, err := filepath.EvalSymlinks(dir)
	if err != nil || real != dir {
		return nil, fail
	}
	for _, p := range []string{dir, path} {
		st, e := os.Lstat(p)
		if e != nil {
			return nil, fail
		}
		if !ownedByCurrentUser(st) || st.Mode().Perm()&0077 != 0 || st.Mode()&os.ModeSymlink != 0 {
			return nil, fail
		}
		if p == path && (!st.Mode().IsRegular() || st.Size() > 8*1024*1024) {
			return nil, fail
		}
	}
	before, err := os.Lstat(path)
	if err != nil {
		return nil, fail
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fail
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(before, opened) || opened.Mode().Perm()&0077 != 0 {
		return nil, fail
	}
	b, err := io.ReadAll(io.LimitReader(f, 8*1024*1024+1))
	if err != nil || len(b) > 8*1024*1024 {
		return nil, fail
	}
	return b, nil
}
func strictJSON(b []byte, v any) error {
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if e := d.Decode(v); e != nil {
		return e
	}
	if d.Decode(new(any)) != io.EOF {
		return errors.New("invalid trailing registration data")
	}
	return nil
}
func loadRegistration(source RegistrationSource, node, endpoint string, now time.Time) (registrationClaims, error) {
	var c registrationClaims
	fail := errors.New("signed registration rejected")
	key, e := hex.DecodeString(source.PublicKey)
	if e != nil || len(key) != ed25519.PublicKeySize || source.MinimumSequence < 1 {
		return c, fail
	}
	b, e := privateRegistration(source.Path)
	if e != nil {
		return c, fail
	}
	var envelope struct {
		Payload   string `json:"payload"`
		Signature string `json:"signature"`
	}
	if strictJSON(b, &envelope) != nil {
		return c, fail
	}
	payload, e := base64.StdEncoding.Strict().DecodeString(envelope.Payload)
	if e != nil {
		return c, fail
	}
	signature, e := hex.DecodeString(envelope.Signature)
	if e != nil || !ed25519.Verify(key, append([]byte("BEUP-OBSERVATION-REGISTRY-V1\n"), payload...), signature) {
		return c, fail
	}
	if strictJSON(payload, &c) != nil || c.Version != 1 || c.Node != node || c.Endpoint != endpoint || !validEndpoint(c.Endpoint) ||
		c.Sequence < source.MinimumSequence || c.IssuedAt > now.Unix()+30 || c.ExpiresAt <= now.Unix() ||
		c.ExpiresAt <= c.IssuedAt || c.ExpiresAt-c.IssuedAt > 900 || len(c.ObservationKey) != 64 {
		return registrationClaims{}, fail
	}
	if k, e := hex.DecodeString(c.ObservationKey); e != nil || len(k) != 32 {
		return registrationClaims{}, fail
	}
	if k, e := hex.DecodeString(c.KeyID); e != nil || len(k) != 8 {
		return registrationClaims{}, fail
	}
	if _, e = New(Config{Node: c.Node, IdentityRevision: c.IdentityRevision, Bindings: c.Bindings}); e != nil {
		return registrationClaims{}, fail
	}
	return c, nil
}
func (c registrationClaims) fingerprint() [32]byte {
	c.IssuedAt = 0
	c.ExpiresAt = 0
	b, _ := json.Marshal(c)
	return sha256.Sum256(b)
}
func mappingFingerprint(bindings map[string]map[int]string) [32]byte {
	b, _ := json.Marshal(bindings)
	return sha256.Sum256(b)
}

// Re-read every five seconds. Bad deliveries do not replace a still-valid
// signed snapshot. Expiry stops telemetry, never the proxy. The sequence floor
// is pinned by bootstrap; additional rollback protection lasts this process.
func (r *Runtime) reloadRegistration(now time.Time) error {
	if r.source == nil {
		return nil
	}
	c, err := loadRegistration(*r.source, r.settings.Node, r.settings.Endpoint, now)
	r.settingsMu.Lock()
	defer r.settingsMu.Unlock()
	if err == nil {
		fingerprint := c.fingerprint()
		if c.Sequence < r.sequence || (c.Sequence == r.sequence && fingerprint != r.registrationFingerprint) ||
			c.IssuedAt < r.issuedAt {
			err = errors.New("registration rollback or conflict rejected")
		} else if c.IdentityRevision == r.settings.IdentityRevision && mappingFingerprint(c.Bindings) != mappingFingerprint(r.settings.Bindings) {
			err = errors.New("registration mapping revision required")
		} else {
			if c.IdentityRevision != r.settings.IdentityRevision || r.suspended {
				if err = r.Observer.ReplaceRegistry(c.IdentityRevision, c.Bindings); err != nil {
					return err
				}
			}
			r.settings.IdentityRevision = c.IdentityRevision
			r.settings.Bindings = c.Bindings
			r.settings.ObservationKey = c.ObservationKey
			r.sequence = c.Sequence
			r.expiresAt = c.ExpiresAt
			r.issuedAt = c.IssuedAt
			r.keyID = c.KeyID
			r.registrationFingerprint = fingerprint
			r.suspended = false
			r.RegistrationReloaded.Add(1)
		}
	}
	if err != nil {
		r.RegistrationRejected.Add(1)
	}
	if now.Unix() >= r.expiresAt && !r.suspended {
		_ = r.Observer.ReplaceRegistry(r.settings.IdentityRevision, nil)
		r.suspended = true
		r.RegistrationExpired.Add(1)
	}
	return err
}
