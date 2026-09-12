package observer

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func registrationFixture(t *testing.T) (Settings, registrationClaims, ed25519.PrivateKey) {
	t.Helper()
	dir, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	os.Chmod(dir, 0700)
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	source := &RegistrationSource{filepath.Join(dir, "signed.json"), hex.EncodeToString(pub), 1}
	s := Settings{Enabled: true, Mode: "observe", Node: "demo-hk", Endpoint: "https://observer.example.test/api/v1/attack-guard/observation", Registration: source}
	now := time.Now().Unix()
	c := registrationClaims{1, s.Node, 1, now, now + 900, "registry-1", s.Endpoint, strings.Repeat("a", 16), strings.Repeat("b", 64), map[string]map[int]string{"tag": {2: testSubject}}}
	deliver(t, source.Path, c, key)
	return s, c, key
}
func deliver(t *testing.T, path string, c registrationClaims, key ed25519.PrivateKey) {
	t.Helper()
	b, _ := json.Marshal(c)
	envelope, _ := json.Marshal(map[string]string{"payload": base64.StdEncoding.EncodeToString(b), "signature": hex.EncodeToString(ed25519.Sign(key, append([]byte("BEUP-OBSERVATION-REGISTRY-V1\n"), b...)))})
	// Delivery operator uses atomic replace, never truncates the live file.
	if e := os.WriteFile(path+".next", envelope, 0600); e != nil {
		t.Fatal(e)
	}
	if e := os.Rename(path+".next", path); e != nil {
		t.Fatal(e)
	}
}
func TestSignedRegistrationAuthenticityAndScope(t *testing.T) {
	s, c, key := registrationFixture(t)
	if _, e := NewRuntime(s); e != nil {
		t.Fatal(e)
	}
	cases := []func(*registrationClaims){
		func(c *registrationClaims) { c.Node = "other" },
		func(c *registrationClaims) {
			c.Endpoint = "https://attacker.example.test/api/v1/attack-guard/observation"
		},
		func(c *registrationClaims) { c.ExpiresAt = time.Now().Unix() },
		func(c *registrationClaims) { c.ExpiresAt = c.IssuedAt + 901 },
		func(c *registrationClaims) { c.IssuedAt = time.Now().Unix() + 60; c.ExpiresAt = c.IssuedAt + 300 },
		func(c *registrationClaims) { c.Sequence = 0 },
		func(c *registrationClaims) { c.ObservationKey = "short" },
		func(c *registrationClaims) { c.KeyID = "bad" },
		func(c *registrationClaims) { c.Bindings = map[string]map[int]string{"tag": {0: testSubject}} },
	}
	for _, change := range cases {
		bad := c
		change(&bad)
		deliver(t, s.Registration.Path, bad, key)
		if _, e := NewRuntime(s); e == nil {
			t.Fatal("invalid signed claims accepted")
		}
	}
	deliver(t, s.Registration.Path, c, key)
	b, _ := os.ReadFile(s.Registration.Path)
	b[len(b)-5] ^= 1
	os.WriteFile(s.Registration.Path, b, 0600)
	if _, e := NewRuntime(s); e == nil {
		t.Fatal("tampering accepted")
	}
	deliver(t, s.Registration.Path, c, key)
	s.ObservationKey = strings.Repeat("x", 64)
	if _, e := NewRuntime(s); e == nil {
		t.Fatal("legacy downgrade accepted")
	}
	s.ObservationKey = ""
	os.Chmod(s.Registration.Path, 0644)
	if _, e := NewRuntime(s); e == nil {
		t.Fatal("public signed snapshot contains secret")
	}
}
func TestRegistryHotReloadRevocationAndExpiry(t *testing.T) {
	s, c, key := registrationFixture(t)
	r, e := NewRuntime(s)
	if e != nil {
		t.Fatal(e)
	}
	r.Observer.Bind("tag", "auth-two", 2)
	if r.Observer.Bind("tag", "auth-three", 3) {
		t.Fatal("unregistered UID")
	}
	old := currentReport()
	old.IdentityRevision = c.IdentityRevision
	c.Sequence = 2
	c.IdentityRevision = "registry-2"
	c.Bindings = map[string]map[int]string{"tag": {3: strings.Repeat("c", 32)}}
	deliver(t, s.Registration.Path, c, key)
	if e = r.reloadRegistration(time.Now()); e != nil {
		t.Fatal(e)
	}
	r.Observer.mu.Lock()
	if len(r.Observer.bindings) != 1 || r.Observer.bindings[r.Observer.labelKey("tag", "auth-three")] != strings.Repeat("c", 32) || !r.Observer.partial {
		t.Error("authenticated reference not rebound")
	}
	r.Observer.mu.Unlock()
	if r.send(context.Background(), old) || r.StaleRevision.Load() != 1 {
		t.Fatal("old queued revision sent")
	}
	// Same sequence may renew time only, never silently alter mapping/key.
	c.Sequence = 1
	deliver(t, s.Registration.Path, c, key)
	if r.reloadRegistration(time.Now()) == nil {
		t.Fatal("rollback accepted")
	}
	c.Sequence = 2
	c.KeyID = strings.Repeat("c", 16)
	deliver(t, s.Registration.Path, c, key)
	if r.reloadRegistration(time.Now()) == nil {
		t.Fatal("same sequence conflict")
	}
	c.Sequence = 3
	deliver(t, s.Registration.Path, c, key)
	if r.reloadRegistration(time.Now()) != nil {
		t.Fatal("key rotation rejected")
	}
	if r.keyID != c.KeyID {
		t.Fatal("key not switched")
	}
	if r.reloadRegistration(time.Unix(c.ExpiresAt, 0)) == nil || !r.suspended || r.RegistrationExpired.Load() != 1 {
		t.Fatal("expiry did not suspend")
	}
	r.Observer.mu.Lock()
	n := len(r.Observer.bindings)
	r.Observer.mu.Unlock()
	if n != 0 {
		t.Fatal("expired registry retained attribution")
	}
	c.IssuedAt = c.ExpiresAt
	c.ExpiresAt += 900
	deliver(t, s.Registration.Path, c, key)
	if r.reloadRegistration(time.Unix(c.IssuedAt, 0)) != nil || r.suspended {
		t.Fatal("renewal failed")
	}
	r.Observer.Unbind("tag", "auth-three")
	c.Sequence = 4
	c.IdentityRevision = "registry-4"
	deliver(t, s.Registration.Path, c, key)
	r.reloadRegistration(time.Unix(c.IssuedAt, 0))
	r.Observer.mu.Lock()
	n = len(r.Observer.bindings)
	r.Observer.mu.Unlock()
	if n != 0 {
		t.Fatal("deleted core credential resurrected")
	}
}
func TestRegistryConcurrentReloadAndSampling(t *testing.T) {
	s, c, key := registrationFixture(t)
	r, e := NewRuntime(s)
	if e != nil {
		t.Fatal(e)
	}
	r.Observer.Bind("tag", "auth", 2)
	var wg sync.WaitGroup
	for j := 0; j < 4; j++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 1000; i++ {
				r.Observer.Observe("tag", "auth", "tcp", "example.test", 443)
				r.Observer.Snapshot(time.Now())
			}
		}()
	}
	for i := 0; i < 20; i++ {
		c.Sequence++
		c.IdentityRevision = "registry-" + strings.Repeat("a", i+1)
		deliver(t, s.Registration.Path, c, key)
		if e = r.reloadRegistration(time.Now()); e != nil {
			t.Fatal(e)
		}
	}
	wg.Wait()
}
func TestPHPRegistrationInterop(t *testing.T) {
	dir := os.Getenv("BEUP_REGISTRY_QA_FIXTURE")
	if dir == "" {
		t.Skip("optional PHP-generated private synthetic fixture")
	}
	if !strings.HasPrefix(dir, "/private/tmp/beup-registry-") {
		t.Fatal("invalid QA fixture")
	}
	s, e := LoadSettings(filepath.Join(dir, "bootstrap.json"))
	if e != nil {
		t.Fatal(e)
	}
	r, e := NewRuntime(s)
	if e != nil {
		t.Fatal(e)
	}
	if len(r.settings.Bindings["tag"]) != 1 {
		t.Fatal("PHP signed roster mismatch")
	}
	report := currentReport()
	report.IdentityRevision = r.settings.IdentityRevision
	report.Subjects = []Sample{{Subject: r.settings.Bindings["tag"][2], Metrics: Metrics{ProxyRequests: 1, TCPRequests: 1, DistinctTargets: 1, DistinctPorts: 1, MaxTargetRequests: 1}}}
	b, h, e := r.Observer.encodeWithKeyID(report, []byte(r.settings.ObservationKey), r.keyID, time.Now())
	if e != nil {
		t.Fatal(e)
	}
	h["key_id"] = r.keyID
	wire, _ := json.Marshal(map[string]any{"body": base64.StdEncoding.EncodeToString(b), "headers": h})
	if e = os.WriteFile(filepath.Join(dir, "wire.json"), wire, 0600); e != nil {
		t.Fatal(e)
	}
}
