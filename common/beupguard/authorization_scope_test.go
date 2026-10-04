package beupguard

import (
	"fmt"
	"testing"
)

func TestSubscriptionRuntimeRejectsLegacyAndPermanentSignedCommands(t *testing.T) {
	r, client, key := runtimeFixture(t, true)
	r.settings.AuthorizationOnly = true
	for _, tag := range []string{"a", "b"} {
		r.guard.Bind(tag, "target", 2, "synthetic")
		r.guard.Bind(tag, "legacy", 2, "legacy")
	}
	lease := Lease{ID: fmt.Sprintf("%032x", 1), Identity: Identity{2, CredentialDigest("legacy")}, StartedAt: 1800000000, ExpiresAt: 1800000600}
	command := func(l Lease) Envelope {
		return signed(key, Command{1, "synthetic-jp", 1, 1800000000, 1800000060, "block", l})
	}
	if code, _ := rpc(t, client, "POST", "/v1/execute", command(lease)); code != 403 {
		t.Fatal("legacy credential accepted", code)
	}
	lease.Identity.Credential = CredentialDigest("synthetic")
	r.guard.registerAuthorization("a", "target", fmt.Sprintf("%032x", 1))
	if code, _ := rpc(t, client, "POST", "/v1/execute", command(lease)); code != 403 {
		t.Fatal("partially migrated identity accepted", code)
	}
	r.guard.registerAuthorization("b", "target", fmt.Sprintf("%032x", 1))
	lease.Manual = true
	lease.ExpiresAt = 0
	if code, _ := rpc(t, client, "POST", "/v1/execute", command(lease)); code != 403 {
		t.Fatal("permanent subscription ban accepted", code)
	}
	lease.Manual = false
	lease.ExpiresAt = 1800000600
	if code, _ := rpc(t, client, "POST", "/v1/execute", command(lease)); code != 200 {
		t.Fatal("complete independent authorization rejected", code)
	}
	if _, e := r.guard.Track("a", "legacy", nil); e != nil {
		t.Fatal("same owner's legacy rejected", e)
	}
}
