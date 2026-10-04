package beupguard

import (
	"fmt"
	"testing"
	"time"
)

func TestAuthorizationProofNeedsRegisteredGrantEveryInboundAndRealAuthentication(t *testing.T) {
	now := time.Unix(1800000000, 0)
	g := New(100, func() time.Time { return now })
	if e := g.RequireTags([]string{"a", "b"}); e != nil {
		t.Fatal(e)
	}
	id := Identity{UID: 10, Credential: CredentialDigest("new-grant-credential")}
	grant := fmt.Sprintf("%032x", 1)
	q := AuthorizationRequest{Version: 1, ID: fmt.Sprintf("%032x", 2), Targets: []AuthorizationTarget{{Grant: grant, Identity: id}}}
	g.Bind("a", "first", 10, "new-grant-credential")
	g.Bind("b", "second", 10, "new-grant-credential")
	p, e := g.authorizationProof(q)
	if e != nil || p[0].Bound {
		t.Fatal("legacy credentials classified as independent")
	}
	g.registerAuthorization("a", "first", grant)
	p, _ = g.authorizationProof(q)
	if p[0].Bound {
		t.Fatal("incomplete scope accepted")
	}
	g.registerAuthorization("b", "second", grant)
	p, _ = g.authorizationProof(q)
	if !p[0].Bound || p[0].LastAuthenticatedAt != 0 {
		t.Fatal("bound credential fabricated use")
	}
	done, e := g.Track("a", "first", func() {})
	if e != nil {
		t.Fatal(e)
	}
	defer done()
	p, _ = g.authorizationProof(q)
	if p[0].LastAuthenticatedAt != now.Unix() {
		t.Fatal("real authentication not recorded")
	}
	// Another credential for the same owner must not inherit this grant's use.
	sibling := Identity{UID: 10, Credential: CredentialDigest("sibling")}
	g.Bind("a", "sibling", 10, "sibling")
	q.Targets[0].Identity = sibling
	p, _ = g.authorizationProof(q)
	if p[0].Bound || p[0].LastAuthenticatedAt != 0 {
		t.Fatal("same owner confused with same authorization")
	}
	q.Targets[0].Identity = id
	g.Unbind("b", "second")
	p, _ = g.authorizationProof(q)
	if p[0].Bound {
		t.Fatal("removed scope retained ready proof")
	}
}
func TestAuthorizationProofRequestBounds(t *testing.T) {
	q := AuthorizationRequest{Version: 1, ID: fmt.Sprintf("%032x", 1), Targets: []AuthorizationTarget{{Grant: fmt.Sprintf("%032x", 2), Identity: Identity{UID: 1, Credential: CredentialDigest("x")}}}}
	if !validAuthorizationRequest(q) {
		t.Fatal("valid request")
	}
	q.Targets = append(q.Targets, q.Targets[0])
	if validAuthorizationRequest(q) {
		t.Fatal("duplicate target")
	}
}
