package beupguard

import (
	"errors"
	"regexp"
)

const AuthorizationProofDomain = "BEUP-SUBSCRIPTION-AUTHORIZATION-PROOF-V1\n"

type AuthorizationTarget struct {
	Grant    string   `json:"grant"`
	Identity Identity `json:"identity"`
}
type AuthorizationRequest struct {
	Version int                   `json:"version"`
	ID      string                `json:"id"`
	Targets []AuthorizationTarget `json:"targets"`
}
type AuthorizationProof struct {
	Grant               string   `json:"grant"`
	Identity            Identity `json:"identity"`
	Bound               bool     `json:"bound"`
	LastAuthenticatedAt int64    `json:"last_authenticated_at"`
}
type AuthorizationReport struct {
	Version    int                  `json:"version"`
	Node       string               `json:"node"`
	RequestID  string               `json:"request_id"`
	ObservedAt int64                `json:"observed_at"`
	Ready      bool                 `json:"ready"`
	Proofs     []AuthorizationProof `json:"proofs"`
}

func validAuthorizationRequest(q AuthorizationRequest) bool {
	if q.Version != 1 || !regexp.MustCompile(`^[a-f0-9]{32}$`).MatchString(q.ID) || len(q.Targets) < 1 || len(q.Targets) > 16 {
		return false
	}
	seen := map[string]bool{}
	for _, target := range q.Targets {
		if !regexp.MustCompile(`^[a-f0-9]{32}$`).MatchString(target.Grant) || target.Identity.UID <= 0 || !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(target.Identity.Credential) || seen[target.Grant] {
			return false
		}
		seen[target.Grant] = true
	}
	return true
}
func (g *Guard) registerAuthorization(tag, label, grant string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	binding := Binding{tag, label}
	identity, ok := g.bindings[binding]
	if !ok || !regexp.MustCompile(`^[a-f0-9]{32}$`).MatchString(grant) {
		delete(g.authorizations, binding)
		return
	}
	g.authorizations[binding] = grant
	if _, ok = g.authorizationUse[identity]; !ok {
		g.authorizationUse[identity] = 0
	}
}
func RegisterAuthorization(tag, label, grant string) {
	for _, g := range guardsForTag(tag) {
		g.registerAuthorization(tag, label, grant)
	}
}
func (g *Guard) authorizationProof(q AuthorizationRequest) ([]AuthorizationProof, error) {
	if !validAuthorizationRequest(q) {
		return nil, errors.New("invalid scoped authorization proof request")
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	out := make([]AuthorizationProof, 0, len(q.Targets))
	for _, target := range q.Targets {
		tags := map[string]bool{}
		conflict := false
		for binding, id := range g.bindings {
			if id == target.Identity {
				if g.authorizations[binding] != target.Grant {
					conflict = true
				} else {
					tags[binding.Tag] = true
				}
			}
		}
		bound := !conflict && len(g.requiredTags) > 0
		for tag := range g.requiredTags {
			if !tags[tag] {
				bound = false
			}
		}
		proof := AuthorizationProof{Grant: target.Grant, Identity: target.Identity, Bound: bound}
		if bound {
			proof.LastAuthenticatedAt = g.authorizationUse[target.Identity]
		}
		out = append(out, proof)
	}
	return out, nil
}

// Enforced on the node itself, even if a signed command targets a legacy UUID.
func (g *Guard) independentIdentity(identity Identity) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	grant := ""
	tags := map[string]bool{}
	for b, id := range g.bindings {
		if id == identity {
			value := g.authorizations[b]
			if value == "" || (grant != "" && value != grant) {
				return false
			}
			grant = value
			tags[b.Tag] = true
		}
	}
	if grant == "" || len(g.requiredTags) == 0 {
		return false
	}
	for tag := range g.requiredTags {
		if !tags[tag] {
			return false
		}
	}
	return true
}
