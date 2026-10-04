// Package beupidentity binds telemetry and node-local overlays to the exact
// authenticated credential, without storing or reporting the credential itself.
package beupidentity

import (
	"crypto/sha256"
	"encoding/hex"
)

func CredentialDigest(credential string) string {
	if credential == "" || len(credential) > 1024 {
		return ""
	}
	h := sha256.Sum256([]byte("BEUP-ACCOUNT-CREDENTIAL-V1\n" + credential))
	return hex.EncodeToString(h[:])
}
