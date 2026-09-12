//go:build !unix

package observer

import "os"

// No audited private-file ownership policy on this platform. Fail closed for
// observation settings; an unset/invalid observer never stops the proxy.
func ownedByCurrentUser(os.FileInfo) bool { return false }
