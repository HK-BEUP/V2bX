//go:build unix

package observer

import (
	"os"
	"syscall"
)

// Keep the Unix owner check in a platform-specific file; do not weaken it.
func ownedByCurrentUser(st os.FileInfo) bool {
	owner, ok := st.Sys().(*syscall.Stat_t)
	return ok && owner.Uid == uint32(os.Geteuid())
}
