//go:build unix

package observer

import (
	"os"
	"path/filepath"
	"testing"
)

func TestOwnershipNativeFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "owned")
	if err := os.WriteFile(path, []byte("synthetic"), 0600); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !ownedByCurrentUser(st) {
		t.Fatal("current user's private file was rejected")
	}
}
