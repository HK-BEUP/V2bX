//go:build !unix

package observer

import "testing"

func TestUnsupportedOwnershipFailsClosed(t *testing.T) {
	if ownedByCurrentUser(nil) {
		t.Fatal("unsupported ownership must fail closed")
	}
}
