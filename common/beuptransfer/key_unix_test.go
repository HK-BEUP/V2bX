//go:build linux || darwin

package beuptransfer

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestScopeKeyIsLocalPrivateAndNeverCreated(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	os.Chmod(dir, 0700)
	s, err := OpenFileStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err = s.ReadKey(); err == nil {
		t.Fatal("missing key accepted")
	}
	p := filepath.Join(dir, "accounting.key")
	if _, err = os.Stat(p); !os.IsNotExist(err) {
		t.Fatal("key was automatically provisioned")
	}
	for _, n := range []int{0, 31, 33, 64} {
		os.WriteFile(p, bytes.Repeat([]byte{3}, n), 0600)
		if _, err = s.ReadKey(); err == nil {
			t.Fatalf("accepted %d bytes", n)
		}
	}
	expected := bytes.Repeat([]byte{5}, 32)
	os.WriteFile(p, expected, 0600)
	os.Chmod(p, 0644)
	if _, err = s.ReadKey(); err == nil {
		t.Fatal("public key file accepted")
	}
	os.Chmod(p, 0600)
	got, err := s.ReadKey()
	if err != nil || !bytes.Equal(got, expected) {
		t.Fatal("valid key not read", err)
	}
	os.Remove(p)
	target := filepath.Join(dir, "other-key")
	os.WriteFile(target, expected, 0600)
	os.Symlink(target, p)
	if _, err = s.ReadKey(); err == nil {
		t.Fatal("symlink key accepted")
	}
	s.Close()
	if _, err = s.ReadKey(); err == nil {
		t.Fatal("read key after lock closed")
	}
}
