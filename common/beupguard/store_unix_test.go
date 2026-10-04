//go:build linux || darwin

package beupguard

import (
	"os"
	"path/filepath"
	"testing"
)

func privateTestDir(t *testing.T) string {
	t.Helper()
	p, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	if e = os.Chmod(p, 0700); e != nil {
		t.Fatal(e)
	}
	return p
}
func TestFileStoreExplicitInitializeExclusiveOwnerAndCAS(t *testing.T) {
	dir := privateTestDir(t)
	if s, e := OpenFileStore(dir, "test", false); e == nil {
		s.Close()
		t.Fatal("missing journal initialized silently")
	}
	s, e := OpenFileStore(dir, "test", true)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	if second, e := OpenFileStore(dir, "test", false); e == nil {
		second.Close()
		t.Fatal("second owner accepted")
	}
	j, e := s.Load()
	if e != nil {
		t.Fatal(e)
	}
	j.Records = append(j.Records, Record{AcceptedAt: 123})
	if e = s.Save(1, j); e == nil {
		t.Fatal("wrong record count accepted")
	}
	if e = s.Save(0, j); e != nil {
		t.Fatal(e)
	}
	st, _ := os.Stat(filepath.Join(dir, "journal.json"))
	if st.Mode().Perm() != 0600 {
		t.Fatal("journal not private")
	}
	if e = os.WriteFile(filepath.Join(dir, "journal.json"), []byte("{}"), 0600); e != nil {
		t.Fatal(e)
	}
	j.Records = append(j.Records, Record{AcceptedAt: 124})
	if e = s.Save(1, j); e == nil {
		t.Fatal("overwrote concurrent operator change")
	}
}
func TestFileStoreRejectsSymlinksPublicPermissionsAndCorruption(t *testing.T) {
	for _, kind := range []string{"symlink", "public", "corrupt"} {
		t.Run(kind, func(t *testing.T) {
			dir := privateTestDir(t)
			path := filepath.Join(dir, "journal.json")
			s, e := OpenFileStore(dir, "test", true)
			if e != nil {
				t.Fatal(e)
			}
			s.Close()
			switch kind {
			case "symlink":
				if e = os.Rename(path, filepath.Join(dir, "saved.json")); e != nil {
					t.Fatal(e)
				}
				e = os.Symlink("saved.json", path)
			case "public":
				e = os.Chmod(path, 0644)
			case "corrupt":
				e = os.WriteFile(path, []byte("{broken"), 0600)
			}
			if e != nil {
				t.Fatal(e)
			}
			if s, e = OpenFileStore(dir, "test", false); e == nil {
				s.Close()
				t.Fatal("unsafe store accepted")
			}
		})
	}
}
