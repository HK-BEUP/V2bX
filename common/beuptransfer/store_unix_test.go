//go:build linux || darwin

package beuptransfer

import (
	"os"
	"path/filepath"
	"testing"
)

func private(t *testing.T) string {
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
func TestFileStoreRoundtripAndExclusiveWriter(t *testing.T) {
	p := private(t)
	s, e := OpenFileStore(p)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	if _, e = OpenFileStore(p); e == nil {
		t.Fatal("second writer acquired journal")
	}
	if e = s.Save([]byte(`{"synthetic":true}`)); e != nil {
		t.Fatal(e)
	}
	b, e := s.Load()
	if e != nil || string(b) != `{"synthetic":true}` {
		t.Fatal("roundtrip failed", e)
	}
	st, e := os.Stat(filepath.Join(p, "journal.json"))
	if e != nil || st.Mode().Perm() != 0600 {
		t.Fatal("loose journal permissions")
	}
	if e = s.Close(); e != nil {
		t.Fatal(e)
	}
	s, e = OpenFileStore(p)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	if _, e = s.Load(); e != nil {
		t.Fatal(e)
	}
}
func TestFileStoreRejectsSymlinkDirectoryJournalAndLooseMode(t *testing.T) {
	p := private(t)
	link := filepath.Join(private(t), "link")
	if e := os.Symlink(p, link); e != nil {
		t.Fatal(e)
	}
	if _, e := OpenFileStore(link); e == nil {
		t.Fatal("symlink directory accepted")
	}
	if e := os.Chmod(p, 0755); e != nil {
		t.Fatal(e)
	}
	if _, e := OpenFileStore(p); e == nil {
		t.Fatal("public directory accepted")
	}
	os.Chmod(p, 0700)
	s, e := OpenFileStore(p)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	if e = os.Symlink(filepath.Join(p, "missing"), filepath.Join(p, "journal.json")); e != nil {
		t.Fatal(e)
	}
	if _, e = s.Load(); e == nil {
		t.Fatal("symlink journal accepted")
	}
}
func TestFileStoreClosedCannotReadOrWrite(t *testing.T) {
	s, e := OpenFileStore(private(t))
	if e != nil {
		t.Fatal(e)
	}
	s.Close()
	if _, e = s.Load(); e == nil {
		t.Fatal("closed read accepted")
	}
	if e = s.Save([]byte("{}")); e == nil {
		t.Fatal("closed write accepted")
	}
}

func TestFileStoreRejectsTruncatedEmptyJournal(t *testing.T) {
	p := private(t)
	s, e := OpenFileStore(p)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	if e = os.WriteFile(filepath.Join(p, "journal.json"), nil, 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = s.Load(); e == nil {
		t.Fatal("empty existing journal treated as first startup")
	}
}
