//go:build linux || darwin

package beupguard

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"syscall"
)

const journalLimit = 16 * 1024 * 1024

type FileStore struct {
	mu        sync.Mutex
	dir, path string
	lock      *os.File
	digest    [32]byte
	loaded    bool
}

func privateDir(path string) error {
	st, err := os.Lstat(path)
	real, e := filepath.EvalSymlinks(path)
	if err != nil || e != nil || real != path || !filepath.IsAbs(path) || !st.IsDir() || st.Mode().Perm()&0077 != 0 {
		return errors.New("private isolation directory required")
	}
	s, ok := st.Sys().(*syscall.Stat_t)
	if !ok || int(s.Uid) != os.Geteuid() {
		return errors.New("isolation directory ownership mismatch")
	}
	return nil
}
func readPrivate(path string) ([]byte, error) {
	st, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	s, ok := st.Sys().(*syscall.Stat_t)
	if !ok || int(s.Uid) != os.Geteuid() || !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 || st.Size() > journalLimit {
		return nil, errors.New("private isolation journal required")
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(st, opened) {
		return nil, errors.New("isolation journal changed")
	}
	b, err := io.ReadAll(io.LimitReader(f, journalLimit+1))
	if err != nil || len(b) > journalLimit {
		return nil, errors.New("invalid isolation journal size")
	}
	return b, nil
}

// initialize=true is for an explicit first installation only. Runtime must use
// false: loss of replay/hold state is an error, not an empty new installation.
func OpenFileStore(dir, node string, initialize bool) (*FileStore, error) {
	if err := privateDir(dir); err != nil {
		return nil, err
	}
	l, err := os.OpenFile(filepath.Join(dir, "journal.lock"), os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, err
	}
	st, err := l.Stat()
	if err != nil {
		l.Close()
		return nil, err
	}
	s, ok := st.Sys().(*syscall.Stat_t)
	if !ok || int(s.Uid) != os.Geteuid() || !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 {
		l.Close()
		return nil, errors.New("private isolation lock required")
	}
	if err := syscall.Flock(int(l.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		l.Close()
		return nil, errors.New("isolation journal already owned")
	}
	store := &FileStore{dir: dir, path: filepath.Join(dir, "journal.json"), lock: l}
	if initialize {
		f, e := os.OpenFile(store.path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
		if e != nil {
			store.Close()
			return nil, e
		}
		b, _ := json.Marshal(Journal{Version: 1, Node: node, Records: []Record{}})
		_, e = f.Write(b)
		if e == nil {
			e = f.Sync()
		}
		ce := f.Close()
		if e == nil {
			e = ce
		}
		if e == nil {
			e = syncDirectory(dir)
		}
		if e != nil {
			store.Close()
			return nil, e
		}
	}
	if _, err = store.Load(); err != nil {
		store.Close()
		return nil, err
	}
	return store, nil
}
func syncDirectory(dir string) error {
	f, e := os.Open(dir)
	if e != nil {
		return e
	}
	defer f.Close()
	return f.Sync()
}
func (s *FileStore) Load() (Journal, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var j Journal
	if s.lock == nil {
		return j, errors.New("closed isolation store")
	}
	if err := privateDir(s.dir); err != nil {
		return j, err
	}
	b, e := readPrivate(s.path)
	if e != nil {
		return j, e
	}
	if e = decodeStrict(b, &j); e != nil {
		return j, errors.New("invalid isolation journal JSON")
	}
	s.digest = sha256.Sum256(b)
	s.loaded = true
	return j, nil
}
func (s *FileStore) Save(expectedRecords int, next Journal) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lock == nil || !s.loaded {
		return errors.New("isolation store unavailable")
	}
	if e := privateDir(s.dir); e != nil {
		return e
	}
	before, e := readPrivate(s.path)
	if e != nil {
		return e
	}
	var old Journal
	if sha256.Sum256(before) != s.digest || decodeStrict(before, &old) != nil || len(old.Records) != expectedRecords || next.Version != old.Version || next.Node != old.Node || len(next.Records) != expectedRecords+1 {
		return errors.New("isolation journal CAS mismatch")
	}
	for i, r := range old.Records {
		if r != next.Records[i] {
			return errors.New("isolation history changed")
		}
	}
	b, e := json.Marshal(next)
	if e != nil || len(b) > journalLimit {
		return errors.New("isolation journal capacity exceeded")
	}
	f, e := os.CreateTemp(s.dir, ".journal-")
	if e != nil {
		return e
	}
	name := f.Name()
	defer os.Remove(name)
	if e = f.Chmod(0600); e == nil {
		_, e = f.Write(b)
	}
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e == nil {
		e = ce
	}
	if e != nil {
		return e
	}
	// Recheck before the only replacement. Another process cannot own the
	// advisory lock; an out-of-band operator edit must still cause a stop.
	current, e := readPrivate(s.path)
	if e != nil || sha256.Sum256(current) != s.digest {
		return errors.New("isolation journal changed before commit")
	}
	if e = os.Rename(name, s.path); e != nil {
		return e
	}
	if e = syncDirectory(s.dir); e != nil {
		return e
	}
	s.digest = sha256.Sum256(b)
	return nil
}
func (s *FileStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lock == nil {
		return nil
	}
	f := s.lock
	s.lock = nil
	return f.Close()
}
