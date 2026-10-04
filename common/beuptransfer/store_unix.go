//go:build linux || darwin

package beuptransfer

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

type FileStore struct {
	directory string
	lock      *os.File
}

func owned(st os.FileInfo) bool {
	s, ok := st.Sys().(*syscall.Stat_t)
	return ok && int(s.Uid) == os.Geteuid()
}

// OpenFileStore requires an already provisioned private directory. It never
// opens a network port and refuses symlinks, loose modes, and another owner.
func OpenFileStore(directory string) (*FileStore, error) {
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		return nil, errors.New("absolute clean accounting directory required")
	}
	resolved, err := filepath.EvalSymlinks(directory)
	if err != nil || resolved != directory {
		return nil, errors.New("accounting directory symlink refused")
	}
	st, err := os.Lstat(directory)
	if err != nil || !st.IsDir() || st.Mode().Perm() != 0700 || !owned(st) {
		return nil, errors.New("private accounting directory required")
	}
	fd, err := syscall.Open(filepath.Join(directory, "writer.lock"), syscall.O_RDWR|syscall.O_CREAT|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), "writer.lock")
	st, err = f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Mode().Perm() != 0600 || !owned(st) {
		f.Close()
		return nil, errors.New("private lock required")
	}
	if err := syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, errors.New("another accounting writer is active")
	}
	return &FileStore{directory, f}, nil
}
func (s *FileStore) Load() ([]byte, error) {
	if s.lock == nil {
		return nil, errors.New("accounting store closed")
	}
	fd, err := syscall.Open(filepath.Join(s.directory, "journal.json"), syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), "journal.json")
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Mode().Perm() != 0600 || !owned(st) || st.Size() == 0 || st.Size() > 16<<20 {
		return nil, errors.New("unsafe accounting journal")
	}
	return io.ReadAll(io.LimitReader(f, 16<<20+1))
}
func (s *FileStore) Save(data []byte) error {
	if s.lock == nil || len(data) == 0 || len(data) > 16<<20 {
		return errors.New("accounting store unavailable")
	}
	f, err := os.CreateTemp(s.directory, ".journal-*")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if _, err = f.Write(data); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err = os.Rename(name, filepath.Join(s.directory, "journal.json")); err != nil {
		return err
	}
	dir, err := os.Open(s.directory)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
func (s *FileStore) Close() error {
	if s.lock == nil {
		return nil
	}
	err := s.lock.Close()
	s.lock = nil
	return err
}
