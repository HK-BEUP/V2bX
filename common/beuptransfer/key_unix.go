//go:build linux || darwin

package beuptransfer

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

// The dedicated raw 32-byte key lives only inside the already locked private
// scope directory; never reuse the panel API token or fetch a key over HTTP.
func (s *FileStore) ReadKey() ([]byte, error) {
	if s.lock == nil {
		return nil, errors.New("accounting store closed")
	}
	fd, err := syscall.Open(filepath.Join(s.directory, "accounting.key"), syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, errors.New("accounting key unavailable")
	}
	f := os.NewFile(uintptr(fd), "accounting.key")
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Mode().Perm() != 0600 || !owned(st) || st.Size() != 32 {
		return nil, errors.New("private 32-byte accounting key required")
	}
	b, err := io.ReadAll(io.LimitReader(f, 33))
	if err != nil || len(b) != 32 {
		return nil, errors.New("accounting key read failed")
	}
	return b, nil
}
