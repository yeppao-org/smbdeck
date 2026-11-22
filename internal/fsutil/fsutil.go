// Package fsutil writes files atomically and reads them defensively.
//
// The state directory is shared between roles that do not trust each other:
// what one writes, the other must read without following a link, without
// blocking on a FIFO, and without reading an unbounded amount.
package fsutil

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
)

// WriteAtomic replaces path with data: it writes a temporary file in the same
// directory with mode perm, syncs it, renames it over path and syncs the
// directory. Readers see either the old content or the new one, never a mix.
func WriteAtomic(path string, data []byte, perm os.FileMode) error {
	return writeAtomic(path, data, perm, true)
}

func writeAtomic(path string, data []byte, perm os.FileMode, sync bool) (err error) {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() {
		if err != nil {
			_ = os.Remove(tmp)
		}
	}()
	if err = f.Chmod(perm); err != nil {
		_ = f.Close()
		return err
	}
	if _, err = f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if sync {
		if err = f.Sync(); err != nil {
			_ = f.Close()
			return err
		}
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Rename(tmp, path); err != nil {
		return err
	}
	if sync {
		syncDir(dir)
	}
	return nil
}

func syncDir(dir string) {
	d, err := os.Open(dir)
	if err != nil {
		return
	}
	defer d.Close()
	// Best effort: some file systems refuse fsync on a directory. The rename
	// is atomic either way; the sync only makes it durable sooner.
	_ = d.Sync()
}

// Writer writes files atomically, and only when their content changed since
// it last wrote them. It compares with what it wrote, kept in memory, and
// never reads the file back: whatever was planted at the path (a link, a
// FIFO) is neither followed nor read, only replaced.
type Writer struct {
	// Sync makes every write durable (fsync). Off for files that are
	// rewritten often and recreated at start anyway: it spares SD cards.
	Sync bool

	mu   sync.Mutex
	last map[string][]byte
}

// Write writes data to path with mode perm if it differs from what this
// writer last wrote there. It reports whether it wrote.
func (w *Writer) Write(path string, data []byte, perm os.FileMode) (bool, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if old, ok := w.last[path]; ok && bytes.Equal(old, data) {
		return false, nil
	}
	if err := writeAtomic(path, data, perm, w.Sync); err != nil {
		return false, err
	}
	if w.last == nil {
		w.last = map[string][]byte{}
	}
	w.last[path] = bytes.Clone(data)
	return true, nil
}

// Forget makes the next Write to path happen whatever its content.
func (w *Writer) Forget(path string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	delete(w.last, path)
}

// ErrTooLarge is returned by ReadLimited for a file over the limit.
var ErrTooLarge = errors.New("file too large")

// ErrNotRegular is returned by ReadLimited for anything but a regular file.
var ErrNotRegular = errors.New("not a regular file")

// ReadLimited reads a whole regular file of at most limit bytes, written by
// someone else: it does not follow a symbolic link (the last component), does
// not block on a FIFO, and checks the type and size on the open descriptor,
// so that nothing can be swapped between the check and the read.
func ReadLimited(path string, limit int64) ([]byte, error) {
	return read(path, limit, syscall.O_NOFOLLOW)
}

// ReadConfig reads a configuration file given by the operator (seed, password
// files). It follows symbolic links, as Kubernetes mounts Secrets and
// ConfigMaps through them, but still refuses anything but a regular file of
// at most limit bytes, without blocking on a FIFO.
func ReadConfig(path string, limit int64) ([]byte, error) {
	return read(path, limit, 0)
}

func read(path string, limit int64, extra int) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_CLOEXEC|extra, 0)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return nil, fmt.Errorf("%s: %w", path, ErrNotRegular)
		}
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s: %w", path, ErrNotRegular)
	}
	if fi.Size() > limit {
		return nil, ErrTooLarge
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, ErrTooLarge
	}
	return data, nil
}

// RemoveStaleTemps removes the temporary files a crash may have left behind
// for base in dir (".<base>.tmp-*").
func RemoveStaleTemps(dir, base string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	prefix := "." + base + ".tmp-"
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), prefix) && e.Type().IsRegular() {
			_ = os.Remove(filepath.Join(dir, e.Name()))
		}
	}
}
