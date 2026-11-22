package fsutil

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// within fails the test if fn does not return in time (a FIFO would block a
// careless reader forever).
func within(t *testing.T, d time.Duration, fn func()) {
	t.Helper()
	done := make(chan struct{})
	go func() { fn(); close(done) }()
	select {
	case <-done:
	case <-time.After(d):
		t.Fatal("blocked")
	}
}

func TestReadLimitedRefusesWhatIsNotARegularFile(t *testing.T) {
	dir := t.TempDir()
	secret := filepath.Join(dir, "secret")
	if err := os.WriteFile(secret, []byte("not yours"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(secret, link); err != nil {
		t.Fatal(err)
	}
	zero := filepath.Join(dir, "zero")
	if err := os.Symlink("/dev/zero", zero); err != nil {
		t.Fatal(err)
	}
	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{link, zero, fifo, dir} {
		within(t, 2*time.Second, func() {
			if data, err := ReadLimited(p, 1<<20); err == nil {
				t.Errorf("%s read (%d bytes)", filepath.Base(p), len(data))
			}
		})
	}
	big := filepath.Join(dir, "big")
	if err := os.WriteFile(big, bytes.Repeat([]byte("x"), 2048), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadLimited(big, 1024); !errors.Is(err, ErrTooLarge) {
		t.Errorf("oversized file: %v", err)
	}
	if data, err := ReadLimited(secret, 1024); err != nil || string(data) != "not yours" {
		t.Errorf("regular file: %q %v", data, err)
	}
}

// The writer never reads back what is on disk: it compares with what it last
// wrote. A FIFO or a link planted at the path must neither block it nor be
// followed.
func TestWriterComparesWithMemory(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "status.json")
	if err := syscall.Mkfifo(p, 0o600); err != nil {
		t.Fatal(err)
	}
	var w Writer
	within(t, 2*time.Second, func() {
		changed, err := w.Write(p, []byte("one"), 0o644)
		if err != nil || !changed {
			t.Errorf("first write: %v %v", changed, err)
		}
	})
	fi, err := os.Lstat(p)
	if err != nil || !fi.Mode().IsRegular() || fi.Mode().Perm() != 0o644 {
		t.Fatalf("not replaced by a regular file: %v %v", fi.Mode(), err)
	}
	if changed, _ := w.Write(p, []byte("one"), 0o644); changed {
		t.Error("identical content written again")
	}
	if changed, _ := w.Write(p, []byte("two"), 0o644); !changed {
		t.Error("new content not written")
	}
}

func TestRemoveStaleTemps(t *testing.T) {
	dir := t.TempDir()
	for _, n := range []string{".desired.json.tmp-123", ".desired.json.tmp-abc", "desired.json", ".other.tmp-1"} {
		if err := os.WriteFile(filepath.Join(dir, n), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	RemoveStaleTemps(dir, "desired.json")
	entries, _ := os.ReadDir(dir)
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	if len(names) != 2 || names[0] != ".other.tmp-1" || names[1] != "desired.json" {
		t.Fatalf("left %v", names)
	}
}
