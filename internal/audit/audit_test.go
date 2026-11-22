package audit

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestAppendRecentAndRotation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	l := New(path, 600)
	for i := range 20 {
		if err := l.Append(Entry{Time: time.Unix(int64(i), 0), Actor: "sue", Action: UserCreated, Target: fmt.Sprintf("u%d", i), Result: OK}); err != nil {
			t.Fatal(err)
		}
	}
	got, err := l.Recent(5)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 5 || got[0].Target != "u19" || got[4].Target != "u15" {
		t.Fatalf("recent: %+v", got)
	}
	for _, p := range []string{path, path + ".1"} {
		fi, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Size() > 600 {
			t.Errorf("%s is %d bytes, over the bound", p, fi.Size())
		}
		if fi.Mode().Perm() != 0o600 && p == path {
			t.Errorf("mode %v", fi.Mode().Perm())
		}
	}
	all, _ := l.Recent(1000)
	if len(all) >= 20 {
		t.Errorf("rotation kept everything (%d entries)", len(all))
	}
}

// The journal is shown from its end: Recent reads a bounded tail, however
// large the files are, and still returns the newest entries in order.
func TestRecentReadsOnlyTheEnd(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	l := New(path, 64<<20)
	var buf []byte
	for i := range 40000 {
		buf = fmt.Appendf(buf, `{"time":"2026-01-01T00:00:00Z","actor":"sue","action":"user.created","target":"u%d","result":"ok"}`+"\n", i)
	}
	if err := os.WriteFile(path, buf, 0o600); err != nil {
		t.Fatal(err)
	}
	if len(buf) <= tailBytes {
		t.Fatalf("test file (%d bytes) smaller than the tail (%d)", len(buf), tailBytes)
	}
	got, err := l.Recent(3)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || got[0].Target != "u39999" || got[2].Target != "u39997" {
		t.Fatalf("recent: %+v", got)
	}
	if read := l.lastRead; read > 2*tailBytes {
		t.Fatalf("read %d bytes for 3 entries", read)
	}
}

func TestRecentOnEmptyLog(t *testing.T) {
	l := New(filepath.Join(t.TempDir(), "audit.log"), 1<<20)
	got, err := l.Recent(10)
	if err != nil || len(got) != 0 {
		t.Fatalf("%v %v", got, err)
	}
}
