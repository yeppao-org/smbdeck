package state

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
)

func newDesired() *Desired {
	return &Desired{
		SchemaVersion: SchemaVersion,
		Users:         []User{{Name: "sue", UID: FirstUID, NTHash: strings.Repeat("A", 32), Admin: true}},
		Shares:        []Share{{Name: "Data", Root: "drive1", Access: map[string]Access{"sue": ReadWrite}}},
	}
}

func TestCreateOnce(t *testing.T) {
	s := NewStore(t.TempDir())
	if _, err := s.Load(); !errors.Is(err, ErrNotInitialized) {
		t.Fatalf("empty store: %v", err)
	}
	d, err := s.Create(newDesired())
	if err != nil {
		t.Fatal(err)
	}
	if d.Revision != 1 {
		t.Fatalf("revision %d", d.Revision)
	}
	if _, err := s.Create(newDesired()); !errors.Is(err, ErrExists) {
		t.Fatalf("second create: %v", err)
	}
	fi, err := os.Stat(filepath.Join(s.Dir(), DesiredFile))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v, want 0600", fi.Mode().Perm())
	}
}

func TestUpdateRevisionAndConflict(t *testing.T) {
	s := NewStore(t.TempDir())
	if _, err := s.Update(0, func(*Desired) error { return nil }); !errors.Is(err, ErrNotInitialized) {
		t.Fatalf("update before create: %v", err)
	}
	if _, err := s.Create(newDesired()); err != nil {
		t.Fatal(err)
	}
	d, err := s.Update(1, func(d *Desired) error {
		d.Users = append(d.Users, User{Name: "alice", UID: d.AllocUID(), NTHash: strings.Repeat("B", 32)})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if d.Revision != 2 || len(d.Users) != 2 {
		t.Fatalf("got revision %d, %d users", d.Revision, len(d.Users))
	}
	// A writer that read revision 1 must be refused.
	if _, err := s.Update(1, func(d *Desired) error { d.Users = nil; return nil }); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale update: %v", err)
	}
	got, _ := s.Load()
	if got.Revision != 2 || len(got.Users) != 2 {
		t.Fatal("stale update was written")
	}
}

func TestUpdateCheckAndFnErrorsWriteNothing(t *testing.T) {
	s := NewStore(t.TempDir())
	boom := errors.New("refused")
	s.Check = func(_, d *Desired) error {
		if len(d.Users) == 0 {
			return boom
		}
		return nil
	}
	if _, err := s.Create(newDesired()); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Update(1, func(d *Desired) error { d.Users = nil; return nil }); !errors.Is(err, boom) {
		t.Fatalf("check: %v", err)
	}
	if _, err := s.Update(1, func(*Desired) error { return boom }); !errors.Is(err, boom) {
		t.Fatalf("fn: %v", err)
	}
	got, _ := s.Load()
	if got.Revision != 1 || len(got.Users) != 1 {
		t.Fatal("refused update was written")
	}
	// No temporary file is left behind.
	entries, _ := os.ReadDir(s.Dir())
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp-") {
			t.Fatalf("leftover %s", e.Name())
		}
	}
}

func TestLoadReturnsCopies(t *testing.T) {
	s := NewStore(t.TempDir())
	if _, err := s.Create(newDesired()); err != nil {
		t.Fatal(err)
	}
	a, _ := s.Load()
	a.Users[0].Name = "mutated"
	a.Shares[0].Access["x"] = ReadOnly
	b, _ := s.Load()
	if b.Users[0].Name != "sue" || len(b.Shares[0].Access) != 1 {
		t.Fatal("Load shares memory with its cache")
	}
}

func TestConcurrentUpdatesSerialize(t *testing.T) {
	s := NewStore(t.TempDir())
	if _, err := s.Create(newDesired()); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	wins := 0
	for range 8 {
		wg.Go(func() {
			_, err := s.Update(1, func(d *Desired) error { return nil })
			if err == nil {
				mu.Lock()
				wins++
				mu.Unlock()
			} else if !errors.Is(err, ErrConflict) {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if wins != 1 {
		t.Fatalf("%d writers won from the same revision, want 1", wins)
	}
}

func TestDecodeStrict(t *testing.T) {
	good := `{"schemaVersion":1,"revision":3,"users":[],"shares":[]}`
	if _, err := Decode([]byte(good)); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{
		`{"schemaVersion":1,"unknown":true}`,
		good + `{}`,
		`[]`,
		`{"schemaVersion":"1"}`,
		``,
	} {
		if _, err := Decode([]byte(bad)); err == nil {
			t.Errorf("Decode(%q) accepted", bad)
		}
	}
}

func TestEncodeDeterministic(t *testing.T) {
	d := newDesired()
	d.Shares[0].Access = map[string]Access{"zed": ReadOnly, "amy": ReadWrite, "sue": ReadWrite}
	a, _ := Encode(d)
	for range 20 {
		b, _ := Encode(d.Clone())
		if string(a) != string(b) {
			t.Fatal("encoding is not deterministic")
		}
	}
}

// Two stores on the same directory stand for two processes: only the lock
// file serializes them.
func TestConcurrentUpdatesAcrossStores(t *testing.T) {
	dir := t.TempDir()
	if _, err := NewStore(dir).Create(newDesired()); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	wins := 0
	for range 8 {
		s := NewStore(dir)
		wg.Go(func() {
			if _, err := s.Update(1, func(*Desired) error { return nil }); err == nil {
				mu.Lock()
				wins++
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	if wins != 1 {
		t.Fatalf("%d writers won from the same revision, want 1", wins)
	}
}

// A file with more elements than allowed is refused while decoding, before
// it takes memory: [{},{},...] costs far more in memory than on disk.
func TestDecodeRefusesTooManyElements(t *testing.T) {
	many := func(field string, n int) []byte {
		return []byte(fmt.Sprintf(`{"schemaVersion":1,"revision":1,%q:[%s]}`, field, strings.TrimSuffix(strings.Repeat("{},", n), ",")))
	}
	if _, err := Decode(many("users", MaxUsers)); err != nil {
		t.Fatalf("at the limit: %v", err)
	}
	if _, err := Decode(many("users", MaxUsers+1)); err == nil {
		t.Fatal("too many users decoded")
	}
	if _, err := Decode(many("shares", MaxShares+1)); err == nil {
		t.Fatal("too many shares decoded")
	}
	if _, err := Decode([]byte(`{"schemaVersion":1,"schemaVersion":1}`)); err == nil {
		t.Fatal("duplicate key accepted")
	}
	if MaxDesiredSize > 1<<20 {
		t.Fatal("desired.json may be larger than 1 MiB")
	}
}

// A state written by a newer version is never read, so it is never written
// back in the old format.
func TestLoadRefusesFutureSchema(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, DesiredFile), []byte(`{"schemaVersion":2,"revision":5,"users":[],"shares":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	s := NewStore(dir)
	if _, err := s.Load(); !errors.Is(err, ErrSchema) {
		t.Fatalf("load: %v", err)
	}
	if _, err := s.Update(5, func(*Desired) error { return nil }); !errors.Is(err, ErrSchema) {
		t.Fatalf("update: %v", err)
	}
}

// A rewrite with the same size and modification time is still seen: the
// atomic rename gives the file a new inode.
func TestLoadSeesRewriteWithSameSizeAndTime(t *testing.T) {
	dir := t.TempDir()
	s := NewStore(dir)
	d := newDesired()
	d.Users[0].Name = "aaa"
	if _, err := s.Create(d); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, DesiredFile)
	fi, _ := os.Stat(path)
	if got, _ := s.Load(); got.Users[0].Name != "aaa" {
		t.Fatal("first load")
	}
	data, _ := os.ReadFile(path)
	tmp := path + ".new"
	if err := os.WriteFile(tmp, []byte(strings.Replace(string(data), `"aaa"`, `"bbb"`, 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(tmp, fi.ModTime(), fi.ModTime()); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, path); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.Load(); got.Users[0].Name != "bbb" {
		t.Fatal("rewrite with the same size and time not seen")
	}
}

// UIDs are never handed out twice, even after the highest account is deleted:
// the same UID would mean the same SID to clients.
func TestUIDsAreNeverReused(t *testing.T) {
	s := NewStore(t.TempDir())
	if _, err := s.Create(newDesired()); err != nil {
		t.Fatal(err)
	}
	add := func(rev int64, name string) int {
		var uid int
		if _, err := s.Update(rev, func(d *Desired) error {
			uid = d.AllocUID()
			d.Users = append(d.Users, User{Name: name, UID: uid, NTHash: strings.Repeat("C", 32)})
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		return uid
	}
	first := add(1, "alice")
	if _, err := s.Update(2, func(d *Desired) error {
		d.Users = slices.DeleteFunc(d.Users, func(u User) bool { return u.Name == "alice" })
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if second := add(3, "bob"); second <= first {
		t.Fatalf("UID %d handed out again (first was %d)", second, first)
	}
}

// Once a state has existed, its disappearance is an error, not a fresh start:
// the setup page must not reopen.
func TestMissingStateAfterInitialization(t *testing.T) {
	dir := t.TempDir()
	s := NewStore(dir)
	if _, err := s.Create(newDesired()); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, DesiredFile)); err != nil {
		t.Fatal(err)
	}
	if _, err := NewStore(dir).Load(); !errors.Is(err, ErrMissing) {
		t.Fatalf("load: %v", err)
	}
	if _, err := NewStore(dir).Create(newDesired()); !errors.Is(err, ErrExists) {
		t.Fatalf("create after loss: %v", err)
	}

}
