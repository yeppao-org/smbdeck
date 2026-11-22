package state

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/yeppao-org/smbdeck/internal/fsutil"
)

// Errors returned by the store.
var (
	// ErrConflict: the desired state changed since the caller read it.
	ErrConflict = errors.New("state: revision conflict")
	// ErrNotInitialized: there is no desired state yet, and there never was.
	ErrNotInitialized = errors.New("state: not initialized")
	// ErrMissing: a desired state existed and is gone.
	ErrMissing = errors.New("state: desired state missing")
	// ErrExists: Create was called but a desired state exists or existed.
	ErrExists = errors.New("state: already initialized")
	// ErrSchema: the desired state was written by another version.
	ErrSchema = errors.New("state: unsupported schema version")
	// ErrTooMany: a list holds more elements than allowed.
	ErrTooMany = errors.New("state: too many elements")
)

// DesiredPerm is the mode of desired.json: it holds NT hashes.
const DesiredPerm = 0o600

// Decode parses desired.json strictly: one JSON object, no unknown or
// duplicate field, no trailing data, and lists bounded while they are read
// (a small file of empty objects would otherwise take a lot of memory).
func Decode(data []byte) (*Desired, error) {
	d, err := decode(data)
	if err != nil {
		return nil, fmt.Errorf("decode desired state: %w", err)
	}
	return d, nil
}

func decode(data []byte) (*Desired, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := expectDelim(dec, '{'); err != nil {
		return nil, err
	}
	var d Desired
	seen := map[string]bool{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		key, _ := tok.(string)
		if seen[key] {
			return nil, fmt.Errorf("duplicate field %q", key)
		}
		seen[key] = true
		switch key {
		case "schemaVersion":
			err = dec.Decode(&d.SchemaVersion)
		case "revision":
			err = dec.Decode(&d.Revision)
		case "nextUid":
			err = dec.Decode(&d.NextUID)
		case "users":
			err = decodeList(dec, MaxUsers, func() error {
				var u User
				if err := dec.Decode(&u); err != nil {
					return err
				}
				d.Users = append(d.Users, u)
				return nil
			})
		case "shares":
			err = decodeList(dec, MaxShares, func() error {
				var s Share
				if err := dec.Decode(&s); err != nil {
					return err
				}
				d.Shares = append(d.Shares, s)
				return nil
			})
		default:
			return nil, fmt.Errorf("unknown field %q", key)
		}
		if err != nil {
			return nil, err
		}
	}
	if err := expectDelim(dec, '}'); err != nil {
		return nil, err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("trailing data")
	}
	return &d, nil
}

func expectDelim(dec *json.Decoder, want json.Delim) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	if d, ok := tok.(json.Delim); !ok || d != want {
		return fmt.Errorf("expected %q", want)
	}
	return nil
}

// decodeList reads a JSON array (or null) element by element, refusing more
// than limit elements before decoding the extra one.
func decodeList(dec *json.Decoder, limit int, each func() error) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	if tok == nil {
		return nil
	}
	if d, ok := tok.(json.Delim); !ok || d != '[' {
		return errors.New("expected a list")
	}
	for n := 0; dec.More(); n++ {
		if n >= limit {
			return ErrTooMany
		}
		if err := each(); err != nil {
			return err
		}
	}
	_, err = dec.Token()
	return err
}

// Encode serializes a desired state. Map keys come out sorted, so equal
// states give equal bytes.
func Encode(d *Desired) ([]byte, error) {
	data, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

// Digest returns the hex SHA-256 of data.
func Digest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// Store reads and writes desired.json for the web console. Writes are atomic,
// serialized (in process and across processes, with a lock file) and guarded
// by the revision the caller last read (optimistic concurrency).
type Store struct {
	dir string
	// Check validates a state before it is written; cur is the state being
	// replaced (nil on Create). A non-nil error aborts the write and is
	// returned to the caller unchanged. It runs with the store locked: it
	// must not call the store.
	Check func(cur, next *Desired) error

	mu     sync.Mutex
	cached *Desired
	key    fileKey
}

// fileKey identifies a version of a file without reading it. The inode
// changes with every atomic rename, even when size and time do not.
type fileKey struct {
	mod  time.Time
	size int64
	ino  uint64
}

// KeyOf returns the key of a file's metadata.
func keyOf(fi os.FileInfo) fileKey {
	k := fileKey{mod: fi.ModTime(), size: fi.Size()}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		k.ino = uint64(st.Ino) //nolint:unconvert // Ino is not uint64 on every platform
	}
	return k
}

// NewStore returns a store for the state directory dir. It removes the
// temporary files a crash may have left behind.
func NewStore(dir string) *Store {
	fsutil.RemoveStaleTemps(dir, DesiredFile)
	return &Store{dir: dir}
}

// Dir returns the state directory.
func (s *Store) Dir() string { return s.dir }

func (s *Store) path() string { return filepath.Join(s.dir, DesiredFile) }

// Load returns a copy of the current desired state. It returns
// ErrNotInitialized when there never was one, ErrMissing when it is gone, and
// ErrSchema when it comes from another version.
func (s *Store) Load() (*Desired, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, err := s.load()
	if err != nil {
		return nil, err
	}
	return d.Clone(), nil
}

func (s *Store) load() (*Desired, error) {
	fi, err := os.Lstat(s.path())
	if errors.Is(err, fs.ErrNotExist) {
		s.cached = nil
		if _, merr := os.Lstat(filepath.Join(s.dir, InitializedFile)); merr == nil {
			return nil, ErrMissing
		}
		return nil, ErrNotInitialized
	}
	if err != nil {
		return nil, err
	}
	key := keyOf(fi)
	if s.cached != nil && key == s.key {
		return s.cached, nil
	}
	data, err := fsutil.ReadLimited(s.path(), MaxDesiredSize)
	if err != nil {
		return nil, err
	}
	d, err := Decode(data)
	if err != nil {
		return nil, err
	}
	if d.SchemaVersion != SchemaVersion {
		return nil, fmt.Errorf("%w: %d", ErrSchema, d.SchemaVersion)
	}
	s.cached, s.key = d, key
	return d, nil
}

// Create writes the first desired state. It fails with ErrExists when one
// exists or ever existed: the first-admin setup and the seed happen once.
func (s *Store) Create(d *Desired) (*Desired, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	unlock, err := lockDir(s.dir)
	if err != nil {
		return nil, err
	}
	defer unlock()
	for _, name := range []string{DesiredFile, InitializedFile} {
		if _, err := os.Lstat(filepath.Join(s.dir, name)); err == nil {
			return nil, ErrExists
		} else if !errors.Is(err, fs.ErrNotExist) {
			return nil, err
		}
	}
	next := d.Clone()
	next.SchemaVersion = SchemaVersion
	next.Revision = 1
	if err := s.write(nil, next); err != nil {
		return nil, err
	}
	// The marker outlives the file: if desired.json disappears later, that
	// is an error to report, not a first start.
	return next, fsutil.WriteAtomic(filepath.Join(s.dir, InitializedFile), []byte("1\n"), DesiredPerm)
}

// Update applies fn to a copy of the state at revision expected and writes the
// result as the next revision. It returns ErrConflict if the state is no
// longer at revision expected. An expected revision of -1 means "whatever the
// current one": for changes that cannot conflict with others (an account
// changing its own password).
func (s *Store) Update(expected int64, fn func(*Desired) error) (*Desired, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	unlock, err := lockDir(s.dir)
	if err != nil {
		return nil, err
	}
	defer unlock()
	s.cached = nil // another process may have written: read from disk
	cur, err := s.load()
	if err != nil {
		return nil, err
	}
	if expected != -1 && cur.Revision != expected {
		return nil, ErrConflict
	}
	next := cur.Clone()
	if err := fn(next); err != nil {
		return nil, err
	}
	next.SchemaVersion = SchemaVersion
	next.Revision = cur.Revision + 1
	return next, s.write(cur, next)
}

func (s *Store) write(cur, d *Desired) error {
	slices.SortFunc(d.Users, func(a, b User) int { return strings.Compare(a.Name, b.Name) })
	slices.SortFunc(d.Shares, func(a, b Share) int {
		return strings.Compare(strings.ToLower(a.Name), strings.ToLower(b.Name))
	})
	if s.Check != nil {
		if err := s.Check(cur, d); err != nil {
			return err
		}
	}
	data, err := Encode(d)
	if err != nil {
		return err
	}
	if len(data) > MaxDesiredSize {
		return ErrTooMany
	}
	if err := fsutil.WriteAtomic(s.path(), data, DesiredPerm); err != nil {
		return err
	}
	s.cached = nil
	return nil
}

// ReadStatus reads status.json from the status directory.
func ReadStatus(dir string) (*Status, error) {
	var st Status
	if err := readJSON(filepath.Join(dir, StatusFile), &st); err != nil {
		return nil, err
	}
	return &st, nil
}

// ReadTree reads tree.json from the status directory.
func ReadTree(dir string) (*Tree, error) {
	var t Tree
	if err := readJSON(filepath.Join(dir, TreeFile), &t); err != nil {
		return nil, err
	}
	return &t, nil
}

func readJSON(path string, v any) error {
	data, err := fsutil.ReadLimited(path, MaxReportSize)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}

// EncodeJSON returns v as indented JSON with a final newline.
func EncodeJSON(v any) ([]byte, error) {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}
