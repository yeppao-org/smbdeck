// Package audit keeps the journal of who changed what, and when. It records
// codes and names only: never a password, a hash, or text typed by a visitor
// (a failed login records the account only when it exists, since people
// sometimes type their password in the user field).
package audit

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"slices"
	"sync"
	"time"
)

// Actions recorded in the journal. The UI translates them ("audit.<action>").
const (
	LoginOK             = "login.ok"
	LoginFailed         = "login.failed"
	LoginBlocked        = "login.blocked"
	Logout              = "logout"
	SetupAdmin          = "setup.admin_created"
	SetupFailed         = "setup.failed"
	SeedApplied         = "seed.applied"
	UserCreated         = "user.created"
	UserDeleted         = "user.deleted"
	UserPasswordReset   = "user.password_reset"
	UserPasswordChanged = "user.password_changed"
	UserDisabled        = "user.disabled"
	UserEnabled         = "user.enabled"
	UserAdminGranted    = "user.admin_granted"
	UserAdminRevoked    = "user.admin_revoked"
	ShareCreated        = "share.created"
	ShareUpdated        = "share.updated"
	ShareDeleted        = "share.deleted"
)

// Actions lists every action, for the translation tests.
func Actions() []string {
	return []string{
		LoginOK, LoginFailed, LoginBlocked, Logout, SetupAdmin, SetupFailed, SeedApplied,
		UserCreated, UserDeleted, UserPasswordReset, UserPasswordChanged, UserDisabled, UserEnabled,
		UserAdminGranted, UserAdminRevoked, ShareCreated, ShareUpdated, ShareDeleted,
	}
}

// Results.
const (
	OK     = "ok"
	Denied = "denied"
)

// Entry is one line of the journal.
type Entry struct {
	Time   time.Time `json:"time"`
	Actor  string    `json:"actor"`
	IP     string    `json:"ip,omitempty"`
	Action string    `json:"action"`
	Target string    `json:"target,omitempty"`
	Result string    `json:"result"`
}

// Log appends entries to a JSON-lines file, rotated to <path>.1 when it grows
// over max bytes: the journal never takes more than twice that.
type Log struct {
	path string
	max  int64
	mu   sync.Mutex
	// lastRead is how many bytes the last Recent read (for the tests).
	lastRead int
}

// New returns a journal at path, bounded by max bytes per file.
func New(path string, max int64) *Log {
	return &Log{path: path, max: max}
}

// Append writes one entry.
func (l *Log) Append(e Entry) error {
	if e.Time.IsZero() {
		e.Time = time.Now()
	}
	e.Time = e.Time.UTC().Truncate(time.Second)
	line, err := json.Marshal(e)
	if err != nil {
		return err
	}
	line = append(line, '\n')
	l.mu.Lock()
	defer l.mu.Unlock()
	if fi, err := os.Stat(l.path); err == nil && fi.Size()+int64(len(line)) > l.max {
		if err := os.Rename(l.path, l.path+".1"); err != nil {
			return err
		}
	}
	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(line); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// tailBytes is how much of the end of each file Recent reads: plenty for
// the few hundred entries shown, whatever the size of the journal.
const tailBytes = 256 << 10

// Recent returns up to n entries, newest first. It reads only the end of the
// current file, and the end of the previous one if that is not enough.
func (l *Log) Recent(n int) ([]Entry, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lastRead = 0
	var newest []Entry
	for _, p := range []string{l.path, l.path + ".1"} {
		entries, read, err := tail(p)
		l.lastRead += read
		if err != nil {
			return nil, err
		}
		slices.Reverse(entries)
		newest = append(newest, entries...)
		if len(newest) >= n {
			break
		}
	}
	if len(newest) > n {
		newest = newest[:n]
	}
	return newest, nil
}

// tail parses the complete lines in the last tailBytes of path.
func tail(path string) ([]Entry, int, error) {
	f, err := os.Open(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, 0, nil
	}
	if err != nil {
		return nil, 0, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, 0, err
	}
	start := max(fi.Size()-tailBytes, 0)
	buf := make([]byte, fi.Size()-start)
	if _, err := f.ReadAt(buf, start); err != nil && !errors.Is(err, io.EOF) {
		return nil, 0, err
	}
	if start > 0 {
		// Drop the line cut in two by the start of the window.
		if i := bytes.IndexByte(buf, '\n'); i >= 0 {
			buf = buf[i+1:]
		}
	}
	var out []Entry
	for _, line := range bytes.Split(buf, []byte{'\n'}) {
		var e Entry
		if len(line) > 0 && json.Unmarshal(line, &e) == nil {
			out = append(out, e)
		}
	}
	return out, len(buf), nil
}
