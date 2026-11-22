package agent

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/yeppao-org/smbdeck/internal/state"
	"github.com/yeppao-org/smbdeck/internal/validate"
)

// harness builds an agent around temporary directories and fake Samba tools.
type harness struct {
	t        *testing.T
	dir      string
	stateDir string
	root     string
	calls    string
	cfg      Config
	a        *Agent
	logs     *syncBuffer
}

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// newHarness: smbstatus prints statusJSON (or fails when it is "fail").
func newHarness(t *testing.T, statusJSON string) *harness {
	h := &harness{t: t, dir: t.TempDir(), logs: &syncBuffer{}}
	h.stateDir = filepath.Join(h.dir, "state")
	h.root = filepath.Join(h.dir, "roots", "drive1")
	h.calls = filepath.Join(h.dir, "calls")
	must(t, os.MkdirAll(h.stateDir, 0o700))
	must(t, os.MkdirAll(filepath.Join(h.root, "data"), 0o755))
	must(t, os.WriteFile(filepath.Join(h.dir, "passwd"), []byte(basePasswd), 0o644))
	must(t, os.WriteFile(filepath.Join(h.dir, "group"), []byte(baseGroup), 0o644))
	fake := func(name, body string) string {
		p := filepath.Join(h.dir, name)
		must(t, os.WriteFile(p, []byte("#!/bin/sh\necho \"$@\" >> "+h.calls+"\n"+body), 0o755))
		return p
	}
	status := "echo '" + statusJSON + "'"
	if statusJSON == "fail" {
		status = "exit 1"
	}
	h.cfg = Config{
		StateDir: h.stateDir, StatusDir: filepath.Join(h.dir, "status"), RunDir: filepath.Join(h.dir, "run"),
		Roots: []Root{{Name: "drive1", Dir: h.root}}, TreeInterval: time.Hour,
		FilesUID: os.Getuid(), FilesGID: os.Getgid(), NetBIOSName: "SMBDECK", ServerString: "smbdeck", Workgroup: "WORKGROUP",
		PollInterval: time.Second, ResyncInterval: time.Minute,
		SMBD: "/nonexistent", BasePasswd: filepath.Join(h.dir, "passwd"), BaseGroup: filepath.Join(h.dir, "group"),
		SMBControl: fake("smbcontrol", ""), SMBStatus: fake("smbstatus", status),
	}
	h.cfg.EtcDir = filepath.Join(h.cfg.RunDir, "etc")
	a, err := New(h.cfg, slog.New(slog.NewTextHandler(h.logs, nil)), "test")
	must(t, err)
	h.a = a
	must(t, a.prepare())
	return h
}

func (h *harness) write(d *state.Desired) {
	h.t.Helper()
	writeDesired(h.t, h.stateDir, d)
}

func (h *harness) sync() { h.a.sync(context.Background(), false) }

func (h *harness) conf() string {
	data, _ := os.ReadFile(filepath.Join(h.cfg.RunDir, "smb.conf"))
	return string(data)
}

func (h *harness) status() *state.Status {
	h.t.Helper()
	st, err := state.ReadStatus(h.cfg.StatusDir)
	if err != nil {
		h.t.Fatal(err)
	}
	return st
}

func (h *harness) shutdowns() string {
	data, _ := os.ReadFile(h.calls)
	var out []string
	for _, l := range strings.Split(string(data), "\n") {
		if rest, ok := strings.CutSuffix(l, " shutdown"); ok {
			out = append(out, rest[strings.LastIndex(rest, " ")+1:])
		}
	}
	return strings.Join(out, ",")
}

func hasIssue(st *state.Status, kind, name string, code validate.Code) bool {
	for _, is := range st.Issues {
		if is.Kind == kind && is.Name == name && is.Code == string(code) {
			return true
		}
	}
	return false
}

// B1. Once an account is removed from /etc/passwd, smbstatus names its
// sessions by UID ("20001"), not by name. The sessions of a deleted account
// must still be closed.
func TestDeletedAccountSessionsAreClosed(t *testing.T) {
	h := newHarness(t, `{"sessions":{"7":{"username":"20001","uid":20001,"server_id":{"pid":"4242"}},"8":{"username":"sue","uid":20000,"server_id":{"pid":"5151"}}}}`)
	d := desired(1)
	h.write(d)
	h.sync()
	d.Revision = 2
	d.Users = slices.DeleteFunc(d.Users, func(u state.User) bool { return u.Name == "alice" })
	h.write(d)
	h.sync()
	if got := h.shutdowns(); got != "4242" {
		t.Fatalf("closed sessions %q, want 4242 (alice's) only", got)
	}
}

// R1. An unreadable desired state at start: smbd still gets a configuration,
// and the refusal is logged once, not at every poll.
func TestUnreadableStateAtStart(t *testing.T) {
	h := newHarness(t, `{}`)
	must(t, os.WriteFile(filepath.Join(h.stateDir, state.DesiredFile), []byte("{not json"), 0o600))
	for range 3 {
		h.sync()
	}
	if !strings.Contains(h.conf(), "[global]") {
		t.Fatal("no smb.conf: smbd cannot start")
	}
	if n := strings.Count(h.logs.String(), "desired state refused"); n != 1 {
		t.Fatalf("refusal logged %d times, want 1", n)
	}
}

// A document with another schemaVersion is refused: the applied configuration
// stays, the problem is reported, and the refusal is logged once.
func TestOtherSchemaVersionKeepsConfiguration(t *testing.T) {
	h := newHarness(t, `{}`)
	h.write(desired(3))
	h.sync()
	if !strings.Contains(h.conf(), "\n[Data]\n") {
		t.Fatal("not applied")
	}
	for _, version := range []int{2, 0} {
		d := desired(4)
		d.SchemaVersion = version
		h.write(d)
		for range 3 {
			h.sync()
		}
		if !strings.Contains(h.conf(), "\n[Data]\n") {
			t.Fatalf("schemaVersion %d: configuration not kept", version)
		}
		st := h.status()
		if st.AppliedRevision != 3 || !hasIssue(st, state.KindState, "", validate.StateSchemaUnsupported) {
			t.Fatalf("schemaVersion %d: status %+v", version, st)
		}
	}
	// Only readDesired logs "keeping the last good one": plan validation has
	// its own, later refusal ("keeping the applied configuration"), so this
	// line proves the agent's own schemaVersion guard ran, once per document.
	if n := strings.Count(h.logs.String(), "desired state refused, keeping the last good one"); n != 2 {
		t.Fatalf("schemaVersion refusals logged %d times, want 2 (one per rewritten document)", n)
	}
}

// R7. desired.json disappearing after it was applied is an error: the last
// configuration stays.
func TestDeletedStateKeepsConfiguration(t *testing.T) {
	h := newHarness(t, `{}`)
	h.write(desired(3))
	h.sync()
	if !strings.Contains(h.conf(), "\n[Data]\n") {
		t.Fatal("not applied")
	}
	must(t, os.Remove(filepath.Join(h.stateDir, state.DesiredFile)))
	h.sync()
	if !strings.Contains(h.conf(), "\n[Data]\n") {
		t.Fatal("shares withdrawn when desired.json disappeared")
	}
	st := h.status()
	if st.AppliedRevision != 3 || !hasIssue(st, state.KindState, "", validate.StateMissing) {
		t.Fatalf("status: %+v", st)
	}
}

// R9. A rewrite with the same size and modification time is applied.
func TestRewriteWithSameSizeAndTime(t *testing.T) {
	h := newHarness(t, `{}`)
	d := desired(1)
	d.Shares[0].Name = "Aaaa"
	h.write(d)
	h.sync()
	path := filepath.Join(h.stateDir, state.DesiredFile)
	fi, _ := os.Stat(path)
	d.Shares[0].Name = "Bbbb"
	data, _ := os.ReadFile(path)
	tmp := path + ".new"
	must(t, os.WriteFile(tmp, bytes.Replace(data, []byte(`"Aaaa"`), []byte(`"Bbbb"`), 1), 0o600))
	must(t, os.Chtimes(tmp, fi.ModTime(), fi.ModTime()))
	must(t, os.Rename(tmp, path))
	h.sync()
	if !strings.Contains(h.conf(), "\n[Bbbb]\n") {
		t.Fatal("rewrite not applied")
	}
}

// R10. A failed apply has its own code; and when smbstatus fails, closing
// the sessions is retried at the next pass, even if nothing else changed.
func TestApplyFailureAndSessionRetry(t *testing.T) {
	h := newHarness(t, "fail")
	d := desired(1)
	h.write(d)
	h.sync()
	d.Revision = 2
	d.Users[1].Disabled = true // alice
	h.write(d)
	h.sync()
	if h.shutdowns() != "" {
		t.Fatal("smbstatus failed, yet a session was closed")
	}
	// smbstatus works again.
	must(t, os.WriteFile(h.cfg.SMBStatus, []byte("#!/bin/sh\necho '{\"sessions\":{\"1\":{\"username\":\"alice\",\"uid\":20001,\"server_id\":{\"pid\":\"777\"}}}}'\n"), 0o755))
	h.sync()
	if got := h.shutdowns(); got != "777" {
		t.Fatalf("not retried: %q", got)
	}

	// The passdb cannot be written: that is an apply failure.
	private := filepath.Join(h.cfg.RunDir, "private")
	must(t, os.RemoveAll(private))
	must(t, os.WriteFile(private, nil, 0o644))
	d.Revision = 3
	d.Users[1].Disabled = false
	h.write(d)
	h.sync()
	if st := h.status(); !hasIssue(st, state.KindState, "", validate.StateApplyFailed) {
		t.Fatalf("issues: %+v", st.Issues)
	}
}

// S10. A share folder is never created through a link, even one that stays
// inside the root (another share's folder could be reached that way).
func TestCreateFolderRefusesLinksInsideRoot(t *testing.T) {
	root := t.TempDir()
	must(t, os.MkdirAll(filepath.Join(root, "a", "other"), 0o755))
	must(t, os.Symlink("other", filepath.Join(root, "a", "link")))
	err := createFolder(os.Getuid(), os.Getgid())(root, "a/link/new")
	if err == nil {
		t.Fatal("created through a link")
	}
	if _, err := os.Stat(filepath.Join(root, "a", "other", "new")); err == nil {
		t.Fatal("folder created in the link's target")
	}
}

// S10. On a file system without Unix owners (exFAT, NTFS), chown fails: the
// folder is not kept, so the next pass does not publish it with the wrong
// owner; the error says why.
func TestCreateFolderWithoutOwnersIsRolledBack(t *testing.T) {
	old := fchown
	fchown = func(int, int, int) error { return syscall.EPERM }
	defer func() { fchown = old }()
	h := newHarness(t, `{}`)
	// The tests run as root: the wanted owner must differ from the creator.
	h.a.cfg.FilesUID, h.a.cfg.FilesGID = 1000, 1000
	d := desired(1)
	d.Shares = []state.Share{{Name: "New", Root: "drive1", Path: "fresh", CreateFolder: true, Access: map[string]state.Access{"sue": "rw"}}}
	h.write(d)
	h.sync()
	if _, err := os.Stat(filepath.Join(h.root, "fresh")); err == nil {
		t.Fatal("folder kept although its owner could not be set")
	}
	if st := h.status(); !hasIssue(st, state.KindShare, "New", validate.SharePathOwnership) {
		t.Fatalf("issues: %+v", st.Issues)
	}
	h.a.sync(context.Background(), true)
	if strings.Contains(h.conf(), "[New]") {
		t.Fatal("published at the next pass")
	}
}

// S2. The agent writes its reports in its own directory, never in the state
// directory the web console controls; and it does not follow a link put in
// place of desired.json (its hash would be published: an oracle).
func TestReportsStayOutOfTheStateDirectory(t *testing.T) {
	h := newHarness(t, `{}`)
	h.write(desired(1))
	h.sync()
	h.a.writeTree()
	for _, f := range []string{state.StatusFile, state.TreeFile, state.AppliedFile} {
		if _, err := os.Lstat(filepath.Join(h.stateDir, f)); err == nil {
			t.Errorf("%s written in the state directory", f)
		}
		if _, err := os.Lstat(filepath.Join(h.cfg.StatusDir, f)); err != nil {
			t.Errorf("%s missing from the status directory", f)
		}
	}
	secret := filepath.Join(h.dir, "secret")
	must(t, os.WriteFile(secret, []byte("someone else's file"), 0o600))
	must(t, os.Remove(filepath.Join(h.stateDir, state.DesiredFile)))
	must(t, os.Symlink(secret, filepath.Join(h.stateDir, state.DesiredFile)))
	h.sync()
	st := h.status()
	if st.ObservedSHA256 == state.Digest([]byte("someone else's file")) {
		t.Fatal("the hash of a linked file was published")
	}
	if !hasIssue(st, state.KindState, "", validate.StateUnreadable) || !strings.Contains(h.conf(), "[Data]") {
		t.Fatalf("link not refused, or configuration lost: %+v", st.Issues)
	}
}

// R1. After a restart, a broken desired.json does not take the shares away:
// the copy of the last applied state is used.
func TestRestartWithBrokenStateUsesLastApplied(t *testing.T) {
	h := newHarness(t, `{}`)
	h.write(desired(4))
	h.sync()
	must(t, os.WriteFile(filepath.Join(h.stateDir, state.DesiredFile), []byte("{broken"), 0o600))
	a, err := New(h.cfg, slog.New(slog.NewTextHandler(h.logs, nil)), "test")
	must(t, err)
	must(t, a.prepare())
	a.sync(context.Background(), true)
	h.a = a
	if !strings.Contains(h.conf(), "\n[Data]\n") {
		t.Fatal("restart lost the shares")
	}
	if st := h.status(); st.AppliedRevision != 4 || !hasIssue(st, state.KindState, "", validate.StateUnreadable) {
		t.Fatalf("status: %+v", st)
	}
}

// R4. The folder tree is breadth first: a crowded first folder must not push
// the others out of the picker.
func TestTreeIsBreadthFirst(t *testing.T) {
	root := t.TempDir()
	for i := range treeMaxFolders + 50 {
		must(t, os.MkdirAll(filepath.Join(root, "a", fmt.Sprintf("x%04d", i)), 0o755))
	}
	must(t, os.Mkdir(filepath.Join(root, "b"), 0o755))
	must(t, os.Mkdir(filepath.Join(root, "c"), 0o755))
	tree := scanTree([]Root{{Name: "r", Dir: root}}, time.Unix(0, 0))
	got := tree.Roots[0].Folders
	if !slices.Contains(got, "b") || !slices.Contains(got, "c") || !tree.Roots[0].Truncated {
		t.Fatalf("b or c missing (or not truncated): %d folders", len(got))
	}
	if len(got) > treeMaxFolders {
		t.Fatalf("%d folders, over the cap", len(got))
	}
}
