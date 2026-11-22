// Package agent is the only privileged role: it runs smbd, reads the desired
// state written by the web console, validates every value again, and applies
// what passes. It never executes or writes a value that has not been checked.
//
// The agent reads from the state directory (which the web console controls)
// and writes only to its own directories: the run directory (a tmpfs) and the
// status directory, which the web console mounts read-only.
package agent

import (
	"context"
	"errors"
	"io/fs"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"syscall"
	"time"

	"github.com/yeppao-org/smbdeck/internal/fsutil"
	"github.com/yeppao-org/smbdeck/internal/smbconf"
	"github.com/yeppao-org/smbdeck/internal/state"
	"github.com/yeppao-org/smbdeck/internal/validate"
)

// heartbeat is how often status.json is refreshed even when nothing changes.
// The web console treats a status older than three heartbeats as "agent
// down". Writes are not synced: SD cards last longer.
const heartbeat = time.Minute

// treeScanWarning is how long a folder scan may take before it is reported
// (a hung mount blocks it; the main loop goes on regardless).
const treeScanWarning = 30 * time.Second

// Agent applies the desired state to Samba.
type Agent struct {
	cfg     Config
	log     *slog.Logger
	version string

	base                  baseAccounts
	filesUser, filesGroup string
	sup                   *supervisor
	smb                   samba
	now                   func() time.Time

	// files writes into the run directory, reports into the status
	// directory; both compare with what they last wrote and never read back.
	files, reports fsutil.Writer

	// current is the last desired state read successfully (from
	// desired.json, or from the copy kept at the last successful apply);
	// nil before any. problem says why desired.json is not used right now.
	current     *state.Desired
	currentData []byte
	problem     validate.Code
	observed    observation

	applied   *plan
	appliedAt time.Time
	issues    []state.Issue
	// pendingClose holds the accounts (by UID) whose sessions must still be
	// closed: kept until smbstatus and smbcontrol succeed.
	pendingClose map[int]string

	treeMu    sync.Mutex
	treeBusy  bool
	treeDirty bool
	lastTree  time.Time
}

type observation struct {
	seen     bool
	key      fileKey
	revision int64
	digest   string
}

type fileKey struct {
	exists bool
	mod    time.Time
	size   int64
	ino    uint64
}

// New prepares an agent. It reads the image's base account files.
func New(cfg Config, log *slog.Logger, version string) (*Agent, error) {
	passwd, err := fsutil.ReadLimited(cfg.BasePasswd, 1<<20)
	if err != nil {
		return nil, err
	}
	group, err := fsutil.ReadLimited(cfg.BaseGroup, 1<<20)
	if err != nil {
		return nil, err
	}
	a := &Agent{cfg: cfg, log: log, version: version, now: time.Now, pendingClose: map[int]string{}}
	a.base = parseBase(passwd, group)
	a.filesUser, a.filesGroup = a.base.filesIdentity(cfg.FilesUID, cfg.FilesGID)
	conf := a.confPath()
	a.sup = &supervisor{path: cfg.SMBD, configFile: conf, log: log, stdout: os.Stdout, stderr: os.Stderr,
		changed: make(chan struct{}, 1)}
	a.smb = samba{smbcontrol: cfg.SMBControl, smbstatus: cfg.SMBStatus, configFile: conf, log: log}
	return a, nil
}

func (a *Agent) confPath() string    { return filepath.Join(a.cfg.RunDir, "smb.conf") }
func (a *Agent) passdbPath() string  { return filepath.Join(a.cfg.RunDir, "private", "smbpasswd") }
func (a *Agent) sambaRunDir() string { return filepath.Join(a.cfg.RunDir, "samba") }
func (a *Agent) desiredPath() string { return filepath.Join(a.cfg.StateDir, state.DesiredFile) }
func (a *Agent) markerPath() string  { return filepath.Join(a.cfg.StateDir, state.InitializedFile) }
func (a *Agent) statusPath() string  { return filepath.Join(a.cfg.StatusDir, state.StatusFile) }
func (a *Agent) treePath() string    { return filepath.Join(a.cfg.StatusDir, state.TreeFile) }
func (a *Agent) appliedPath() string { return filepath.Join(a.cfg.StatusDir, state.AppliedFile) }

// mkdir creates missing share folders and marks the folder tree for refresh.
func (a *Agent) mkdir() folderCreator {
	create := createFolder(a.cfg.FilesUID, a.cfg.FilesGID)
	return func(rootDir, rel string) error {
		err := create(rootDir, rel)
		if err == nil {
			a.treeMu.Lock()
			a.treeDirty = true
			a.treeMu.Unlock()
		}
		return err
	}
}

func (a *Agent) global() smbconf.Global {
	return smbconf.Global{
		NetBIOSName: a.cfg.NetBIOSName, ServerString: a.cfg.ServerString, Workgroup: a.cfg.Workgroup,
		HostsAllow: a.cfg.HostsAllow, PassdbPath: a.passdbPath(), RunDir: a.sambaRunDir(),
		LogLevel: a.cfg.SambaLog, Signing: a.cfg.Signing,
	}
}

// prepare creates the agent's writable directories (all under RunDir, so the
// root file system can stay read-only), the base account files and a minimal
// smb.conf (smbd can start whatever the desired state looks like), and
// restores the last state that was applied.
func (a *Agent) prepare() error {
	dirs := []struct {
		path string
		mode os.FileMode
	}{
		{a.cfg.RunDir, 0o755},
		{a.cfg.EtcDir, 0o755},
		{filepath.Join(a.cfg.RunDir, "private"), 0o700},
		{a.sambaRunDir(), 0o755},
		{filepath.Join(a.sambaRunDir(), "lock"), 0o755},
		{filepath.Join(a.sambaRunDir(), "state"), 0o755},
		{filepath.Join(a.sambaRunDir(), "cache"), 0o755},
		{filepath.Join(a.sambaRunDir(), "pid"), 0o755},
		{filepath.Join(a.sambaRunDir(), "ncalrpc"), 0o755},
		{filepath.Join(a.sambaRunDir(), "private"), 0o700},
		{filepath.Join(a.sambaRunDir(), "log"), 0o700},
	}
	for _, d := range dirs {
		if err := os.MkdirAll(d.path, d.mode); err != nil {
			return err
		}
		if err := os.Chmod(d.path, d.mode); err != nil {
			return err
		}
	}
	if err := os.MkdirAll(a.cfg.StatusDir, 0o755); err != nil { //nolint:gosec // G301: the web console (another UID) reads the reports
		return err
	}
	for _, name := range []string{state.StatusFile, state.TreeFile, state.AppliedFile} {
		fsutil.RemoveStaleTemps(a.cfg.StatusDir, name)
	}
	if _, err := os.Stat(a.cfg.StateDir); err != nil {
		return err
	}
	if err := a.writeAccounts(nil); err != nil {
		return err
	}
	conf, err := smbconf.Render(a.global(), nil)
	if err != nil {
		return err
	}
	if _, err := a.files.Write(a.confPath(), conf, 0o644); err != nil {
		return err
	}
	// The copy of the last applied state is re-validated like any other.
	if data, err := fsutil.ReadLimited(a.appliedPath(), state.MaxDesiredSize); err == nil {
		if d, err := state.Decode(data); err == nil && d.SchemaVersion == state.SchemaVersion {
			a.current, a.currentData = d, data
			a.log.Info("restored the last applied state", "revision", d.Revision)
		}
	}
	return nil
}

func (a *Agent) writeAccounts(users []state.User) error {
	if _, err := a.files.Write(filepath.Join(a.cfg.EtcDir, "passwd"),
		renderPasswd(a.base, a.cfg.FilesUID, a.cfg.FilesGID, users), 0o644); err != nil {
		return err
	}
	if _, err := a.files.Write(filepath.Join(a.cfg.EtcDir, "group"),
		renderGroup(a.base, a.cfg.FilesGID), 0o644); err != nil {
		return err
	}
	_, err := a.files.Write(a.passdbPath(), renderSMBPasswd(users), 0o600)
	return err
}

// Run applies the desired state until ctx ends.
func (a *Agent) Run(ctx context.Context) error {
	if err := a.prepare(); err != nil {
		return err
	}
	a.log.Info("agent starting", "version", a.version, "roots", len(a.cfg.Roots),
		"filesUser", a.filesUser, "filesGroup", a.filesGroup)
	a.sync(ctx, true)
	a.refreshTree()

	supDone := make(chan struct{})
	go func() {
		a.sup.run(ctx)
		close(supDone)
	}()

	poll := time.NewTicker(a.cfg.PollInterval)
	resync := time.NewTicker(a.cfg.ResyncInterval)
	tree := time.NewTicker(a.cfg.TreeInterval)
	beat := time.NewTicker(heartbeat)
	defer poll.Stop()
	defer resync.Stop()
	defer tree.Stop()
	defer beat.Stop()
	for {
		select {
		case <-ctx.Done():
			<-supDone
			a.writeStatus()
			a.log.Info("agent stopped")
			return nil
		case <-poll.C:
			a.sync(ctx, false)
		case <-resync.C:
			a.sync(ctx, true)
		case <-tree.C:
			a.refreshTree()
		case <-beat.C:
			a.writeStatus()
		case <-a.sup.changed:
			a.writeStatus()
		}
		a.treeMu.Lock()
		dirty := a.treeDirty
		a.treeMu.Unlock()
		if dirty {
			a.refreshTree()
		}
	}
}

func (a *Agent) statDesired() (fileKey, error) {
	fi, err := os.Lstat(a.desiredPath())
	if errors.Is(err, fs.ErrNotExist) {
		return fileKey{}, nil
	}
	if err != nil {
		return fileKey{}, err
	}
	k := fileKey{exists: true, mod: fi.ModTime(), size: fi.Size()}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		k.ino = uint64(st.Ino) //nolint:unconvert // not uint64 on every platform
	}
	return k, nil
}

// sync reads the desired state if its file changed and applies it. With
// force, it applies the current state again anyway: links and mounts can
// change on disk, and every path is resolved again.
func (a *Agent) sync(ctx context.Context, force bool) {
	key, err := a.statDesired()
	if err != nil {
		a.log.Error("cannot stat the desired state", "err", err)
		return
	}
	changed := !a.observed.seen || key != a.observed.key
	if !changed && !force && len(a.pendingClose) == 0 {
		return
	}
	if changed {
		a.observed.seen, a.observed.key = true, key
		a.readDesired(key)
	}

	d := a.current
	if d == nil {
		d = &state.Desired{SchemaVersion: state.SchemaVersion}
	}
	p := buildPlan(d, a.cfg.Roots, a.base, a.filesUser, a.filesGroup, a.mkdir())
	p.digest = state.Digest(a.currentData)
	if a.current == nil {
		// Nothing asked yet: an empty state has no administrator, which is
		// expected until the first one is created.
		p.issues = nil
	}
	if fatal := fatalIssue(p.issues); fatal != "" {
		a.log.Error("desired state refused, keeping the applied configuration", "code", fatal, "revision", d.Revision)
		a.issues = a.withProblem(p.issues)
		a.writeStatus()
		return
	}
	newRevision := a.applied == nil || a.applied.revision != p.revision || a.applied.digest != p.digest
	if err := a.apply(ctx, &p); err != nil {
		a.log.Error("apply failed", "err", err, "revision", p.revision)
		a.issues = a.withProblem(append(p.issues, state.Issue{Kind: state.KindState, Code: string(validate.StateApplyFailed)}))
		a.writeStatus()
		return
	}
	if newRevision && a.current != nil {
		// Kept so that a restart with a broken desired.json still serves
		// the last good configuration.
		if _, err := a.reports.Write(a.appliedPath(), a.currentData, 0o600); err != nil {
			a.log.Warn("cannot keep a copy of the applied state", "err", err)
		}
	}
	a.issues = a.withProblem(p.issues)
	a.writeStatus()
}

// readDesired reads desired.json after its file changed. On any problem the
// current state stays what it was, and the problem is logged once (sync
// calls this only when the file changes).
func (a *Agent) readDesired(key fileKey) {
	fail := func(code validate.Code, err error) {
		a.problem = code
		a.log.Error("desired state refused, keeping the last good one", "code", string(code), "err", err)
	}
	if !key.exists {
		_, markerErr := os.Lstat(a.markerPath())
		if a.current != nil || markerErr == nil {
			fail(validate.StateMissing, fs.ErrNotExist)
			return
		}
		a.problem = ""
		return
	}
	data, err := fsutil.ReadLimited(a.desiredPath(), state.MaxDesiredSize)
	if err != nil {
		fail(validate.StateUnreadable, err)
		return
	}
	d, err := state.Decode(data)
	if err != nil {
		fail(validate.StateUnreadable, err)
		return
	}
	if d.SchemaVersion != state.SchemaVersion {
		fail(validate.StateSchemaUnsupported, errors.New("schema version"))
		return
	}
	a.current, a.currentData, a.problem = d, data, ""
	a.observed.revision, a.observed.digest = d.Revision, state.Digest(data)
}

func (a *Agent) withProblem(issues []state.Issue) []state.Issue {
	if a.problem == "" {
		return issues
	}
	return append([]state.Issue{{Kind: state.KindState, Code: string(a.problem)}}, issues...)
}

func fatalIssue(issues []state.Issue) string {
	for _, is := range issues {
		if is.Kind == state.KindState && is.Code != string(validate.StateNoAdmin) {
			return is.Code
		}
	}
	return ""
}

// apply writes the account files and smb.conf, reloads smbd if the
// configuration changed, and ends the sessions that lost something.
func (a *Agent) apply(ctx context.Context, p *plan) error {
	shares := make([]smbconf.Share, 0, len(p.shares))
	for _, s := range p.shares {
		shares = append(shares, s.conf)
	}
	conf, err := smbconf.Render(a.global(), shares)
	if err != nil {
		// Unreachable when validation holds; refusing here is the last line.
		return err
	}
	if err := a.writeAccounts(p.users); err != nil {
		return err
	}
	changed, err := a.files.Write(a.confPath(), conf, 0o644)
	if err != nil {
		return err
	}
	if running, _, _ := a.sup.snapshot(); changed && running {
		if err := a.smb.reload(ctx); err != nil {
			a.log.Warn("reload failed; smbd re-reads its configuration periodically", "err", err)
		}
	}
	// Sessions are matched by UID: once an account is gone from
	// /etc/passwd, smbstatus no longer knows its name.
	maps.Copy(a.pendingClose, sessionsToClose(a.applied, p))
	if len(a.pendingClose) > 0 {
		if err := a.smb.closeSessions(ctx, a.pendingClose, a.sup.mainPID()); err != nil {
			a.log.Warn("could not close sessions, will retry", "accounts", slices.Collect(maps.Values(a.pendingClose)), "err", err)
		} else {
			clear(a.pendingClose)
		}
	}
	if a.applied == nil || a.applied.revision != p.revision || a.applied.digest != p.digest || changed {
		a.appliedAt = a.now()
		a.log.Info("desired state applied", "revision", p.revision, "users", len(p.users),
			"shares", len(p.shares), "issues", len(p.issues))
	}
	a.applied = p
	return nil
}

func (a *Agent) writeStatus() {
	running, since, restarts := a.sup.snapshot()
	st := state.Status{
		SchemaVersion:    state.SchemaVersion,
		ObservedRevision: a.observed.revision,
		ObservedSHA256:   a.observed.digest,
		AppliedAt:        a.appliedAt.UTC(),
		UpdatedAt:        a.now().UTC(),
		AgentVersion:     a.version,
		SMBD:             state.SMBDStatus{Running: running, Since: since.UTC(), Restarts: restarts},
		Roots:            []state.RootStatus{},
		Issues:           slices.Clone(a.issues),
	}
	if st.Issues == nil {
		st.Issues = []state.Issue{}
	}
	if a.applied != nil {
		st.AppliedRevision = a.applied.revision
		st.Roots = a.applied.roots
	}
	data, err := state.EncodeJSON(st)
	if err == nil {
		_, err = a.reports.Write(a.statusPath(), data, 0o644)
	}
	if err != nil {
		a.log.Error("cannot write status", "err", err)
	}
}

// refreshTree scans the folders of the roots in the background: a hung mount
// must not stop the agent. One scan at a time.
func (a *Agent) refreshTree() {
	a.treeMu.Lock()
	if a.treeBusy {
		a.treeMu.Unlock()
		return
	}
	a.treeBusy, a.treeDirty = true, false
	a.treeMu.Unlock()
	go func() {
		done := make(chan struct{})
		go func() {
			select {
			case <-done:
			case <-time.After(treeScanWarning):
				a.log.Warn("folder scan is slow; is a root on a hung mount?")
			}
		}()
		a.writeTree()
		close(done)
		a.treeMu.Lock()
		a.treeBusy = false
		a.treeMu.Unlock()
	}()
}

// writeTree scans and writes tree.json now.
func (a *Agent) writeTree() {
	now := a.now()
	data, err := state.EncodeJSON(scanTree(a.cfg.Roots, now))
	if err == nil {
		_, err = a.reports.Write(a.treePath(), data, 0o644)
	}
	if err != nil {
		a.log.Error("cannot write tree", "err", err)
	}
	a.treeMu.Lock()
	a.lastTree = now
	a.treeMu.Unlock()
}
