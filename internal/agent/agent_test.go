package agent

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/yeppao-org/smbdeck/internal/config"
	"github.com/yeppao-org/smbdeck/internal/nthash"
	"github.com/yeppao-org/smbdeck/internal/state"
	"github.com/yeppao-org/smbdeck/internal/validate"
)

const basePasswd = `root:x:0:0:root:/root:/bin/sh
nobody:x:65534:65534:nobody:/:/sbin/nologin
avahi:x:86:86:avahi:/var/lib/avahi:/sbin/nologin
smbdeck:x:10001:10001:smbdeck:/nonexistent:/sbin/nologin
legacy:x:20005:100::/nonexistent:/sbin/nologin
`

const baseGroup = `root:x:0:root
users:x:100:
nogroup:x:65533:
smbdeck:x:10001:
`

func TestParseRoots(t *testing.T) {
	roots, err := ParseRoots(" drive2=/roots/drive2 , drive1=/roots/drive1")
	if err != nil {
		t.Fatal(err)
	}
	if len(roots) != 2 || roots[0].Name != "drive1" || roots[1].Dir != "/roots/drive2" {
		t.Fatalf("got %+v", roots)
	}
	if r, err := ParseRoots(""); err != nil || len(r) != 0 {
		t.Fatal("empty list refused")
	}
	for _, bad := range []string{
		"drive1", "=/roots/a", "Drive=/roots/a", "a=/data", "a=/roots", "a=/roots/", "a=/roots/../etc",
		"a=/roots/x/", "a=relative", "a=/roots/a,a=/roots/b", "a=/roots/a,b=/roots/a/sub",
		"a=/roots/a\nb", "a=/roots/%U",
	} {
		if _, err := ParseRoots(bad); err == nil {
			t.Errorf("ParseRoots(%q) accepted", bad)
		}
	}
}

func TestFromEnv(t *testing.T) {
	c, err := FromEnv(config.MapEnv(map[string]string{"SMBDECK_ROOTS": "d=/roots/d", "SMBDECK_SMB_HOSTS_ALLOW": "192.168.1.0/24,10.0.0.1"}))
	if err != nil {
		t.Fatal(err)
	}
	if c.FilesUID != 1000 || c.NetBIOSName != "SMBDECK" || !slices.Equal(c.HostsAllow, []string{"192.168.1.0/24", "10.0.0.1/32"}) {
		t.Fatalf("defaults: %+v", c)
	}
	for k, v := range map[string]string{
		"SMBDECK_FILES_UID":         "0",
		"SMBDECK_FILES_GID":         "0",
		"SMBDECK_SMB_NETBIOS_NAME":  "much-too-long-name",
		"SMBDECK_SMB_SERVER_STRING": "x\n[global]",
		"SMBDECK_SMB_HOSTS_ALLOW":   "everyone",
		"SMBDECK_STATE_DIR":         "relative",
	} {
		if _, err := FromEnv(config.MapEnv(map[string]string{k: v})); err == nil {
			t.Errorf("%s=%q accepted", k, v)
		}
	}
	if _, err := FromEnv(config.MapEnv(map[string]string{"SMBDECK_FILES_UID": "20001"})); err == nil {
		t.Error("files UID in the account range accepted")
	}
	if c, err := FromEnv(config.MapEnv(map[string]string{"SMBDECK_FILES_UID": "100000"})); err != nil || c.FilesUID != 100000 {
		t.Error("files UID above the account range refused")
	}
}

func TestAccountFiles(t *testing.T) {
	base := parseBase([]byte(basePasswd), []byte(baseGroup))
	user, group := base.filesIdentity(1000, 100)
	if user != "smbdeck-files" || group != "users" {
		t.Fatalf("files identity %s:%s", user, group)
	}
	if u, _ := base.filesIdentity(65534, 1); u != "nobody" {
		t.Fatal("existing UID not reused")
	}
	users := []state.User{
		{Name: "sue", UID: 20000, NTHash: strings.Repeat("a", 32), PasswordChangedAt: time.Unix(0x5f5e1000, 0)},
		{Name: "bob", UID: 20001, NTHash: strings.Repeat("B", 32), Disabled: true},
	}
	passwd := string(renderPasswd(base, 1000, 100, users))
	for _, want := range []string{
		"root:x:0:0:root:/root:/bin/sh\n",
		"smbdeck-files:x:1000:100:smbdeck file owner:/nonexistent:/sbin/nologin\n",
		"sue:x:20000:100:smbdeck account:/nonexistent:/sbin/nologin\n",
	} {
		if !strings.Contains(passwd, want) {
			t.Errorf("passwd lacks %q", want)
		}
	}
	group2 := string(renderGroup(base, 1000))
	if !strings.HasSuffix(group2, "smbdeck-files:x:1000:\n") {
		t.Errorf("group: %q", group2)
	}
	if strings.Contains(string(renderGroup(base, 100)), "smbdeck-files") {
		t.Error("existing group duplicated")
	}
	got := string(renderSMBPasswd(users))
	want := "sue:20000:XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:[UX         ]:LCT-5F5E1000:\n" +
		"bob:20001:XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB:[UDX        ]:LCT-00000000:\n"
	if got != want {
		t.Fatalf("smbpasswd:\n%s\nwant:\n%s", got, want)
	}
	if !base.conflicts(state.User{Name: "legacy", UID: 20999}) || !base.conflicts(state.User{Name: "x", UID: 20005}) {
		t.Error("base conflicts not detected")
	}
}

func hash(pw string) string { return nthash.Sum(pw).String() }

func desired(rev int64) *state.Desired {
	return &state.Desired{
		SchemaVersion: 1, Revision: rev,
		Users: []state.User{
			{Name: "sue", UID: 20000, NTHash: hash("one"), Admin: true},
			{Name: "alice", UID: 20001, NTHash: hash("two")},
			{Name: "bob", UID: 20002, NTHash: hash("three"), Disabled: true},
		},
		Shares: []state.Share{
			{Name: "Data", Root: "drive1", Path: "data", Access: map[string]state.Access{"sue": "rw", "alice": "ro", "bob": "rw"}},
			{Name: "Bob only", Root: "drive1", Path: "data", Access: map[string]state.Access{"bob": "rw"}},
		},
	}
}

func TestBuildPlan(t *testing.T) {
	root := t.TempDir()
	must(t, os.Mkdir(filepath.Join(root, "data"), 0o755))
	outside := t.TempDir()
	must(t, os.Symlink(outside, filepath.Join(root, "escape")))
	base := parseBase([]byte(basePasswd), []byte(baseGroup))
	roots := []Root{{Name: "drive1", Dir: root}, {Name: "gone", Dir: filepath.Join(root, "missing")}}

	d := desired(4)
	d.Users = append(d.Users, state.User{Name: "legacy", UID: 20010, NTHash: hash("x")})
	d.Shares = append(d.Shares,
		state.Share{Name: "Escape", Root: "drive1", Path: "escape", Access: map[string]state.Access{"sue": "rw"}},
		state.Share{Name: "Missing", Root: "drive1", Path: "nope", Access: map[string]state.Access{"sue": "rw"}},
		state.Share{Name: "Unmounted", Root: "gone", Access: map[string]state.Access{"sue": "rw"}},
	)
	p := buildPlan(d, roots, base, "smbdeck-files", "users", nil)
	if p.revision != 4 {
		t.Fatal("revision")
	}
	if names := userNames(p.users); !slices.Equal(names, []string{"sue", "alice", "bob"}) {
		t.Fatalf("users %v", names)
	}
	if len(p.shares) != 2 {
		t.Fatalf("shares %+v", p.shares)
	}
	data := p.share("data")
	if data == nil || !slices.Equal(data.conf.WriteUsers, []string{"sue"}) || !slices.Equal(data.conf.ReadUsers, []string{"alice"}) {
		t.Fatalf("Data: %+v", data)
	}
	if data.access["bob"] != "rw" {
		t.Error("disabled account's access forgotten (needed to close its sessions later)")
	}
	codes := issueCodes(p.issues)
	for _, want := range []string{
		"user:legacy:" + string(validate.UserNameReserved),
		"share:Escape:" + string(validate.SharePathOutsideRoot),
		"share:Missing:" + string(validate.SharePathMissing),
		"share:Unmounted:" + string(validate.ShareRootUnavailable),
	} {
		if !slices.Contains(codes, want) {
			t.Errorf("missing issue %s in %v", want, codes)
		}
	}
	if p.roots[1].Available {
		t.Error("missing root reported available")
	}
}

func TestBuildPlanCreatesFolderInsideRootOnly(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	must(t, os.Symlink(outside, filepath.Join(root, "link")))
	base := parseBase([]byte(basePasswd), []byte(baseGroup))
	d := desired(1)
	d.Shares = []state.Share{
		{Name: "New", Root: "drive1", Path: "a/b", CreateFolder: true, Access: map[string]state.Access{"sue": "rw"}},
		{Name: "Sneaky", Root: "drive1", Path: "link/x", CreateFolder: true, Access: map[string]state.Access{"sue": "rw"}},
	}
	p := buildPlan(d, []Root{{Name: "drive1", Dir: root}}, base, "f", "g", createFolder(os.Getuid(), os.Getgid()))
	if p.share("New") == nil {
		t.Fatalf("folder not created: %v", issueCodes(p.issues))
	}
	fi, err := os.Stat(filepath.Join(root, "a", "b"))
	if err != nil || !fi.IsDir() || fi.Mode()&os.ModeSetgid == 0 || fi.Mode().Perm() != 0o775 {
		t.Fatalf("created folder: %v %v", fi.Mode(), err)
	}
	if p.share("Sneaky") != nil {
		t.Fatal("share through a link out of the root was planned")
	}
	if _, err := os.Stat(filepath.Join(outside, "x")); err == nil {
		t.Fatal("folder created outside the root")
	}
}

func TestSessionsToClose(t *testing.T) {
	root := t.TempDir()
	must(t, os.Mkdir(filepath.Join(root, "data"), 0o755))
	must(t, os.Mkdir(filepath.Join(root, "other"), 0o755))
	base := parseBase([]byte(basePasswd), []byte(baseGroup))
	roots := []Root{{Name: "drive1", Dir: root}}
	plan := func(d *state.Desired) *plan {
		p := buildPlan(d, roots, base, "f", "g", nil)
		return &p
	}
	old := plan(desired(1))
	names := func(m map[int]string) []string {
		var out []string
		for _, n := range m {
			out = append(out, n)
		}
		slices.Sort(out)
		return out
	}
	cases := []struct {
		name string
		edit func(*state.Desired)
		want []string
	}{
		{"no change", func(*state.Desired) {}, nil},
		{"access widened", func(d *state.Desired) { d.Shares[0].Access["alice"] = "rw" }, []string{"alice"}},
		{"access new on a share", func(d *state.Desired) { d.Shares[1].Access["alice"] = "rw" }, nil},
		{"new account", func(d *state.Desired) {
			d.Users = append(d.Users, state.User{Name: "carol", UID: 20003, NTHash: hash("c")})
		}, nil},
		{"admin flag", func(d *state.Desired) { d.Users[1].Admin = true }, nil},
		{"deleted", func(d *state.Desired) { d.Users = d.Users[:1]; delete(d.Shares[0].Access, "alice") }, []string{"alice", "bob"}},
		{"disabled", func(d *state.Desired) { d.Users[1].Disabled = true }, []string{"alice"}},
		{"password", func(d *state.Desired) { d.Users[0].NTHash = hash("new") }, []string{"sue"}},
		{"downgraded", func(d *state.Desired) { d.Shares[0].Access["sue"] = "ro" }, []string{"sue"}},
		{"removed from share", func(d *state.Desired) { delete(d.Shares[0].Access, "alice") }, []string{"alice"}},
		{"share deleted", func(d *state.Desired) { d.Shares = d.Shares[1:] }, []string{"alice", "bob", "sue"}},
		{"share moved", func(d *state.Desired) { d.Shares[0].Path = "other" }, []string{"alice", "bob", "sue"}},
	}
	for _, c := range cases {
		d := desired(2)
		c.edit(d)
		got := names(sessionsToClose(old, plan(d)))
		if !slices.Equal(got, c.want) {
			t.Errorf("%s: closes %v, want %v", c.name, got, c.want)
		}
	}
	if len(sessionsToClose(nil, old)) != 0 {
		t.Error("first apply closes sessions")
	}
}

func TestSessionPIDs(t *testing.T) {
	// smbstatus names a session after the UID's entry in /etc/passwd: a
	// deleted account shows as its UID in digits. Only "uid" is reliable.
	out := []byte(`{"version":"4.23.8","sessions":{
		"1":{"username":"alice","uid":20001,"server_id":{"pid":"58"}},
		"2":{"username":"20001","uid":20001,"server_id":{"pid":"61"}},
		"3":{"username":"sue","uid":20000,"server_id":{"pid":"70"}},
		"4":{"username":"bob","uid":20002,"server_id":{"pid":"1"}},
		"5":{"username":"bob","uid":20002,"server_id":{"pid":"x"}}},"tcons":{}}`)
	got, err := sessionPIDs(out, map[int]string{20001: "alice", 20002: "bob"})
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(got[20001])
	if !slices.Equal(got[20001], []int{58, 61}) || len(got[20002]) != 0 || len(got[20000]) != 0 {
		t.Fatalf("got %v", got)
	}
	if _, err := sessionPIDs([]byte("not json"), nil); err == nil {
		t.Fatal("garbage accepted")
	}
}

func TestScanTree(t *testing.T) {
	root := t.TempDir()
	for _, d := range []string{"a/b/c", "a/d", "Été 2024", ".hidden/x", "pct%U", "bad\\name"} {
		must(t, os.MkdirAll(filepath.Join(root, d), 0o755))
	}
	must(t, os.WriteFile(filepath.Join(root, "file"), nil, 0o644))
	must(t, os.Symlink("/", filepath.Join(root, "link")))
	tree := scanTree([]Root{{Name: "r", Dir: root}, {Name: "gone", Dir: filepath.Join(root, "nope")}}, time.Unix(0, 0))
	got := tree.Roots[0].Folders
	want := []string{"a", "a/b", "a/d", "Été 2024"}
	if !slices.Equal(got, want) {
		t.Fatalf("folders %q, want %q", got, want)
	}
	if !tree.Roots[0].Available || tree.Roots[1].Available || tree.Roots[1].Folders == nil {
		t.Fatalf("availability: %+v", tree.Roots)
	}
}

// The whole pass, without smbd: the agent reads a desired state written by
// hand, refuses what does not pass, and writes the files Samba reads.
func TestAgentSyncWritesFiles(t *testing.T) {
	dir := t.TempDir()
	stateDir := filepath.Join(dir, "state")
	root := filepath.Join(dir, "roots", "drive1")
	must(t, os.MkdirAll(stateDir, 0o700))
	must(t, os.MkdirAll(filepath.Join(root, "data"), 0o755))
	must(t, os.Symlink("/etc", filepath.Join(root, "etc")))
	must(t, os.WriteFile(filepath.Join(dir, "passwd"), []byte(basePasswd), 0o644))
	must(t, os.WriteFile(filepath.Join(dir, "group"), []byte(baseGroup), 0o644))
	calls := filepath.Join(dir, "calls")
	fake := func(name, body string) string {
		p := filepath.Join(dir, name)
		must(t, os.WriteFile(p, []byte("#!/bin/sh\necho \"$@\" >> "+calls+"\n"+body), 0o755))
		return p
	}
	cfg := Config{
		StateDir: stateDir, StatusDir: filepath.Join(dir, "status"), RunDir: filepath.Join(dir, "run"),
		Roots: []Root{{Name: "drive1", Dir: root}}, TreeInterval: time.Hour,
		FilesUID: 1000, FilesGID: 100, NetBIOSName: "SMBDECK", ServerString: "smbdeck", Workgroup: "WORKGROUP",
		PollInterval: time.Second, ResyncInterval: time.Minute,
		SMBD: "/nonexistent", BasePasswd: filepath.Join(dir, "passwd"), BaseGroup: filepath.Join(dir, "group"),
		SMBControl: fake("smbcontrol", ""),
		SMBStatus:  fake("smbstatus", `echo '{"sessions":{"9":{"username":"alice","uid":20001,"server_id":{"pid":"4242"}}}}'`),
	}
	cfg.EtcDir = filepath.Join(cfg.RunDir, "etc")
	a, err := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), "test")
	if err != nil {
		t.Fatal(err)
	}
	must(t, a.prepare())
	ctx := context.Background()

	// No desired state yet: smbd gets an empty configuration.
	a.sync(ctx, true)
	conf := read(t, filepath.Join(cfg.RunDir, "smb.conf"))
	if strings.Contains(conf, "\n[") && strings.Count(conf, "\n[") != 1 {
		t.Fatalf("shares without desired state:\n%s", conf)
	}

	// A desired state written by hand, with a share escaping its root and an
	// injection attempt in a share name.
	d := desired(7)
	d.Shares = append(d.Shares,
		state.Share{Name: "Etc", Root: "drive1", Path: "etc", Access: map[string]state.Access{"sue": "rw"}},
		state.Share{Name: "x]\n[global]\nwide links = yes\n[y", Root: "drive1", Access: map[string]state.Access{"sue": "rw"}},
		state.Share{Name: "Up", Root: "drive1", Path: "../../etc", Access: map[string]state.Access{"sue": "rw"}},
	)
	writeDesired(t, stateDir, d)
	a.sync(ctx, false)

	conf = read(t, filepath.Join(cfg.RunDir, "smb.conf"))
	if !strings.Contains(conf, "\n[Data]\n") || strings.Contains(conf, "[Etc]") || strings.Contains(conf, "/etc") ||
		strings.Contains(conf, "wide links = yes") || strings.Contains(conf, "[Up]") {
		t.Fatalf("smb.conf:\n%s", conf)
	}
	if !strings.Contains(conf, "\tforce group = users\n") || !strings.Contains(conf, "\tforce user = smbdeck-files\n") {
		t.Fatalf("file identity:\n%s", conf)
	}
	if fi, err := os.Stat(filepath.Join(cfg.RunDir, "private", "smbpasswd")); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("smbpasswd mode: %v %v", fi.Mode(), err)
	}
	if !strings.Contains(read(t, filepath.Join(cfg.EtcDir, "passwd")), "\nalice:x:20001:100:") {
		t.Fatal("passwd lacks alice")
	}
	st, err := state.ReadStatus(cfg.StatusDir)
	if err != nil {
		t.Fatal(err)
	}
	if st.AppliedRevision != 7 || st.ObservedRevision != 7 {
		t.Fatalf("status revisions %d/%d", st.AppliedRevision, st.ObservedRevision)
	}
	codes := issueCodes(st.Issues)
	for _, want := range []string{"share:Etc:" + string(validate.SharePathOutsideRoot), "share::" + string(validate.ShareNameInvalid), "share:Up:" + string(validate.SharePathInvalid)} {
		if !slices.Contains(codes, want) {
			t.Errorf("status lacks %s: %v", want, codes)
		}
	}
	raw := read(t, filepath.Join(cfg.StatusDir, state.StatusFile))
	if strings.Contains(raw, "wide links") {
		t.Fatal("status echoes text from the desired state")
	}
	a.writeTree()
	if tree, err := state.ReadTree(cfg.StatusDir); err != nil || !slices.Equal(tree.Roots[0].Folders, []string{"data"}) {
		t.Fatalf("tree: %+v %v", tree, err)
	}

	// alice is disabled: her sessions are closed through smbcontrol.
	d.Revision = 8
	d.Users[1].Disabled = true
	writeDesired(t, stateDir, d)
	a.sync(ctx, false)
	if got := read(t, calls); !strings.Contains(got, "4242 shutdown") {
		t.Fatalf("smbcontrol calls: %q", got)
	}
	if !strings.Contains(read(t, filepath.Join(cfg.RunDir, "private", "smbpasswd")), "alice:20001:") ||
		!strings.Contains(read(t, filepath.Join(cfg.RunDir, "private", "smbpasswd")), "[UDX        ]") {
		t.Fatal("alice not disabled in smbpasswd")
	}

	// An unreadable desired state keeps the applied configuration.
	before := read(t, filepath.Join(cfg.RunDir, "smb.conf"))
	must(t, os.WriteFile(filepath.Join(stateDir, state.DesiredFile), []byte("{not json"), 0o600))
	a.sync(ctx, false)
	if read(t, filepath.Join(cfg.RunDir, "smb.conf")) != before {
		t.Fatal("configuration changed on an unreadable state")
	}
	st, _ = state.ReadStatus(cfg.StatusDir)
	if st.AppliedRevision != 8 || !slices.Contains(issueCodes(st.Issues), "state::"+string(validate.StateUnreadable)) {
		t.Fatalf("status after unreadable state: %+v", st)
	}
}

func writeDesired(t *testing.T, dir string, d *state.Desired) {
	t.Helper()
	data, err := json.Marshal(d)
	must(t, err)
	must(t, os.WriteFile(filepath.Join(dir, state.DesiredFile), data, 0o600))
	// Make sure the modification time moves even on coarse clocks.
	future := time.Now().Add(time.Duration(d.Revision) * time.Second)
	must(t, os.Chtimes(filepath.Join(dir, state.DesiredFile), future, future))
}

func read(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	must(t, err)
	return string(data)
}

func userNames(users []state.User) []string {
	var out []string
	for _, u := range users {
		out = append(out, u.Name)
	}
	return out
}

func issueCodes(issues []state.Issue) []string {
	var out []string
	for _, is := range issues {
		out = append(out, is.Kind+":"+is.Name+":"+is.Code)
	}
	return out
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
