package validate

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/yeppao-org/smbdeck/internal/nthash"
	"github.com/yeppao-org/smbdeck/internal/state"
)

// Values that would change the meaning of smb.conf if they reached it.
var injections = []string{
	"a\nb", "a\rb", "a\r\nb", "\n[global]", "x\n[global]\nwide links = yes",
	"[global]", "[x", ";comment", "#comment", "trailing\\", "a\x00b", "a\tb",
	"a\u2028b", "a\u0085b", "%U", "a%Hb", "%$(PATH)", " lead", "trail ",
}

func TestUserName(t *testing.T) {
	for _, ok := range []string{"a", "sue", "alice_b", "_svc", "a-b", "u123", strings.Repeat("a", 32)} {
		if c := UserName(ok); c != OK {
			t.Errorf("UserName(%q) = %s", ok, c)
		}
	}
	bad := append([]string{
		"", "A", "Alice", "1abc", "-a", "a b", "a.b", "a@b", "+grp", "@grp", "&x",
		strings.Repeat("a", 33), "élise", "a/b", "..", "a,b",
	}, injections...)
	for _, b := range bad {
		if c := UserName(b); c != UserNameInvalid {
			t.Errorf("UserName(%q) = %q, want invalid", b, c)
		}
	}
	for _, r := range []string{"root", "nobody", "daemon", "avahi", "smbdeck", "bin", "sys", "adm"} {
		if c := UserName(r); c != UserNameReserved {
			t.Errorf("UserName(%q) = %q, want reserved", r, c)
		}
	}
}

// Samba reads an entry of "valid users" that looks like a SID as that SID,
// and resolves well-known names (Everyone, Users…) before local accounts: an
// account named "s-1-1-0" or "everyone" would open a share to every account.
func TestUserNameNeverMeansAGroupOrASID(t *testing.T) {
	for _, n := range []string{
		"s-1-1-0", "s-1-5-32-544", "s-1-5-11", "s-1", "s-0",
		"everyone", "users", "guests", "administrators", "system", "network",
		"interactive", "local", "self", "builtin", "batch", "dialup", "service",
		"anonymous", "restricted", "replicator", "world", "proxy",
	} {
		if c := UserName(n); c == OK {
			t.Errorf("UserName(%q) accepted", n)
		}
	}
	for _, ok := range []string{"s", "s-", "sam", "s_1", "steve", "s-a1"} {
		if c := UserName(ok); c != OK {
			t.Errorf("UserName(%q) = %q", ok, c)
		}
	}
}

func TestShareName(t *testing.T) {
	for _, ok := range []string{"Partage", "Media 2", "a", "x.y", "Time_Machine-1", strings.Repeat("A", 64)} {
		if c := ShareName(ok); c != OK {
			t.Errorf("ShareName(%q) = %s", ok, c)
		}
	}
	bad := append([]string{
		"", " a", "a ", "a.", ".hidden", "-x", "a/b", "a\\b", "a]b", "a=b", "é", "a$",
		strings.Repeat("A", 65),
	}, injections...)
	for _, b := range bad {
		if c := ShareName(b); c != ShareNameInvalid {
			t.Errorf("ShareName(%q) = %q, want invalid", b, c)
		}
	}
	for _, r := range []string{"global", "GLOBAL", "Homes", "printers"} {
		if c := ShareName(r); c != ShareNameReserved {
			t.Errorf("ShareName(%q) = %q, want reserved", r, c)
		}
	}
	// print$ and ipc$ are refused by the character rule before the list.
	for _, r := range []string{"print$", "IPC$"} {
		if c := ShareName(r); c == OK {
			t.Errorf("ShareName(%q) accepted", r)
		}
	}
}

func TestRelPath(t *testing.T) {
	good := map[string]string{
		"": "", "/": "", ".": "", "a": "a", "a/b": "a/b", "a/b/": "a/b",
		"Photos 2024/Été": "Photos 2024/Été", "a;b": "a;b", "#x": "#x", "[x]": "[x]",
	}
	for in, want := range good {
		got, c := RelPath(in)
		if c != OK || got != want {
			t.Errorf("RelPath(%q) = %q, %q; want %q", in, got, c, want)
		}
	}
	bad := []string{
		"..", "../x", "a/../b", "a/..", "./a", "a/./b", "a//b", "/abs", "/etc/passwd",
		"a\\b", "a\nb", "a\x00b", "a%Ub", "%$(HOME)", "a\"b", " a", "a /b", "a/b ",
		"bad\xffutf8", strings.Repeat("a/", 600),
	}
	for _, b := range bad {
		if _, c := RelPath(b); c != SharePathInvalid {
			t.Errorf("RelPath(%q) = %q, want invalid", b, c)
		}
	}
}

func TestConfValue(t *testing.T) {
	for _, ok := range []string{"", "/roots/drive1/a b", "alice bob", "SMB2_10", "a;b", "a#b", "a[b]", "x = y"} {
		if !ConfValue(ok) {
			t.Errorf("ConfValue(%q) refused", ok)
		}
	}
	for _, b := range injections {
		if ConfValue(b) {
			t.Errorf("ConfValue(%q) accepted", b)
		}
	}
	if SectionName("a]b") || SectionName("a[b") || !SectionName("Media 2") {
		t.Error("SectionName")
	}
}

func TestPassword(t *testing.T) {
	if c := Password("short", 12); c != PasswordTooShort {
		t.Errorf("short: %q", c)
	}
	if c := Password(strings.Repeat("é", 12), 12); c != OK {
		t.Errorf("12 runes: %q", c)
	}
	if c := Password(strings.Repeat("a", MaxPasswordLength+1), 12); c != PasswordTooLong {
		t.Errorf("long: %q", c)
	}
	for _, b := range []string{"abcdefghijkl\n", "abcdefghijkl\x00", "abcdefghijk\xff"} {
		if c := Password(b, 1); c != PasswordInvalid {
			t.Errorf("Password(%q) = %q", b, c)
		}
	}
}

func TestTimeMachineSize(t *testing.T) {
	for _, ok := range []string{"", "1T", "500G", "999999M"} {
		if TimeMachineSize(ok) != OK {
			t.Errorf("%q refused", ok)
		}
	}
	for _, b := range []string{"0G", "1", "1TB", "1 T", "-1G", "1.5T", "1T\n", "%U"} {
		if TimeMachineSize(b) == OK {
			t.Errorf("%q accepted", b)
		}
	}
}

func user(name string, uid int, admin bool) state.User {
	return state.User{Name: name, UID: uid, NTHash: nthash.Sum("x").String(), Admin: admin, CreatedAt: time.Unix(0, 0)}
}

func TestCheck(t *testing.T) {
	d := &state.Desired{
		SchemaVersion: 1,
		Users: []state.User{
			user("sue", 20000, true),
			user("alice", 20001, false),
			user("alice", 20002, false), // duplicate name
			user("bob", 20001, false),   // duplicate uid
			user("root", 20003, false),  // reserved
			user("eve\n", 20004, false), // injection, name must not be echoed
			{Name: "carol", UID: 20005}, // missing hash
			user("dave", 100, false),    // uid out of range
		},
		Shares: []state.Share{
			{Name: "Data", Root: "drive1", Path: "data", Access: map[string]state.Access{"sue": "rw", "alice": "ro", "ghost": "rw", "bob": "rw", "sue2": "x"}},
			{Name: "data", Root: "drive1"}, // duplicate, case-insensitive
			{Name: "Bad[", Root: "drive1"},
			{Name: "Escape", Root: "drive1", Path: "../etc"},
			{Name: "NoRoot", Root: "drive9"},
			{Name: "TM", Root: "drive1", TimeMachine: state.TimeMachine{Enabled: true, MaxSize: "lots"}},
		},
	}
	r := Check(d, map[string]bool{"drive1": true})
	if r.Fatal != OK {
		t.Fatalf("fatal %q", r.Fatal)
	}
	wantUsers := []bool{true, true, false, false, false, false, false, false}
	for i, w := range wantUsers {
		if r.UserOK[i] != w {
			t.Errorf("user %d ok=%v want %v", i, r.UserOK[i], w)
		}
	}
	wantShares := []bool{true, false, false, false, false, false}
	for i, w := range wantShares {
		if r.ShareOK[i] != w {
			t.Errorf("share %d ok=%v want %v", i, r.ShareOK[i], w)
		}
	}
	if got := r.Access[0]; len(got) != 2 || got["sue"] != "rw" || got["alice"] != "ro" {
		t.Errorf("access of share 0 = %v", got)
	}
	for _, is := range r.Issues {
		if strings.ContainsAny(is.Name, "\n[") {
			t.Errorf("issue echoes an invalid name: %+v", is)
		}
	}
	codes := map[string]bool{}
	for _, is := range r.Issues {
		codes[is.Code] = true
	}
	for _, c := range []Code{UserNameDuplicate, UserUIDDuplicate, UserNameReserved, UserNameInvalid, UserHashInvalid, UserUIDInvalid,
		ShareNameDuplicate, ShareNameInvalid, SharePathInvalid, ShareRootUnknown, ShareTimeMachineSize, ShareAccessUnknownUser} {
		if !codes[string(c)] {
			t.Errorf("missing issue %q", c)
		}
	}
	if codes[string(StateNoAdmin)] {
		t.Error("state has an active admin")
	}
}

func TestCheckNoAdmin(t *testing.T) {
	d := &state.Desired{SchemaVersion: 1, Users: []state.User{user("sue", 20000, true)}}
	d.Users[0].Disabled = true
	if r := Check(d, nil); !hasCode(r, StateNoAdmin) {
		t.Fatalf("got %+v", r.Issues)
	}
	// An admin whose record is invalid does not count.
	d.Users[0].Disabled = false
	d.Users[0].NTHash = "nope"
	if r := Check(d, nil); !hasCode(r, StateNoAdmin) {
		t.Fatal("invalid admin counted")
	}
}

func TestCheckFatal(t *testing.T) {
	if r := Check(&state.Desired{SchemaVersion: 2}, nil); r.Fatal != StateSchemaUnsupported {
		t.Fatal("schema 2 accepted")
	}
	d := &state.Desired{SchemaVersion: 1, Users: make([]state.User, MaxUsers+1)}
	if r := Check(d, nil); r.Fatal != StateTooManyUsers {
		t.Fatal("too many users accepted")
	}
}

func hasCode(r Report, c Code) bool {
	for _, is := range r.Issues {
		if is.Code == string(c) {
			return true
		}
	}
	return false
}

func TestResolve(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "root")
	outside := filepath.Join(base, "outside")
	must(t, os.MkdirAll(filepath.Join(root, "a", "b"), 0o755))
	must(t, os.MkdirAll(outside, 0o755))
	must(t, os.WriteFile(filepath.Join(root, "file"), nil, 0o644))
	must(t, os.Symlink(outside, filepath.Join(root, "escape")))
	must(t, os.Symlink("../outside", filepath.Join(root, "escape-rel")))
	must(t, os.Symlink("a/b", filepath.Join(root, "inside")))
	must(t, os.Symlink("/nonexistent", filepath.Join(root, "dangling")))
	must(t, os.Symlink("/", filepath.Join(root, "a", "slash")))
	must(t, os.MkdirAll(filepath.Join(root, "pct%U"), 0o755))
	must(t, os.Symlink("pct%U", filepath.Join(root, "to-pct")))

	rootReal, _ := filepath.EvalSymlinks(root)
	cases := []struct {
		rel  string
		want Code
		path string
	}{
		{"", OK, rootReal},
		{"a", OK, filepath.Join(rootReal, "a")},
		{"a/b", OK, filepath.Join(rootReal, "a", "b")},
		{"inside", SharePathSymlink, ""},
		{"escape", SharePathOutsideRoot, ""},
		{"escape-rel", SharePathOutsideRoot, ""},
		{"a/slash", SharePathOutsideRoot, ""},
		{"a/slash/etc", SharePathOutsideRoot, ""},
		{"dangling", SharePathOutsideRoot, ""},
		{"missing", SharePathMissing, ""},
		{"file", SharePathNotDirectory, ""},
		{"../outside", SharePathInvalid, ""},
		{"to-pct", SharePathSymlink, ""},
		{"pct%U", SharePathInvalid, ""},
	}
	for _, c := range cases {
		got, code := Resolve(root, c.rel)
		if code != c.want || got != c.path {
			t.Errorf("Resolve(%q) = %q, %q; want %q, %q", c.rel, got, code, c.path, c.want)
		}
	}
	if _, c := Resolve(filepath.Join(base, "nope"), "a"); c != ShareRootUnavailable {
		t.Errorf("missing root: %q", c)
	}
	// A root that is itself a link is followed (it is configuration, not data).
	must(t, os.Symlink(root, filepath.Join(base, "rootlink")))
	if got, c := Resolve(filepath.Join(base, "rootlink"), "a"); c != OK || got != filepath.Join(rootReal, "a") {
		t.Errorf("root link: %q %q", got, c)
	}
}

func TestWithin(t *testing.T) {
	if !Within("/roots/a", "/roots/a") || !Within("/roots/a", "/roots/a/b") {
		t.Error("inside refused")
	}
	if Within("/roots/a", "/roots/ab") || Within("/roots/a", "/roots") || Within("/roots/a", "/etc") {
		t.Error("outside accepted")
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
