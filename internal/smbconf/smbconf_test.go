package smbconf

import (
	"slices"
	"strings"
	"testing"
)

func global() Global {
	return Global{
		NetBIOSName: "SMBDECK", ServerString: "smbdeck", Workgroup: "WORKGROUP",
		HostsAllow: []string{"192.168.1.0/24", "100.64.0.0/10"},
		PassdbPath: "/run/smbdeck/private/smbpasswd", RunDir: "/run/smbdeck/samba", LogLevel: 1,
	}
}

func share() Share {
	return Share{
		Name: "Data", Path: "/roots/drive1/data",
		ReadUsers: []string{"alice"}, WriteUsers: []string{"sue"},
		FilesUser: "smbdeck-files", FilesGroup: "users",
	}
}

func TestRenderHardenedGlobal(t *testing.T) {
	out, err := Render(global(), []Share{share()})
	if err != nil {
		t.Fatal(err)
	}
	conf := string(out)
	for _, want := range []string{
		"server min protocol = SMB2_10",
		"server smb encrypt = desired",
		"restrict anonymous = 2",
		"map to guest = never",
		"disable netbios = yes",
		"smb ports = 445",
		"load printers = no",
		"wide links = no",
		"unix extensions = no",
		"access based share enum = yes",
		"vfs objects = catia fruit streams_xattr",
		"hosts allow = 192.168.1.0/24 100.64.0.0/10",
		"passdb backend = smbpasswd:/run/smbdeck/private/smbpasswd",
	} {
		if !strings.Contains(conf, "\t"+want+"\n") {
			t.Errorf("missing %q", want)
		}
	}
}

// Signing is mandatory unless the operator says otherwise; SMB3 POSIX
// extensions stay off; and a password changed from an SMB client is refused
// (smbdeck rewrites the passdb from the desired state: the change would be
// accepted, then silently undone).
func TestRenderSigningExtensionsAndPasswordChanges(t *testing.T) {
	out, err := Render(global(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"server signing = mandatory", "smb3 unix extensions = no", "check password script = /bin/false"} {
		if !strings.Contains(string(out), "\t"+want+"\n") {
			t.Errorf("missing %q", want)
		}
	}
	g := global()
	g.Signing = "auto"
	out, _ = Render(g, nil)
	if !strings.Contains(string(out), "\tserver signing = auto\n") {
		t.Error("signing setting ignored")
	}
	g.Signing = "disabled"
	if _, err := Render(g, nil); err == nil {
		t.Error("signing disabled accepted")
	}
}

func TestRenderShare(t *testing.T) {
	s := share()
	s.ReadUsers = []string{"bob", "alice", "sue"} // sue also writes: write wins
	s.TimeMachine = true
	s.TimeMachineMaxSize = "500G"
	out, err := Render(global(), []Share{s})
	if err != nil {
		t.Fatal(err)
	}
	want := `
[Data]
	path = /roots/drive1/data
	valid users = alice bob sue
	read list = alice bob
	write list = sue
	read only = yes
	browseable = yes
	guest ok = no
	force user = smbdeck-files
	force group = users
	create mask = 0664
	directory mask = 2775
	fruit:time machine = yes
	fruit:time machine max size = 500G
`
	if !strings.HasSuffix(string(out), want) {
		t.Fatalf("share section:\n%s\nwant suffix:\n%s", out, want)
	}
}

// An empty "valid users" means "everyone" to Samba. A share nobody may open
// must not be published at all.
func TestShareWithoutAccountsIsLeftOut(t *testing.T) {
	s := share()
	s.ReadUsers, s.WriteUsers = nil, nil
	out, err := Render(global(), []Share{s})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "[Data]") {
		t.Fatal("share without accounts was published")
	}
	if strings.Contains(string(out), "valid users = \n") {
		t.Fatal("empty valid users written")
	}
}

func TestRenderRefusesInjection(t *testing.T) {
	// Refused anywhere in a value.
	anywhere := []string{"x\n[global]\nwide links = yes", "x\r\nhosts allow = 0.0.0.0/0", "%$(HOME)", "x\\", "x\x00y"}
	// Refused at the start of a value only: fields that the generator prefixes
	// (paths, the passdb backend) may contain them.
	leading := []string{";x", "#x", "[x"}
	prefixed := map[string]bool{"share path": true, "passdb": true}
	for _, bad := range append(anywhere, leading...) {
		cases := map[string]func() (Global, []Share){
			"netbios":       func() (Global, []Share) { g := global(); g.NetBIOSName = bad; return g, nil },
			"server string": func() (Global, []Share) { g := global(); g.ServerString = bad; return g, nil },
			"workgroup":     func() (Global, []Share) { g := global(); g.Workgroup = bad; return g, nil },
			"hosts allow":   func() (Global, []Share) { g := global(); g.HostsAllow = []string{"10.0.0.0/8", bad}; return g, nil },
			"passdb":        func() (Global, []Share) { g := global(); g.PassdbPath = bad; return g, nil },
			"share name":    func() (Global, []Share) { s := share(); s.Name = bad; return global(), []Share{s} },
			"share path":    func() (Global, []Share) { s := share(); s.Path = "/roots/" + bad; return global(), []Share{s} },
			"read user":     func() (Global, []Share) { s := share(); s.ReadUsers = []string{bad}; return global(), []Share{s} },
			"write user":    func() (Global, []Share) { s := share(); s.WriteUsers = []string{bad}; return global(), []Share{s} },
			"force user":    func() (Global, []Share) { s := share(); s.FilesUser = bad; return global(), []Share{s} },
			"tm size": func() (Global, []Share) {
				s := share()
				s.TimeMachine, s.TimeMachineMaxSize = true, "1T"+bad
				return global(), []Share{s}
			},
		}
		for field, build := range cases {
			if prefixed[field] && slices.Contains(leading, bad) {
				continue
			}
			g, shares := build()
			if out, err := Render(g, shares); err == nil {
				t.Errorf("%s = %q rendered:\n%s", field, bad, out)
			}
		}
	}
}

func TestRenderRefusesRelativePathAndOddUsers(t *testing.T) {
	s := share()
	s.Path = "roots/x"
	if _, err := Render(global(), []Share{s}); err == nil {
		t.Error("relative path accepted")
	}
	for _, u := range []string{"@admins", "+group", "a b", "root"} {
		s := share()
		s.WriteUsers = []string{u}
		if _, err := Render(global(), []Share{s}); err == nil {
			t.Errorf("account %q accepted in a list", u)
		}
	}
}

// Every line is either blank, a comment, a section header, or "key = value":
// whatever the input, the structure of the file stays what the generator meant.
func TestRenderStructure(t *testing.T) {
	s2 := share()
	s2.Name, s2.Path = "Media 2", "/roots/drive2/Films; et #séries [2024]"
	out, err := Render(global(), []Share{share(), s2})
	if err != nil {
		t.Fatal(err)
	}
	sections := 0
	for _, line := range strings.Split(strings.TrimSuffix(string(out), "\n"), "\n") {
		switch {
		case line == "", strings.HasPrefix(line, "# "):
		case strings.HasPrefix(line, "["):
			sections++
		case strings.HasPrefix(line, "\t") && strings.Contains(line, " = "):
		default:
			t.Errorf("unexpected line %q", line)
		}
	}
	if sections != 3 {
		t.Errorf("%d sections, want 3", sections)
	}
}
