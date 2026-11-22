package discovery

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/yeppao-org/smbdeck/internal/config"
)

func env(m map[string]string) config.Env { return config.MapEnv(m) }

func TestFromEnv(t *testing.T) {
	c, err := FromEnv(env(map[string]string{
		"SMBDECK_DISCOVERY_HOSTNAME":  "Partage",
		"SMBDECK_DISCOVERY_ADDRESS":   "192.168.1.210",
		"SMBDECK_DISCOVERY_INTERFACE": "eno1",
	}), ModeAll)
	if err != nil {
		t.Fatal(err)
	}
	if c.HostName != "partage" || c.DisplayName != "partage" || c.NetBIOSName() != "PARTAGE" || c.Workgroup != "WORKGROUP" {
		t.Fatalf("%+v", c)
	}
	bad := []map[string]string{
		{},
		{"SMBDECK_DISCOVERY_HOSTNAME": "bad name"},
		{"SMBDECK_DISCOVERY_HOSTNAME": "a", "SMBDECK_DISCOVERY_ADDRESS": "fe80::1"},
		{"SMBDECK_DISCOVERY_HOSTNAME": "a", "SMBDECK_DISCOVERY_ADDRESS": "nope"},
		{"SMBDECK_DISCOVERY_HOSTNAME": "a", "SMBDECK_DISCOVERY_INTERFACE": "eth0; rm -rf"},
		{"SMBDECK_DISCOVERY_HOSTNAME": "a", "SMBDECK_DISCOVERY_NAME": "x\ny"},
		{"SMBDECK_DISCOVERY_HOSTNAME": "a", "SMBDECK_DISCOVERY_TIMEMACHINE_SHARES": "ok,bad=1"},
		{"SMBDECK_DISCOVERY_HOSTNAME": "a", "SMBDECK_DISCOVERY_INTERFACE": "eth0", "SMBDECK_DISCOVERY_MODEL": "<x>"},
	}
	for _, m := range bad {
		if _, err := FromEnv(env(m), ModeAll); err == nil {
			t.Errorf("accepted %v", m)
		}
	}
	if _, err := FromEnv(env(map[string]string{"SMBDECK_DISCOVERY_HOSTNAME": "a"}), "llmnr"); err == nil {
		t.Error("unknown mode accepted")
	}
}

// Without an interface, avahi and wsdd2 would answer on every interface of
// the host (host network): it is required.
func TestInterfaceIsRequired(t *testing.T) {
	for _, mode := range []string{ModeMDNS, ModeWSD, ModeAll} {
		if _, err := FromEnv(env(map[string]string{"SMBDECK_DISCOVERY_HOSTNAME": "nas"}), mode); err == nil {
			t.Errorf("%s: no interface accepted", mode)
		}
	}
}

func TestNetBIOSName(t *testing.T) {
	c := Config{HostName: "a-very-long-host-name"}
	if got := c.NetBIOSName(); got != "A-VERY-LONG-HOS" {
		t.Fatalf("got %q", got)
	}
	c.HostName = "fourteen-chars-"
	if got := c.NetBIOSName(); strings.HasSuffix(got, "-") {
		t.Fatalf("trailing dash: %q", got)
	}
}

func TestFilesPointToAnotherAddress(t *testing.T) {
	c := Config{HostName: "partage", Address: "192.168.1.210", Interface: "eno1", DisplayName: "Partage & co <1>",
		Model: "Xserve", TimeMachineShares: []string{"Backups", "Mac & PC"}}
	conf := c.avahiConf()
	for _, want := range []string{"publish-addresses=no", "allow-interfaces=eno1", "enable-dbus=no", "use-ipv6=no", "enable-reflector=no"} {
		if !strings.Contains(conf, want+"\n") {
			t.Errorf("avahi-daemon.conf lacks %s", want)
		}
	}
	if strings.Contains(conf, "host-name=") {
		t.Error("host name set while announcing another address")
	}
	if c.hosts() != "192.168.1.210 partage.local\n" {
		t.Errorf("hosts %q", c.hosts())
	}
	svc := c.service()
	for _, want := range []string{
		"<name replace-wildcards=\"no\">Partage &amp; co &lt;1&gt;</name>",
		"<type>_smb._tcp</type>", "<host-name>partage.local</host-name>",
		"<txt-record>dk0=adVN=Backups,adVF=0x82</txt-record>",
		"<txt-record>dk1=adVN=Mac &amp; PC,adVF=0x82</txt-record>",
	} {
		if !strings.Contains(svc, want) {
			t.Errorf("service lacks %s:\n%s", want, svc)
		}
	}
}

func TestFilesForThisHost(t *testing.T) {
	c := Config{HostName: "nas", DisplayName: "nas", Model: "Xserve"}
	if !strings.Contains(c.avahiConf(), "host-name=nas\n") || !strings.Contains(c.avahiConf(), "publish-addresses=yes\n") {
		t.Fatal(c.avahiConf())
	}
	if c.hosts() != "" || strings.Contains(c.service(), "<host-name>") || strings.Contains(c.service(), "_adisk") {
		t.Fatal("unexpected static host or Time Machine record")
	}
}

func TestCommands(t *testing.T) {
	c := Config{HostName: "partage", Interface: "eno1", Workgroup: "WORKGROUP", WSDD2: "/usr/sbin/wsdd2", Avahi: "/usr/sbin/avahi-daemon", RunDir: "/run/x"}
	want := []string{"/usr/sbin/wsdd2", "-w", "-4", "-i", "eno1", "-H", "partage", "-N", "PARTAGE", "-G", "WORKGROUP"}
	if got := c.wsddCommand(); !slices.Equal(got, want) {
		t.Fatalf("wsdd2: %q", got)
	}
	if got := c.avahiCommand(); !slices.Contains(got, "--no-drop-root") || got[len(got)-1] != "/run/x/avahi-daemon.conf" {
		t.Fatalf("avahi: %q", got)
	}
}

func TestPrepare(t *testing.T) {
	c := Config{HostName: "nas", DisplayName: "nas", Model: "Xserve", RunDir: t.TempDir()}
	if err := c.prepare(); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"avahi-daemon.conf", "hosts", "services/smb.service"} {
		if _, err := os.Stat(filepath.Join(c.RunDir, f)); err != nil {
			t.Error(err)
		}
	}
	if fi, err := os.Stat(filepath.Join(c.RunDir, "avahi-daemon")); err != nil || !fi.IsDir() {
		t.Error("runtime directory missing")
	}
}
