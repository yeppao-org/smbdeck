// Package discovery announces the SMB server on the local network, without
// any privilege: mDNS/Bonjour with avahi (macOS, iOS, Linux, TVs) and
// WS-Discovery with wsdd2 (the Network view of Windows), LLMNR off.
//
// Multicast does not cross networks, so this role runs on the host network.
// It can announce a name that points to another address (a load balancer IP,
// for example): avahi publishes "<name>.local" from a static hosts file and
// does not publish the node's own addresses.
package discovery

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"
	"unicode"

	"github.com/yeppao-org/smbdeck/internal/config"
	"github.com/yeppao-org/smbdeck/internal/validate"
)

// Modes.
const (
	ModeMDNS = "mdns"
	ModeWSD  = "wsd"
	ModeAll  = "all"
)

// Config is the discovery configuration.
type Config struct {
	Mode        string
	HostName    string
	Address     string
	Interface   string
	DisplayName string
	Workgroup   string
	Model       string
	// TimeMachineShares are advertised as Time Machine destinations
	// (_adisk._tcp), so they show up in macOS's Time Machine settings.
	TimeMachineShares []string
	RunDir            string
	Avahi, WSDD2      string
}

var (
	hostRE      = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	ifaceRE     = regexp.MustCompile(`^[A-Za-z0-9._-]{1,15}$`)
	workgroupRE = regexp.MustCompile(`^[A-Z0-9-]{1,15}$`)
	modelRE     = regexp.MustCompile(`^[A-Za-z0-9,]{1,32}$`)
)

// FromEnv reads the discovery configuration for mode.
func FromEnv(e config.Env, mode string) (Config, error) {
	c := Config{
		Mode:        mode,
		HostName:    strings.ToLower(e.String("SMBDECK_DISCOVERY_HOSTNAME", "")),
		Address:     e.String("SMBDECK_DISCOVERY_ADDRESS", ""),
		Interface:   e.String("SMBDECK_DISCOVERY_INTERFACE", ""),
		Workgroup:   strings.ToUpper(e.String("SMBDECK_DISCOVERY_WORKGROUP", "WORKGROUP")),
		Model:       e.String("SMBDECK_DISCOVERY_MODEL", "Xserve"),
		RunDir:      e.String("SMBDECK_DISCOVERY_RUN_DIR", "/run/smbdeck-discovery"),
		Avahi:       "/usr/sbin/avahi-daemon",
		WSDD2:       "/usr/sbin/wsdd2",
		DisplayName: e.String("SMBDECK_DISCOVERY_NAME", ""),
	}
	c.TimeMachineShares = e.List("SMBDECK_DISCOVERY_TIMEMACHINE_SHARES")
	if c.DisplayName == "" {
		c.DisplayName = c.HostName
	}
	var errs []error
	switch mode {
	case ModeMDNS, ModeWSD, ModeAll:
	default:
		errs = append(errs, fmt.Errorf("discovery mode %q: want mdns, wsd or all", mode))
	}
	if !hostRE.MatchString(c.HostName) {
		errs = append(errs, errors.New("SMBDECK_DISCOVERY_HOSTNAME: required, lower-case letters, digits and dashes (the name before .local)"))
	}
	if c.Address != "" {
		a, err := netip.ParseAddr(c.Address)
		if err != nil || !a.Is4() {
			errs = append(errs, errors.New("SMBDECK_DISCOVERY_ADDRESS: an IPv4 address"))
		}
	}
	// On the host network, without an interface, avahi and wsdd2 would
	// answer on every interface of the host: one must be named.
	if !ifaceRE.MatchString(c.Interface) {
		errs = append(errs, errors.New("SMBDECK_DISCOVERY_INTERFACE: required, the host's interface on the local network (eth0, eno1…)"))
	}
	if !workgroupRE.MatchString(c.Workgroup) {
		errs = append(errs, errors.New("SMBDECK_DISCOVERY_WORKGROUP: 1 to 15 letters, digits or dashes"))
	}
	if !modelRE.MatchString(c.Model) {
		errs = append(errs, errors.New("SMBDECK_DISCOVERY_MODEL: letters, digits and commas"))
	}
	if len(c.DisplayName) > 63 || strings.IndexFunc(c.DisplayName, unicode.IsControl) >= 0 {
		errs = append(errs, errors.New("SMBDECK_DISCOVERY_NAME: up to 63 bytes, no control character"))
	}
	for _, s := range c.TimeMachineShares {
		if validate.ShareName(s) != validate.OK || strings.ContainsAny(s, ",=") {
			errs = append(errs, fmt.Errorf("SMBDECK_DISCOVERY_TIMEMACHINE_SHARES: %q is not a share name", s))
		}
	}
	if !filepath.IsAbs(c.RunDir) {
		errs = append(errs, errors.New("SMBDECK_DISCOVERY_RUN_DIR must be absolute"))
	}
	return c, errors.Join(errs...)
}

// NetBIOSName is the upper-case host name, cut to 15 characters.
func (c Config) NetBIOSName() string {
	n := strings.ToUpper(c.HostName)
	if len(n) > 15 {
		n = n[:15]
	}
	return strings.TrimRight(n, "-")
}

// avahiConf renders avahi-daemon.conf.
func (c Config) avahiConf() string {
	var b strings.Builder
	b.WriteString("[server]\n")
	if c.Address == "" {
		// No other address: this host itself is announced under the name.
		fmt.Fprintf(&b, "host-name=%s\n", c.HostName)
	}
	b.WriteString("use-ipv4=yes\nuse-ipv6=no\n")
	if c.Interface != "" {
		fmt.Fprintf(&b, "allow-interfaces=%s\n", c.Interface)
	}
	b.WriteString("enable-dbus=no\nratelimit-interval-usec=1000000\nratelimit-burst=1000\n")
	b.WriteString("[wide-area]\nenable-wide-area=no\n")
	b.WriteString("[publish]\n")
	if c.Address == "" {
		b.WriteString("publish-addresses=yes\n")
	} else {
		b.WriteString("publish-addresses=no\n")
	}
	b.WriteString("publish-hinfo=no\npublish-workstation=no\npublish-domain=no\n")
	b.WriteString("[reflector]\nenable-reflector=no\n[rlimits]\n")
	return b.String()
}

// hosts renders avahi's static hosts file.
func (c Config) hosts() string {
	if c.Address == "" {
		return ""
	}
	return fmt.Sprintf("%s %s.local\n", c.Address, c.HostName)
}

func xmlText(s string) string {
	var b strings.Builder
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}

// service renders the avahi service file: SMB, the device icon, and the Time
// Machine destinations.
func (c Config) service() string {
	host := ""
	if c.Address != "" {
		host = fmt.Sprintf("    <host-name>%s.local</host-name>\n", c.HostName)
	}
	var b strings.Builder
	b.WriteString("<?xml version=\"1.0\" standalone='no'?>\n<!DOCTYPE service-group SYSTEM \"avahi-service.dtd\">\n<service-group>\n")
	fmt.Fprintf(&b, "  <name replace-wildcards=\"no\">%s</name>\n", xmlText(c.DisplayName))
	fmt.Fprintf(&b, "  <service>\n    <type>_smb._tcp</type>\n    <port>445</port>\n%s  </service>\n", host)
	fmt.Fprintf(&b, "  <service>\n    <type>_device-info._tcp</type>\n    <port>0</port>\n%s    <txt-record>model=%s</txt-record>\n  </service>\n", host, c.Model)
	if len(c.TimeMachineShares) > 0 {
		fmt.Fprintf(&b, "  <service>\n    <type>_adisk._tcp</type>\n    <port>9</port>\n%s    <txt-record>sys=waMa=0,adVF=0x100</txt-record>\n", host)
		for i, s := range c.TimeMachineShares {
			fmt.Fprintf(&b, "    <txt-record>dk%d=adVN=%s,adVF=0x82</txt-record>\n", i, xmlText(s))
		}
		b.WriteString("  </service>\n")
	}
	b.WriteString("</service-group>\n")
	return b.String()
}

// prepare writes avahi's files under RunDir. The image links
// /etc/avahi/hosts, /etc/avahi/services and /run/avahi-daemon there, so the
// root file system can stay read-only and avahi never needs root to create
// its runtime directory.
func (c Config) prepare() error {
	if err := os.MkdirAll(filepath.Join(c.RunDir, "services"), 0o750); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(c.RunDir, "avahi-daemon"), 0o750); err != nil {
		return err
	}
	files := map[string]string{
		"avahi-daemon.conf":    c.avahiConf(),
		"hosts":                c.hosts(),
		"services/smb.service": c.service(),
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(c.RunDir, name), []byte(content), 0o600); err != nil {
			return err
		}
	}
	return nil
}

func (c Config) avahiCommand() []string {
	return []string{c.Avahi, "--no-drop-root", "--no-chroot", "--no-proc-title", "--no-rlimits",
		"-f", filepath.Join(c.RunDir, "avahi-daemon.conf")}
}

// wsddCommand: -w WS-Discovery only (no LLMNR: its answer would be the node's
// own address), -4 IPv4.
func (c Config) wsddCommand() []string {
	args := []string{c.WSDD2, "-w", "-4"}
	if c.Interface != "" {
		args = append(args, "-i", c.Interface)
	}
	return append(args, "-H", c.HostName, "-N", c.NetBIOSName(), "-G", c.Workgroup)
}

// Run starts the announcers of the configured mode and returns when one of
// them exits or ctx ends.
func Run(ctx context.Context, c Config, log *slog.Logger) error {
	var cmds [][]string
	if c.Mode == ModeMDNS || c.Mode == ModeAll {
		if err := c.prepare(); err != nil {
			return fmt.Errorf("discovery files: %w", err)
		}
		cmds = append(cmds, c.avahiCommand())
	}
	if c.Mode == ModeWSD || c.Mode == ModeAll {
		cmds = append(cmds, c.wsddCommand())
	}
	log.Info("announcing", "mode", c.Mode, "host", c.HostName+".local", "address", c.Address,
		"interface", c.Interface, "timeMachine", len(c.TimeMachineShares))

	type exit struct {
		name string
		err  error
	}
	exits := make(chan exit, len(cmds))
	var procs []*exec.Cmd
	for _, argv := range cmds {
		cmd := exec.Command(argv[0], argv[1:]...) //nolint:gosec // G204: fixed program paths; arguments validated in FromEnv
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
		cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
		if err := cmd.Start(); err != nil {
			for _, p := range procs {
				_ = p.Process.Signal(syscall.SIGTERM)
			}
			return fmt.Errorf("start %s: %w", filepath.Base(argv[0]), err)
		}
		procs = append(procs, cmd)
		go func(name string, cmd *exec.Cmd) { exits <- exit{name, cmd.Wait()} }(filepath.Base(argv[0]), cmd)
	}
	var first exit
	select {
	case first = <-exits:
		log.Error("announcer exited", "program", first.name, "err", first.err)
	case <-ctx.Done():
	}
	for _, p := range procs {
		_ = p.Process.Signal(syscall.SIGTERM)
	}
	deadline := time.After(5 * time.Second)
	for range len(procs) - btoi(first.name != "") {
		select {
		case <-exits:
		case <-deadline:
			for _, p := range procs {
				_ = p.Process.Kill()
			}
			return errors.New("announcers did not stop in time")
		}
	}
	if first.name != "" {
		return fmt.Errorf("%s exited: %w", first.name, first.err)
	}
	return nil
}

func btoi(b bool) int {
	if b {
		return 1
	}
	return 0
}
