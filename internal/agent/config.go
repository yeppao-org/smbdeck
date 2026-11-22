package agent

import (
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/yeppao-org/smbdeck/internal/config"
	"github.com/yeppao-org/smbdeck/internal/state"
	"github.com/yeppao-org/smbdeck/internal/validate"
)

// Root is a declared share root: a directory mounted into the agent only.
type Root struct {
	Name string
	Dir  string
}

// Config is the agent's configuration.
type Config struct {
	// StateDir holds desired.json, written by the web console: read only.
	StateDir string
	// StatusDir receives status.json, tree.json and the copy of the last
	// applied state. Only the agent writes it; the web console mounts it
	// read-only.
	StatusDir string
	RunDir    string
	Roots     []Root
	// FilesUID and FilesGID own every file created through SMB.
	FilesUID, FilesGID int

	NetBIOSName  string
	ServerString string
	Workgroup    string
	HostsAllow   []string
	SambaLog     int
	// Signing is Samba's "server signing": mandatory (default) or auto.
	Signing string

	// PollInterval is how often desired.json is checked for changes;
	// ResyncInterval how often everything is re-validated anyway (links can
	// change on disk); TreeInterval how often the folder tree is refreshed
	// (also after the agent creates a folder).
	PollInterval   time.Duration
	ResyncInterval time.Duration
	TreeInterval   time.Duration

	// Paths of the Samba programs and of the image's base account files.
	SMBD, SMBControl, SMBStatus string
	BasePasswd, BaseGroup       string
	// EtcDir receives passwd and group (the image links /etc/passwd and
	// /etc/group there).
	EtcDir string
}

// RootsPrefix is where share roots must be mounted in the agent container.
const RootsPrefix = "/roots/"

const maxID = 1<<31 - 2

var netbiosRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,14}$`)

// FromEnv reads the agent configuration.
func FromEnv(e config.Env) (Config, error) {
	c := Config{ //nolint:gosec // G101: file paths, not credentials
		StateDir:     e.String("SMBDECK_STATE_DIR", "/state"),
		StatusDir:    e.String("SMBDECK_STATUS_DIR", "/status"),
		Signing:      e.String("SMBDECK_SMB_SIGNING", "mandatory"),
		RunDir:       e.String("SMBDECK_RUN_DIR", "/run/smbdeck"),
		NetBIOSName:  strings.ToUpper(e.String("SMBDECK_SMB_NETBIOS_NAME", "SMBDECK")),
		ServerString: e.String("SMBDECK_SMB_SERVER_STRING", "smbdeck"),
		Workgroup:    strings.ToUpper(e.String("SMBDECK_SMB_WORKGROUP", "WORKGROUP")),
		SMBD:         "/usr/sbin/smbd",
		SMBControl:   "/usr/bin/smbcontrol",
		SMBStatus:    "/usr/bin/smbstatus",
		BasePasswd:   "/usr/share/smbdeck/passwd",
		BaseGroup:    "/usr/share/smbdeck/group",
	}
	c.EtcDir = filepath.Join(c.RunDir, "etc")
	var errs []error
	add := func(err error) {
		if err != nil {
			errs = append(errs, err)
		}
	}
	var err error
	// The file owner is never root, and never in the range of account UIDs.
	c.FilesUID, err = e.Int("SMBDECK_FILES_UID", 1000, 1, maxID)
	add(err)
	c.FilesGID, err = e.Int("SMBDECK_FILES_GID", 1000, 1, maxID)
	add(err)
	if c.FilesUID >= state.FirstUID && c.FilesUID <= state.LastUID {
		add(fmt.Errorf("SMBDECK_FILES_UID: %d-%d is reserved for accounts", state.FirstUID, state.LastUID))
	}
	c.SambaLog, err = e.Int("SMBDECK_SMB_LOG_LEVEL", 1, 0, 10)
	add(err)
	c.PollInterval, err = e.Duration("SMBDECK_POLL_INTERVAL", time.Second, 200*time.Millisecond, time.Minute)
	add(err)
	c.ResyncInterval, err = e.Duration("SMBDECK_RESYNC_INTERVAL", time.Minute, 5*time.Second, time.Hour)
	add(err)
	c.TreeInterval, err = e.Duration("SMBDECK_TREE_INTERVAL", 10*time.Minute, time.Minute, 24*time.Hour)
	add(err)
	if c.Signing != "mandatory" && c.Signing != "auto" {
		add(errors.New("SMBDECK_SMB_SIGNING: want mandatory or auto"))
	}

	roots, err := ParseRoots(e("SMBDECK_ROOTS"))
	add(err)
	c.Roots = roots

	if !netbiosRE.MatchString(c.NetBIOSName) {
		add(errors.New("SMBDECK_SMB_NETBIOS_NAME: 1 to 15 letters, digits or dashes"))
	}
	if !netbiosRE.MatchString(c.Workgroup) {
		add(errors.New("SMBDECK_SMB_WORKGROUP: 1 to 15 letters, digits or dashes"))
	}
	if len(c.ServerString) > 64 || !validate.ConfValue(c.ServerString) {
		add(errors.New("SMBDECK_SMB_SERVER_STRING: up to 64 printable characters, no %, no leading ; # ["))
	}
	allow, err := e.Prefixes("SMBDECK_SMB_HOSTS_ALLOW", nil)
	add(err)
	for _, p := range allow {
		c.HostsAllow = append(c.HostsAllow, p.String())
	}
	if !filepath.IsAbs(c.StateDir) || !filepath.IsAbs(c.RunDir) || !filepath.IsAbs(c.StatusDir) {
		add(errors.New("SMBDECK_STATE_DIR, SMBDECK_STATUS_DIR and SMBDECK_RUN_DIR must be absolute"))
	}
	if c.StatusDir == c.StateDir {
		add(errors.New("SMBDECK_STATUS_DIR must differ from SMBDECK_STATE_DIR: the web console must not be able to write the agent's reports"))
	}
	return c, errors.Join(errs...)
}

// ParseRoots reads SMBDECK_ROOTS: "name=/roots/dir,name2=/roots/dir2".
// Each directory must sit under /roots/, and no root may contain another.
func ParseRoots(v string) ([]Root, error) {
	var roots []Root
	for _, item := range strings.Split(v, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		name, dir, ok := strings.Cut(item, "=")
		name, dir = strings.TrimSpace(name), strings.TrimSpace(dir)
		if !ok || !validate.RootName(name) {
			return nil, fmt.Errorf("SMBDECK_ROOTS: %q: want name=/roots/dir, with a lower-case name", item)
		}
		clean := filepath.Clean(dir)
		if clean != dir || !strings.HasPrefix(clean, RootsPrefix) || len(clean) <= len(RootsPrefix) || !validate.ConfValue(clean) {
			return nil, fmt.Errorf("SMBDECK_ROOTS: %q: the directory must be a clean path under %s", item, RootsPrefix)
		}
		for _, r := range roots {
			if r.Name == name {
				return nil, fmt.Errorf("SMBDECK_ROOTS: root %q declared twice", name)
			}
			if validate.Within(r.Dir, clean) || validate.Within(clean, r.Dir) {
				return nil, fmt.Errorf("SMBDECK_ROOTS: %s and %s overlap", r.Dir, clean)
			}
		}
		roots = append(roots, Root{Name: name, Dir: clean})
	}
	slices.SortFunc(roots, func(a, b Root) int { return strings.Compare(a.Name, b.Name) })
	return roots, nil
}
