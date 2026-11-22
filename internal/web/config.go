package web

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/yeppao-org/smbdeck/internal/config"
)

// Config is the web console's configuration.
type Config struct {
	Listen string
	// StateDir holds desired.json and the journal (read-write); StatusDir the
	// agent's reports, mounted read-only.
	StateDir  string
	StatusDir string
	// AllowedNetworks may reach the UI at all; others get 403 before any
	// handler runs.
	AllowedNetworks []netip.Prefix
	// TrustedProxies may set X-Forwarded-For and X-Forwarded-Proto. Empty
	// means those headers are ignored.
	TrustedProxies []netip.Prefix
	// AllowedHosts are the host names the console answers to (Host header),
	// besides IP addresses and localhost: anything else gets 421, which
	// defeats DNS rebinding.
	AllowedHosts []string
	// CookieSecure is "auto" (Secure when the request came over HTTPS),
	// "always" or "never".
	CookieSecure      string
	TLSCert, TLSKey   string
	PasswordMinLength int
	SessionLifetime   time.Duration
	SessionIdle       time.Duration
	// SMBHosts are the names or addresses shown in connection strings. Empty
	// means the host name the browser used.
	SMBHosts         []string
	SeedFile         string
	SeedPasswordsDir string
	AuditMaxBytes    int64
	// AgentStale is the age after which a status file means "agent down".
	AgentStale time.Duration
}

// DefaultAllowedNetworks are the private ranges: loopback, RFC 1918, carrier-
// grade NAT (Tailscale and other overlays use 100.64.0.0/10), and their IPv6
// counterparts (unique local and link-local).
var DefaultAllowedNetworks = []netip.Prefix{
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fe80::/10"),
}

var hostRE = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$`)

// FromEnv reads the web configuration.
func FromEnv(e config.Env) (Config, error) {
	c := Config{
		Listen:           e.String("SMBDECK_LISTEN", ":8080"),
		StateDir:         e.String("SMBDECK_STATE_DIR", "/state"),
		StatusDir:        e.String("SMBDECK_STATUS_DIR", "/status"),
		CookieSecure:     strings.ToLower(e.String("SMBDECK_COOKIE_SECURE", "auto")),
		TLSCert:          e.String("SMBDECK_TLS_CERT", ""),
		TLSKey:           e.String("SMBDECK_TLS_KEY", ""),
		SeedFile:         e.String("SMBDECK_SEED_FILE", ""),
		SeedPasswordsDir: e.String("SMBDECK_SEED_PASSWORDS_DIR", ""),
		AgentStale:       3 * time.Minute,
	}
	var errs []error
	add := func(err error) {
		if err != nil {
			errs = append(errs, err)
		}
	}
	var err error
	c.AllowedNetworks, err = e.Prefixes("SMBDECK_ALLOWED_NETWORKS", DefaultAllowedNetworks)
	add(err)
	c.TrustedProxies, err = e.Prefixes("SMBDECK_TRUSTED_PROXIES", nil)
	add(err)
	c.PasswordMinLength, err = e.Int("SMBDECK_PASSWORD_MIN_LENGTH", 12, 8, 128)
	add(err)
	c.SessionLifetime, err = e.Duration("SMBDECK_SESSION_LIFETIME", 12*time.Hour, 5*time.Minute, 30*24*time.Hour)
	add(err)
	c.SessionIdle, err = e.Duration("SMBDECK_SESSION_IDLE", 2*time.Hour, time.Minute, 30*24*time.Hour)
	add(err)
	// The journal keeps two files of at most this size; only their ends are
	// read for display.
	maxKB, err := e.Int("SMBDECK_AUDIT_MAX_KB", 1024, 16, 16384)
	add(err)
	c.AuditMaxBytes = int64(maxKB) << 10

	switch c.CookieSecure {
	case "auto", "always", "never":
	default:
		add(errors.New("SMBDECK_COOKIE_SECURE: want auto, always or never"))
	}
	if (c.TLSCert == "") != (c.TLSKey == "") {
		add(errors.New("SMBDECK_TLS_CERT and SMBDECK_TLS_KEY go together"))
	}
	if _, _, err := net.SplitHostPort(c.Listen); err != nil {
		add(fmt.Errorf("SMBDECK_LISTEN: %w", err))
	}
	if !filepath.IsAbs(c.StateDir) || !filepath.IsAbs(c.StatusDir) {
		add(errors.New("SMBDECK_STATE_DIR and SMBDECK_STATUS_DIR must be absolute"))
	}
	for _, h := range e.List("SMBDECK_ALLOWED_HOSTS") {
		h = strings.TrimSuffix(strings.ToLower(h), ".")
		if !hostRE.MatchString(h) {
			add(fmt.Errorf("SMBDECK_ALLOWED_HOSTS: %q is not a host name", h))
			continue
		}
		c.AllowedHosts = append(c.AllowedHosts, h)
	}
	for _, h := range e.List("SMBDECK_SMB_HOSTS") {
		if _, err := netip.ParseAddr(h); err != nil && !hostRE.MatchString(h) {
			add(fmt.Errorf("SMBDECK_SMB_HOSTS: %q is not a host name or address", h))
			continue
		}
		c.SMBHosts = append(c.SMBHosts, h)
	}
	if (c.SeedFile == "") != (c.SeedPasswordsDir == "") {
		add(errors.New("SMBDECK_SEED_FILE and SMBDECK_SEED_PASSWORDS_DIR go together"))
	}
	if c.SessionIdle > c.SessionLifetime {
		c.SessionIdle = c.SessionLifetime
	}
	return c, errors.Join(errs...)
}
