package web

import (
	"bytes"
	"compress/gzip"
	"crypto/tls"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/yeppao-org/smbdeck/internal/state"
)

func trustLoopback(c *Config) {
	c.TrustedProxies = []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}
}

func from(c *client, ip string) *client {
	c.hdr = http.Header{"X-Forwarded-For": {ip}}
	return c
}

// S4. Behind a trusted proxy, an X-Forwarded-For hop that cannot be read
// must not fall back to the proxy's own (allowed) address.
func TestUnreadableForwardedHopIsRefused(t *testing.T) {
	e := newEnv(t, true, trustLoopback, func(c *Config) {
		c.AllowedNetworks = []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("10.0.0.0/8")}
	})
	for _, xff := range []string{"garbage", "10.0.0.1, not-an-ip", "unknown"} {
		c := e.client()
		c.hdr = http.Header{"X-Forwarded-For": {xff}}
		if r := c.get("/login"); r.code != http.StatusForbidden {
			t.Errorf("X-Forwarded-For %q: %d", xff, r.code)
		}
	}
}

// S6. Someone else, from another address, cannot lock the administrator out
// by failing on purpose; a hard lock applies to the (account, address) pair.
// A browser that signed in successfully before (device cookie) is exempt
// from the account's lock even from the same address.
func TestThirdPartyCannotLockTheAdminOut(t *testing.T) {
	e := newEnv(t, true, trustLoopback)
	e.srv.slowdown = func(int) time.Duration { return 0 }
	admin := from(e.client(), "192.168.1.10")
	if r := admin.login("sue", adminPassword); r.code != http.StatusSeeOther {
		t.Fatalf("first login: %d", r.code)
	}
	admin.get("/")
	if r := admin.post("/logout", admin.form()); r.loc != "/login" {
		t.Fatalf("logout: %d", r.code)
	}

	attacker := from(e.client(), "192.168.1.66")
	blocked := false
	for range 30 {
		if r := attacker.login("sue", "guess guess guess"); r.code == http.StatusTooManyRequests {
			blocked = true
		}
	}
	if !blocked {
		t.Fatal("the attacker's address was never locked")
	}
	other := from(e.client(), "192.168.1.11")
	if r := other.login("sue", adminPassword); r.code != http.StatusSeeOther {
		t.Fatalf("admin from another address locked out: %d", r.code)
	}
	// Same address as the attacker (NAT), but a known browser.
	nat := from(admin, "192.168.1.66")
	if r := nat.login("sue", adminPassword); r.code != http.StatusSeeOther {
		t.Fatalf("known browser locked out: %d", r.code)
	}
	raw, _ := os.ReadFile(filepath.Join(e.dir, state.AuditFile))
	if !strings.Contains(string(raw), `"action":"login.blocked"`) {
		t.Fatal("no login.blocked in the journal")
	}
	if n := strings.Count(string(raw), `"action":"login.blocked"`); n > 3 {
		t.Fatalf("%d login.blocked entries: the journal can be flooded", n)
	}
}

// S7. DNS rebinding: a page on another name that resolves to the console
// must be refused. By default, only addresses and localhost are accepted.
func TestHostHeaderIsChecked(t *testing.T) {
	e := newEnv(t, true, func(c *Config) { c.AllowedHosts = []string{"nas.local"} })
	for host, want := range map[string]int{
		"evil.example":       http.StatusMisdirectedRequest,
		"evil.example:8080":  http.StatusMisdirectedRequest,
		"nas.local:8080":     http.StatusOK,
		"NAS.local":          http.StatusOK,
		"192.168.1.5:8080":   http.StatusOK,
		"[fd00::5]:8080":     http.StatusOK,
		"localhost:8080":     http.StatusOK,
		"nas.local.evil.com": http.StatusMisdirectedRequest,
	} {
		req, _ := http.NewRequest(http.MethodGet, e.ts.URL+"/login", nil)
		req.Host = host
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = res.Body.Close()
		if res.StatusCode != want {
			t.Errorf("Host %q: %d, want %d", host, res.StatusCode, want)
		}
	}
	if r := e.client().get("/healthz"); r.code != http.StatusOK {
		t.Fatal("health check behind the host check")
	}
}

// S11. Over TLS, the browser is told to stay on HTTPS.
func TestHSTSOverTLS(t *testing.T) {
	e := newEnv(t, true)
	ts := httptestTLS(t, e.srv.Handler())
	c := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	res, err := c.Get(ts + "/login")
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	if !strings.HasPrefix(res.Header.Get("Strict-Transport-Security"), "max-age=") {
		t.Fatalf("no HSTS over TLS: %q", res.Header.Get("Strict-Transport-Security"))
	}
	if r := e.client().get("/login"); r.hdr.Get("Strict-Transport-Security") != "" {
		t.Fatal("HSTS over plain HTTP")
	}
}

// R1. An unreadable desired state does not stop the console: it serves a
// translated error instead of exiting.
func TestDegradedModeWhenStateUnreadable(t *testing.T) {
	dir := t.TempDir()
	must(t, os.WriteFile(filepath.Join(dir, state.DesiredFile), []byte("{broken"), 0o600))
	e := newEnvIn(t, dir)
	c := e.client()
	if r := c.get("/login"); r.code != http.StatusOK {
		t.Fatalf("login page: %d", r.code)
	}
	r := c.login("sue", adminPassword)
	if r.code != http.StatusServiceUnavailable || !strings.Contains(r.body, "cannot be read") {
		t.Fatalf("login with a broken state: %d", r.code)
	}
}

// R2. The status polling of an open page does not keep an idle session
// alive.
func TestStatusPollingDoesNotKeepTheSessionAlive(t *testing.T) {
	e := newEnv(t, true)
	c := e.admin()
	for range 13 {
		e.clock = e.clock.Add(10 * time.Minute)
		c.get("/api/status")
	}
	if r := c.get("/"); r.loc != "/login" {
		t.Fatal("idle session kept alive by /api/status")
	}
}

// R5. A body over the limit is "too large", not a CSRF failure.
func TestOversizedBodyIs413(t *testing.T) {
	e := newEnv(t, true)
	c := e.admin()
	c.get("/users")
	form := c.form("name", "bob", "password", strings.Repeat("x", 100<<10))
	if r := c.post("/users", form); r.code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized body: %d", r.code)
	}
}

// R6. Changing one's own password does not fail because an administrator
// changed something else meanwhile.
func TestOwnPasswordChangeIgnoresUnrelatedChanges(t *testing.T) {
	e := newEnv(t, true)
	alice := e.client()
	alice.login("alice", alicePassword)
	alice.get("/account")
	form := alice.form("current", alicePassword, "password", "a brand new password", "confirm", "a brand new password")
	admin := e.admin()
	admin.get("/users")
	admin.post("/users", admin.form("name", "bob", "password", "bob's long password"))
	if r := alice.post("/account/password", form); r.code != http.StatusSeeOther {
		t.Fatalf("own password change refused after an unrelated change: %d", r.code)
	}
}

// R7. desired.json disappearing after it existed is an error, not a new
// first run: the setup page stays closed.
func TestMissingStateIsAnErrorNotSetup(t *testing.T) {
	e := newEnv(t, true)
	c := e.admin()
	must(t, os.Remove(filepath.Join(e.dir, state.DesiredFile)))
	r := c.get("/")
	if r.loc == "/setup" || r.code != http.StatusServiceUnavailable {
		t.Fatalf("missing state: %d %s", r.code, r.loc)
	}
	if !strings.Contains(r.body, "is missing") {
		t.Fatal("no explanation")
	}
	if r := e.client().get("/setup"); r.loc != "/login" {
		t.Fatalf("setup reopened: %d %s", r.code, r.loc)
	}
}

// R13. A UID is never handed out twice through the console.
func TestUIDNotReusedThroughTheConsole(t *testing.T) {
	e := newEnv(t, true)
	c := e.admin()
	c.get("/users")
	c.post("/users", c.form("name", "zed", "password", "a long enough password"))
	first := e.state().User("zed").UID
	c.get("/users")
	c.post("/users/zed/delete", c.form())
	c.get("/users")
	c.post("/users", c.form("name", "zoe", "password", "a long enough password"))
	if second := e.state().User("zoe").UID; second <= first {
		t.Fatalf("UID %d handed out again", second)
	}
}

// R11. Times say which zone they are in.
func TestTimesShowTheirZone(t *testing.T) {
	e := newEnv(t, true)
	c := e.admin()
	r := c.get("/audit")
	name, _ := time.Now().Zone()
	if !regexp.MustCompile(`\d\d:\d\d ` + regexp.QuoteMeta(name)).MatchString(r.body) {
		t.Fatalf("no zone (%s) next to the times", name)
	}
}

// R17. Without JavaScript: every confirmation has a page of its own, and the
// folder picker fills the form through the server.
func TestNoJavaScriptFallbacks(t *testing.T) {
	e := newEnv(t, true)
	c := e.admin()
	r := c.get("/users")
	for _, href := range []string{`href="/users/alice/delete"`, `href="/users/alice/password"`} {
		if !strings.Contains(r.body, href) {
			t.Errorf("users page lacks %s", href)
		}
	}
	for path, action := range map[string]string{
		"/users/alice/delete":    `action="/users/alice/delete"`,
		"/users/alice/password":  `action="/users/alice/password"`,
		"/shares/Partage/delete": `action="/shares/Partage/delete"`,
	} {
		r := c.get(path)
		if r.code != http.StatusOK || !strings.Contains(r.body, action) || !strings.Contains(r.body, `name="csrf"`) {
			t.Errorf("%s: %d, no confirmation form", path, r.code)
		}
	}
	c.get("/shares/new")
	before := e.state().Revision
	r = c.post("/shares", c.form("name", "Films", "root", "drive1", "path", "", "pick", "drive1/media/films"))
	if r.code != http.StatusOK || !strings.Contains(r.body, `value="media/films"`) || e.state().Revision != before {
		t.Fatalf("picker without JavaScript: %d", r.code)
	}
	if strings.Contains(r.body, "commandfor=") {
		t.Error("dialogs still need invoker commands")
	}
}

// Suggestion: CSS and JS are served compressed when the browser accepts it.
func TestStaticAssetsAreCompressed(t *testing.T) {
	e := newEnv(t, false)
	req, _ := http.NewRequest(http.MethodGet, e.ts.URL+e.srv.assets.url("app.css"), nil)
	req.Header.Set("Accept-Encoding", "gzip")
	res, err := (&http.Transport{DisableCompression: true}).RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.Header.Get("Content-Encoding") != "gzip" || !strings.Contains(res.Header.Get("Vary"), "Accept-Encoding") {
		t.Fatalf("not compressed: %v", res.Header)
	}
	zr, err := gzip.NewReader(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(zr)
	if !bytes.Contains(body, []byte("--accent")) {
		t.Fatal("compressed body is not the stylesheet")
	}
}

// S2. The console reads the agent's reports from their own directory, which
// it only mounts read-only, never from the state directory it writes.
func TestReportsComeFromTheStatusDirectory(t *testing.T) {
	e := newEnv(t, true)
	d := e.state()
	writeJSON(t, filepath.Join(e.dir, state.StatusFile), state.Status{ObservedRevision: d.Revision, AppliedRevision: d.Revision, UpdatedAt: e.clock})
	c := e.admin()
	r := c.get("/api/status")
	if !strings.Contains(r.body, `"state":"unknown"`) {
		t.Fatalf("status read from the state directory: %s", r.body)
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

var _ = cookiejar.New
var _ = url.Values{}

// Seed files mounted from a Kubernetes Secret or ConfigMap are symbolic links
// (key -> ..data/key): the seed must follow them. They are configuration,
// not data the console writes.
func TestSeedFromKubernetesStyleMounts(t *testing.T) {
	seedDir := t.TempDir()
	data := filepath.Join(seedDir, "..data")
	must(t, os.MkdirAll(filepath.Join(data, "passwords"), 0o755))
	must(t, os.WriteFile(filepath.Join(data, "seed.json"), []byte(`{"users":[{"name":"sue","admin":true}],"shares":[]}`), 0o644))
	must(t, os.WriteFile(filepath.Join(data, "passwords", "sue"), []byte(adminPassword+"\n"), 0o600))
	must(t, os.Symlink(filepath.Join("..data", "seed.json"), filepath.Join(seedDir, "seed.json")))
	perAccount := filepath.Join(seedDir, "passwords")
	must(t, os.Mkdir(perAccount, 0o755))
	must(t, os.Symlink(filepath.Join(data, "passwords", "sue"), filepath.Join(perAccount, "sue")))
	dir := t.TempDir()
	seedFile := filepath.Join(seedDir, "seed.json")
	e := newEnvIn(t, dir, func(c *Config) { c.SeedFile, c.SeedPasswordsDir = seedFile, perAccount })
	if r := e.client().login("sue", adminPassword); r.code != http.StatusSeeOther {
		t.Fatalf("seeded account cannot sign in: %d", r.code)
	}
	// A FIFO in place of a password file must not block the start.
	must(t, os.Remove(filepath.Join(perAccount, "sue")))
	must(t, syscall.Mkfifo(filepath.Join(perAccount, "sue"), 0o600))
	done := make(chan error, 1)
	go func() {
		_, err := New(Config{StateDir: t.TempDir(), StatusDir: t.TempDir(), SeedFile: filepath.Join(seedDir, "seed.json"),
			SeedPasswordsDir: perAccount, PasswordMinLength: 12, AuditMaxBytes: 1 << 20}, discardLogger(), "test")
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a FIFO was accepted as a password file")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("start blocked on a FIFO")
	}
}

func discardLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }
