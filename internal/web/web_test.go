package web

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/yeppao-org/smbdeck/internal/nthash"
	"github.com/yeppao-org/smbdeck/internal/state"
)

const (
	adminPassword = "correct horse battery"
	alicePassword = "alice's long password"
)

type env struct {
	t         *testing.T
	dir       string
	statusDir string
	srv       *Server
	ts        *httptest.Server
	clock     time.Time
}

type option func(*Config)

func newEnv(t *testing.T, seed bool, opts ...option) *env {
	t.Helper()
	dir := t.TempDir()
	if seed {
		now := time.Unix(1700000000, 0).UTC()
		st := state.NewStore(dir)
		if _, err := st.Create(&state.Desired{
			Users: []state.User{
				{Name: "sue", UID: 20000, NTHash: nthash.Sum(adminPassword).String(), Admin: true, CreatedAt: now, PasswordChangedAt: now},
				{Name: "alice", UID: 20001, NTHash: nthash.Sum(alicePassword).String(), CreatedAt: now, PasswordChangedAt: now},
			},
			Shares: []state.Share{{Name: "Partage", Root: "drive1", Path: "partage", Access: map[string]state.Access{"sue": "rw", "alice": "ro"}}},
		}); err != nil {
			t.Fatal(err)
		}
	}
	return startEnv(t, dir, opts...)
}

// newEnvIn starts a console on an existing state directory.
func newEnvIn(t *testing.T, dir string, opts ...option) *env {
	t.Helper()
	return startEnv(t, dir, opts...)
}

func startEnv(t *testing.T, dir string, opts ...option) *env {
	t.Helper()
	cfg := Config{
		Listen: ":0", StateDir: dir, AllowedNetworks: DefaultAllowedNetworks, CookieSecure: "auto",
		PasswordMinLength: 12, SessionLifetime: 12 * time.Hour, SessionIdle: 2 * time.Hour,
		AuditMaxBytes: 1 << 20, AgentStale: 3 * time.Minute,
	}
	statusDir := t.TempDir()
	cfg.StatusDir = statusDir
	for _, o := range opts {
		o(&cfg)
	}
	writeJSON(t, filepath.Join(statusDir, state.TreeFile), state.Tree{Roots: []state.TreeRoot{
		{Name: "drive1", Available: true, Folders: []string{"media", "media/films", "partage"}},
	}})
	srv, err := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), "test")
	if err != nil {
		t.Fatal(err)
	}
	e := &env{t: t, dir: dir, statusDir: statusDir, srv: srv, clock: time.Now()}
	srv.now = func() time.Time { return e.clock }
	e.ts = httptest.NewServer(srv.Handler())
	t.Cleanup(e.ts.Close)
	return e
}

func httptestTLS(t *testing.T, h http.Handler) string {
	t.Helper()
	ts := httptest.NewTLSServer(h)
	t.Cleanup(ts.Close)
	return ts.URL
}

func writeJSON(t *testing.T, path string, v any) {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
}

// client is a browser: cookies, no automatic redirects, and the last page's
// hidden fields at hand.
type client struct {
	e    *env
	http *http.Client
	page string
	hdr  http.Header
}

func (e *env) client() *client {
	jar, _ := cookiejar.New(nil)
	return &client{e: e, http: &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}}
}

type resp struct {
	code int
	body string
	loc  string
	hdr  http.Header
}

func (c *client) do(req *http.Request) resp {
	c.e.t.Helper()
	for k, v := range c.hdr {
		req.Header[k] = v
	}
	r, err := c.http.Do(req)
	if err != nil {
		c.e.t.Fatal(err)
	}
	defer r.Body.Close()
	b, _ := io.ReadAll(r.Body)
	out := resp{code: r.StatusCode, body: string(b), loc: r.Header.Get("Location"), hdr: r.Header}
	if strings.HasPrefix(r.Header.Get("Content-Type"), "text/html") {
		c.page = out.body
	}
	return out
}

func (c *client) get(path string) resp {
	req, _ := http.NewRequest(http.MethodGet, c.e.ts.URL+path, nil)
	return c.do(req)
}

func (c *client) post(path string, form url.Values) resp {
	req, _ := http.NewRequest(http.MethodPost, c.e.ts.URL+path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return c.do(req)
}

var (
	csrfRE = regexp.MustCompile(`name="csrf" value="([^"]+)"`)
	revRE  = regexp.MustCompile(`name="rev" value="(\d+)"`)
	preRE  = regexp.MustCompile(`name="pre" value="([^"]+)"`)
)

func field(re *regexp.Regexp, page string) string {
	if m := re.FindStringSubmatch(page); m != nil {
		return m[1]
	}
	return ""
}

// form returns values with the csrf and rev fields of the last page.
func (c *client) form(kv ...string) url.Values {
	v := url.Values{"csrf": {field(csrfRE, c.page)}, "rev": {field(revRE, c.page)}}
	for i := 0; i+1 < len(kv); i += 2 {
		v.Set(kv[i], kv[i+1])
	}
	return v
}

func (c *client) login(name, password string) resp {
	c.get("/login")
	return c.post("/login", url.Values{"pre": {field(preRE, c.page)}, "name": {name}, "password": {password}})
}

func (e *env) state() *state.Desired {
	e.t.Helper()
	d, err := state.NewStore(e.dir).Load()
	if err != nil {
		e.t.Fatal(err)
	}
	return d
}

func (e *env) admin() *client {
	c := e.client()
	if r := c.login("sue", adminPassword); r.code != http.StatusSeeOther || r.loc != "/" {
		e.t.Fatalf("admin login: %d %s", r.code, r.loc)
	}
	return c
}

// --- tests ------------------------------------------------------------------

func TestSecurityHeadersAndNoInlineCode(t *testing.T) {
	e := newEnv(t, true)
	c := e.admin()
	for _, path := range []string{"/login", "/", "/users", "/shares", "/shares/new", "/shares/Partage", "/audit", "/account"} {
		r := c.get(path)
		if path == "/login" {
			r = e.client().get(path)
		}
		if r.code != http.StatusOK {
			t.Fatalf("%s: %d", path, r.code)
		}
		if got := r.hdr.Get("Content-Security-Policy"); got != contentSecurityPolicy {
			t.Errorf("%s: CSP %q", path, got)
		}
		for h, want := range map[string]string{
			"X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY", "Referrer-Policy": "same-origin",
			"Cache-Control": "no-store",
		} {
			if got := r.hdr.Get(h); got != want {
				t.Errorf("%s: %s = %q", path, h, got)
			}
		}
		if !strings.Contains(r.hdr.Get("Permissions-Policy"), "camera=()") {
			t.Errorf("%s: Permissions-Policy", path)
		}
		// The CSP forbids inline code; the pages must not need any.
		for _, bad := range []string{"<style", " style=", "<script>", "javascript:", " onclick=", " onload="} {
			if strings.Contains(r.body, bad) {
				t.Errorf("%s contains %q", path, bad)
			}
		}
	}
	if !strings.Contains(contentSecurityPolicy, "frame-ancestors 'none'") || strings.Contains(contentSecurityPolicy, "unsafe") {
		t.Fatal("CSP weakened")
	}
}

func TestSetupHappensOnce(t *testing.T) {
	e := newEnv(t, false)
	if e.srv.setupCode == "" {
		t.Fatal("no setup code without state")
	}
	c := e.client()
	if r := c.get("/"); r.code != http.StatusSeeOther || r.loc != "/setup" {
		t.Fatalf("home without state: %d %s", r.code, r.loc)
	}
	c.get("/setup")
	pre := field(preRE, c.page)
	form := url.Values{"pre": {pre}, "code": {"WRONG-CODE-0000"}, "name": {"sue"}, "password": {adminPassword}, "confirm": {adminPassword}}
	if r := c.post("/setup", form); r.code != http.StatusUnauthorized {
		t.Fatalf("wrong code: %d", r.code)
	}
	form.Set("pre", field(preRE, c.page))
	form.Set("code", strings.ToLower(e.srv.setupCode))
	form.Set("password", "short")
	form.Set("confirm", "short")
	if r := c.post("/setup", form); r.code != http.StatusUnprocessableEntity || !strings.Contains(r.body, "at least 12") {
		t.Fatalf("short password: %d", r.code)
	}
	form.Set("pre", field(preRE, c.page))
	form.Set("password", adminPassword)
	form.Set("confirm", adminPassword)
	if r := c.post("/setup", form); r.code != http.StatusSeeOther || r.loc != "/" {
		t.Fatalf("setup: %d %s %s", r.code, r.loc, r.body)
	}
	d := e.state()
	if len(d.Users) != 1 || !d.Users[0].Admin || d.Users[0].NTHash != nthash.Sum(adminPassword).String() {
		t.Fatalf("state after setup: %+v", d.Users)
	}
	if r := c.get("/"); r.code != http.StatusOK {
		t.Fatalf("signed in after setup: %d", r.code)
	}
	// Never again, even with the old code.
	other := e.client()
	if r := other.get("/setup"); r.code != http.StatusSeeOther || r.loc != "/login" {
		t.Fatalf("setup page after setup: %d", r.code)
	}
	form.Set("name", "mallory")
	if r := other.post("/setup", form); r.code != http.StatusSeeOther || len(e.state().Users) != 1 {
		t.Fatal("second setup accepted")
	}
}

func TestSetupNeedsPreAuthToken(t *testing.T) {
	e := newEnv(t, false)
	c := e.client()
	c.get("/setup")
	form := url.Values{"pre": {"forged"}, "code": {e.srv.setupCode}, "name": {"sue"}, "password": {adminPassword}, "confirm": {adminPassword}}
	if r := c.post("/setup", form); r.code != http.StatusForbidden {
		t.Fatalf("forged token: %d", r.code)
	}
}

func TestLoginAndCookies(t *testing.T) {
	e := newEnv(t, true)
	c := e.client()
	if r := c.login("sue", "wrong password!"); r.code != http.StatusUnauthorized || !strings.Contains(r.body, "Wrong account or password") {
		t.Fatalf("wrong password: %d", r.code)
	}
	if r := c.login("nobody-here", adminPassword); r.code != http.StatusUnauthorized {
		t.Fatalf("unknown account: %d", r.code)
	}
	r := c.login("SUE ", adminPassword)
	if r.code != http.StatusSeeOther {
		t.Fatalf("login: %d", r.code)
	}
	var session *http.Cookie
	for _, ck := range (&http.Response{Header: r.hdr}).Cookies() {
		if ck.Name == cookieSession {
			session = ck
		}
	}
	if session == nil || !session.HttpOnly || session.SameSite != http.SameSiteStrictMode || session.Secure || len(session.Value) < 40 {
		t.Fatalf("session cookie: %+v", session)
	}
	// A forwarded "https" from an untrusted peer changes nothing.
	c2 := e.client()
	c2.hdr = http.Header{"X-Forwarded-Proto": {"https"}}
	r = c2.login("sue", adminPassword)
	for _, ck := range (&http.Response{Header: r.hdr}).Cookies() {
		if ck.Secure || strings.HasPrefix(ck.Name, securePrefix) {
			t.Fatalf("untrusted X-Forwarded-Proto honored: %+v", ck)
		}
	}
	// The audit log never holds a password or a hash.
	raw, _ := os.ReadFile(filepath.Join(e.dir, state.AuditFile))
	for _, secret := range []string{adminPassword, "wrong password!", nthash.Sum(adminPassword).String(), "nobody-here"} {
		if strings.Contains(string(raw), secret) {
			t.Fatalf("audit log contains %q", secret)
		}
	}
	if !strings.Contains(string(raw), `"action":"login.failed"`) || !strings.Contains(string(raw), `"action":"login.ok"`) {
		t.Fatalf("audit log: %s", raw)
	}
}

func TestSecureCookiesBehindTrustedProxy(t *testing.T) {
	e := newEnv(t, true, func(c *Config) { c.TrustedProxies = []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")} })
	c := e.client()
	c.hdr = http.Header{"X-Forwarded-Proto": {"https"}, "X-Forwarded-For": {"192.168.1.20"}}
	r := c.login("sue", adminPassword)
	found := false
	for _, ck := range (&http.Response{Header: r.hdr}).Cookies() {
		if ck.Name == securePrefix+cookieSession {
			found = ck.Secure
		}
	}
	if !found {
		t.Fatal("no __Host- secure cookie behind a trusted HTTPS proxy")
	}
}

func TestLoginRateLimit(t *testing.T) {
	e := newEnv(t, true)
	c := e.client()
	for i := range 5 {
		if r := c.login("sue", "nope nope nope"); r.code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: %d", i, r.code)
		}
	}
	c.login("sue", "nope nope nope") // sixth failure: locked from now on
	r := c.login("sue", adminPassword)
	if r.code != http.StatusTooManyRequests || r.hdr.Get("Retry-After") == "" {
		t.Fatalf("locked account accepted: %d", r.code)
	}
	// Time passes: the lock lifts.
	e.clock = e.clock.Add(5 * time.Second)
	if r := c.login("sue", adminPassword); r.code != http.StatusSeeOther {
		t.Fatalf("after the wait: %d", r.code)
	}
}

func TestCSRFAndCrossOrigin(t *testing.T) {
	e := newEnv(t, true)
	c := e.admin()
	c.get("/users")
	good := c.form("name", "bob", "password", "bob's long password")
	noToken := c.form("name", "bob", "password", "bob's long password")
	noToken.Del("csrf")
	if r := c.post("/users", noToken); r.code != http.StatusForbidden {
		t.Fatalf("missing token: %d", r.code)
	}
	bad := c.form("name", "bob", "password", "bob's long password")
	tok := []byte(bad.Get("csrf"))
	tok[0] ^= 1 // still base64url, never equal
	bad.Set("csrf", string(tok))
	if r := c.post("/users", bad); r.code != http.StatusForbidden {
		t.Fatalf("wrong token: %d", r.code)
	}
	c.hdr = http.Header{"Origin": {"https://evil.example"}}
	if r := c.post("/users", good); r.code != http.StatusForbidden {
		t.Fatalf("cross-origin: %d", r.code)
	}
	c.hdr = http.Header{"Sec-Fetch-Site": {"cross-site"}}
	if r := c.post("/users", good); r.code != http.StatusForbidden {
		t.Fatalf("cross-site fetch: %d", r.code)
	}
	if e.state().User("bob") != nil {
		t.Fatal("a refused request created an account")
	}
	c.hdr = http.Header{"Sec-Fetch-Site": {"same-origin"}}
	if r := c.post("/users", good); r.code != http.StatusSeeOther || e.state().User("bob") == nil {
		t.Fatalf("same-origin request refused: %d", r.code)
	}
}

// What a browser sends over plain HTTP (no Sec-Fetch-Site, Origin set to the
// page's origin) must pass; an opaque "null" origin must not.
func TestBrowserOriginOverPlainHTTP(t *testing.T) {
	e := newEnv(t, true)
	c := e.client()
	c.get("/login")
	form := url.Values{"pre": {field(preRE, c.page)}, "name": {"sue"}, "password": {adminPassword}}
	c.hdr = http.Header{"Origin": {"null"}}
	if r := c.post("/login", form); r.code != http.StatusForbidden {
		t.Fatalf("Origin: null accepted: %d", r.code)
	}
	c.get("/login")
	form.Set("pre", field(preRE, c.page))
	c.hdr = http.Header{"Origin": {e.ts.URL}}
	if r := c.post("/login", form); r.code != http.StatusSeeOther {
		t.Fatalf("same-origin browser login refused: %d", r.code)
	}
}

func TestAllowedNetworksAndProxies(t *testing.T) {
	only10 := func(c *Config) { c.AllowedNetworks = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")} }
	e := newEnv(t, true, only10)
	c := e.client()
	if r := c.get("/login"); r.code != http.StatusForbidden {
		t.Fatalf("loopback outside allowed networks: %d", r.code)
	}
	if r := c.get("/healthz"); r.code != http.StatusOK {
		t.Fatalf("health check gated: %d", r.code)
	}
	c.hdr = http.Header{"X-Forwarded-For": {"10.1.2.3"}}
	if r := c.get("/login"); r.code != http.StatusForbidden {
		t.Fatal("X-Forwarded-For believed without a trusted proxy")
	}
	e2 := newEnv(t, true, only10, func(c *Config) { c.TrustedProxies = []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")} })
	c2 := e2.client()
	c2.hdr = http.Header{"X-Forwarded-For": {"203.0.113.9, 10.1.2.3"}}
	if r := c2.get("/login"); r.code != http.StatusOK {
		t.Fatalf("trusted proxy, allowed client: %d", r.code)
	}
	// The client is the rightmost untrusted hop: a spoofed leftmost entry
	// cannot let a public address in.
	c2.hdr = http.Header{"X-Forwarded-For": {"10.1.2.3, 203.0.113.9"}}
	if r := c2.get("/login"); r.code != http.StatusForbidden {
		t.Fatalf("spoofed X-Forwarded-For: %d", r.code)
	}
}

func TestAccountsAndGeneratedPassword(t *testing.T) {
	e := newEnv(t, true)
	c := e.admin()
	c.get("/users")
	if r := c.post("/users", c.form("name", "bob", "admin", "on")); r.code != http.StatusSeeOther {
		t.Fatalf("create: %d %s", r.code, r.body)
	}
	r := c.get("/users")
	m := regexp.MustCompile(`id="revealed-password">([^<]+)<`).FindStringSubmatch(r.body)
	if m == nil {
		t.Fatal("generated password not shown")
	}
	bob := e.state().User("bob")
	if bob == nil || !bob.Admin || bob.UID != 20002 || bob.NTHash != nthash.Sum(m[1]).String() {
		t.Fatalf("bob: %+v", bob)
	}
	if len(m[1]) != 23 {
		t.Fatalf("generated password %q", m[1])
	}
	if r := c.get("/users"); strings.Contains(r.body, m[1]) {
		t.Fatal("generated password shown twice")
	}
	// Refused: invalid, reserved and duplicate names, short password.
	for _, tc := range []struct{ name, pw, want string }{
		{"1bob", "a long enough password", "lower-case letters"},
		{"root", "a long enough password", "reserved"},
		{"bob", "a long enough password", "already exists"},
		{"carol", "short", "at least 12"},
		{"x\n[global]", "a long enough password", "lower-case letters"},
	} {
		c.get("/users")
		r := c.post("/users", c.form("name", tc.name, "password", tc.pw))
		if r.code != http.StatusUnprocessableEntity || !strings.Contains(r.body, tc.want) {
			t.Errorf("%q: %d, want %q", tc.name, r.code, tc.want)
		}
	}
	if len(e.state().Users) != 3 {
		t.Fatal("a refused account was written")
	}
}

func TestShares(t *testing.T) {
	e := newEnv(t, true)
	c := e.admin()
	c.get("/shares/new")
	r := c.post("/shares", c.form("name", "Media 2", "root", "drive1", "path", "/media/films/", "access_alice", "ro", "access_sue", "rw",
		"timemachine", "on", "timemachine_max", "500g", "create_folder", "on"))
	if r.code != http.StatusSeeOther {
		t.Fatalf("create share: %d %s", r.code, r.body)
	}
	sh := e.state().Share("media 2")
	if sh == nil || sh.Path != "media/films" || sh.Access["alice"] != "ro" || sh.Access["sue"] != "rw" ||
		!sh.TimeMachine.Enabled || sh.TimeMachine.MaxSize != "500G" || !sh.CreateFolder {
		t.Fatalf("share: %+v", sh)
	}
	for _, tc := range []struct{ name, root, path, want string }{
		{"Escape", "drive1", "../etc", "Invalid folder path"},
		{"Abs", "drive1", "/etc/passwd/..", "Invalid folder path"},
		{"Pct", "drive1", "a/%U", "Invalid folder path"},
		{"x]\n[global]", "drive1", "", "Share names use"},
		{"global", "drive1", "", "reserved"},
		{"partage", "drive1", "", "already exists"},
		{"Other", "drive9", "", "Unknown root"},
	} {
		c.get("/shares/new")
		r := c.post("/shares", c.form("name", tc.name, "root", tc.root, "path", tc.path))
		if r.code != http.StatusUnprocessableEntity || !strings.Contains(r.body, tc.want) {
			t.Errorf("%q/%q: %d, want %q", tc.name, tc.path, r.code, tc.want)
		}
	}
	// Edit and rename, then delete.
	c.get("/shares/Media%202")
	if r := c.post("/shares/Media%202", c.form("name", "Films", "root", "drive1", "path", "media/films", "access_alice", "rw")); r.code != http.StatusSeeOther {
		t.Fatalf("edit: %d %s", r.code, r.body)
	}
	d := e.state()
	if d.Share("Media 2") != nil || d.Share("Films") == nil || d.Share("Films").Access["alice"] != "rw" || d.Share("Films").Access["sue"] != "" {
		t.Fatalf("after edit: %+v", d.Shares)
	}
	c.get("/shares/Films")
	if r := c.post("/shares/Films/delete", c.form()); r.code != http.StatusSeeOther || e.state().Share("Films") != nil {
		t.Fatalf("delete: %d", r.code)
	}
}

func TestOptimisticConcurrency(t *testing.T) {
	e := newEnv(t, true)
	a, b := e.admin(), e.admin()
	a.get("/users")
	b.get("/users")
	if r := a.post("/users", a.form("name", "first", "password", "a long enough password")); r.code != http.StatusSeeOther {
		t.Fatalf("first writer: %d", r.code)
	}
	r := b.post("/users", b.form("name", "second", "password", "a long enough password"))
	if r.code != http.StatusUnprocessableEntity || !strings.Contains(r.body, "changed meanwhile") {
		t.Fatalf("stale writer: %d", r.code)
	}
	if e.state().User("second") != nil {
		t.Fatal("stale write applied")
	}
}

func TestAtLeastOneActiveAdmin(t *testing.T) {
	e := newEnv(t, true)
	c := e.admin()
	for _, action := range []string{"disable", "revoke-admin", "delete"} {
		c.get("/users")
		c.post("/users/sue/"+action, c.form())
		u := e.state().User("sue")
		if u == nil || !u.Admin || u.Disabled {
			t.Fatalf("%s left no active admin", action)
		}
		if r := c.get("/users"); !strings.Contains(r.body, "At least one active administrator") {
			t.Errorf("%s: no explanation shown", action)
		}
	}
	// With a second admin, the first may step down.
	c.get("/users")
	c.post("/users/alice/grant-admin", c.form())
	c.get("/users")
	if r := c.post("/users/sue/revoke-admin", c.form()); r.code != http.StatusSeeOther || e.state().User("sue").Admin {
		t.Fatal("could not step down with another admin present")
	}
}

func TestNonAdminSeesOnlyTheirAccount(t *testing.T) {
	e := newEnv(t, true)
	c := e.client()
	if r := c.login("alice", alicePassword); r.loc != "/account" {
		t.Fatalf("alice lands on %s", r.loc)
	}
	r := c.get("/account")
	if r.code != http.StatusOK || !strings.Contains(r.body, "Partage") || strings.Contains(r.body, "/users") {
		t.Fatalf("account page: %d", r.code)
	}
	if r := c.get("/"); r.loc != "/account" {
		t.Fatalf("home: %s", r.loc)
	}
	for _, p := range []string{"/users", "/shares", "/audit", "/shares/Partage"} {
		if r := c.get(p); r.code != http.StatusForbidden {
			t.Errorf("%s: %d", p, r.code)
		}
	}
	c.get("/account")
	if r := c.post("/users", c.form("name", "mallory", "password", "a long enough password", "admin", "on")); r.code != http.StatusForbidden {
		t.Fatalf("non-admin created an account: %d", r.code)
	}
	// Own password: the current one is required.
	c.get("/account")
	if r := c.post("/account/password", c.form("current", "wrong", "password", "a brand new password", "confirm", "a brand new password")); r.code != http.StatusUnauthorized {
		t.Fatalf("wrong current password: %d", r.code)
	}
	c.get("/account")
	if r := c.post("/account/password", c.form("current", alicePassword, "password", "a brand new password", "confirm", "a brand new password")); r.code != http.StatusSeeOther {
		t.Fatalf("change password: %d %s", r.code, r.body)
	}
	if e.state().User("alice").NTHash != nthash.Sum("a brand new password").String() {
		t.Fatal("password not changed")
	}
	if r := c.get("/account"); r.code != http.StatusOK {
		t.Fatalf("session not renewed after own password change: %d", r.code)
	}
}

func TestSessionsEndWhenAccountChanges(t *testing.T) {
	e := newEnv(t, true)
	admin := e.admin()
	alice := e.client()
	alice.login("alice", alicePassword)

	admin.get("/users")
	admin.post("/users/alice/password", admin.form("password", "another long password"))
	if r := alice.get("/account"); r.code != http.StatusSeeOther || r.loc != "/login" {
		t.Fatalf("session survived a password reset: %d", r.code)
	}
	alice.login("alice", "another long password")
	admin.get("/users")
	admin.post("/users/alice/disable", admin.form())
	if r := alice.get("/account"); r.loc != "/login" {
		t.Fatal("session survived disabling")
	}
	if r := alice.login("alice", "another long password"); r.code != http.StatusUnauthorized {
		t.Fatal("disabled account signed in")
	}
}

// A change made outside this console (another replica, or the file edited
// by hand) ends the sessions it concerns on their next request.
func TestSessionsFollowTheStateWrittenElsewhere(t *testing.T) {
	e := newEnv(t, true)
	alice := e.client()
	alice.login("alice", alicePassword)
	if r := alice.get("/account"); r.code != http.StatusOK {
		t.Fatalf("signed in: %d", r.code)
	}
	st := state.NewStore(e.dir)
	cur, _ := st.Load()
	if _, err := st.Update(cur.Revision, func(d *state.Desired) error {
		d.User("alice").PasswordChangedAt = d.User("alice").PasswordChangedAt.Add(time.Minute)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if r := alice.get("/account"); r.loc != "/login" {
		t.Fatal("session survived a password change made elsewhere")
	}
	alice.login("alice", alicePassword)
	cur, _ = st.Load()
	if _, err := st.Update(cur.Revision, func(d *state.Desired) error { d.User("alice").Disabled = true; return nil }); err != nil {
		t.Fatal(err)
	}
	if r := alice.get("/account"); r.loc != "/login" {
		t.Fatal("session survived disabling made elsewhere")
	}
}

func TestSessionExpiry(t *testing.T) {
	e := newEnv(t, true)
	c := e.admin()
	e.clock = e.clock.Add(2*time.Hour + time.Minute)
	if r := c.get("/"); r.loc != "/login" {
		t.Fatal("idle session still valid")
	}
	c = e.admin()
	for range 7 {
		e.clock = e.clock.Add(110 * time.Minute)
		c.get("/")
	}
	if r := c.get("/"); r.loc != "/login" {
		t.Fatal("session older than its lifetime still valid")
	}
}

func TestLogout(t *testing.T) {
	e := newEnv(t, true)
	c := e.admin()
	c.get("/")
	if r := c.post("/logout", c.form()); r.loc != "/login" {
		t.Fatalf("logout: %d", r.code)
	}
	if r := c.get("/"); r.loc != "/login" {
		t.Fatal("still signed in after logout")
	}
}

func TestLanguage(t *testing.T) {
	e := newEnv(t, true)
	c := e.client()
	c.hdr = http.Header{"Accept-Language": {"fr-FR,fr;q=0.9,en;q=0.8"}}
	if r := c.get("/login"); !strings.Contains(r.body, `lang="fr"`) || !strings.Contains(r.body, "Se connecter") {
		t.Fatal("French not chosen from Accept-Language")
	}
	if r := c.get("/lang/en?next=/login"); r.loc != "/login" {
		t.Fatalf("lang redirect: %s", r.loc)
	}
	if r := c.get("/login"); !strings.Contains(r.body, `lang="en"`) {
		t.Fatal("cookie choice ignored")
	}
	for _, next := range []string{"//evil.example", "https://evil.example", "/\\evil.example", "javascript:alert(1)"} {
		if r := c.get("/lang/fr?next=" + url.QueryEscape(next)); r.loc != "/" {
			t.Errorf("open redirect to %q: %s", next, r.loc)
		}
	}
	if r := c.get("/lang/de"); r.code != http.StatusNotFound {
		t.Fatal("unsupported language accepted")
	}
}

func TestAPIStatus(t *testing.T) {
	e := newEnv(t, true)
	c := e.admin()
	get := func() apiStatus {
		r := c.get("/api/status")
		var s apiStatus
		if err := json.Unmarshal([]byte(r.body), &s); err != nil {
			t.Fatalf("%d %s", r.code, r.body)
		}
		return s
	}
	if s := get(); s.State != agentUnknown {
		t.Fatalf("no status file: %s", s.State)
	}
	d := e.state()
	writeJSON(t, filepath.Join(e.statusDir, state.StatusFile), state.Status{ObservedRevision: d.Revision - 1, AppliedRevision: d.Revision - 1, UpdatedAt: e.clock})
	if s := get(); s.State != agentPending {
		t.Fatalf("older revision: %s", s.State)
	}
	writeJSON(t, filepath.Join(e.statusDir, state.StatusFile), state.Status{ObservedRevision: d.Revision, AppliedRevision: d.Revision, UpdatedAt: e.clock, SMBD: state.SMBDStatus{Running: true}})
	if s := get(); s.State != agentApplied || !s.SMBD || s.Label != "Applied" {
		t.Fatalf("applied: %+v", s)
	}
	e.clock = e.clock.Add(5 * time.Minute)
	if s := get(); s.State != agentDown {
		t.Fatalf("stale status: %s", s.State)
	}
	anon := e.client()
	if r := anon.get("/api/status"); r.code != http.StatusUnauthorized {
		t.Fatalf("anonymous status: %d", r.code)
	}
}

func TestIssuesFromAgentAreShownTranslated(t *testing.T) {
	e := newEnv(t, true)
	d := e.state()
	writeJSON(t, filepath.Join(e.statusDir, state.StatusFile), state.Status{ObservedRevision: d.Revision, AppliedRevision: d.Revision, UpdatedAt: e.clock,
		Issues: []state.Issue{{Kind: "share", Name: "Partage", Field: "path", Code: "share.path.outside_root"}}})
	c := e.admin()
	r := c.get("/")
	if !strings.Contains(r.body, "leads outside its root") || !strings.Contains(r.body, "Not published") {
		t.Fatal("agent issue not shown")
	}
}

func TestStaticAssets(t *testing.T) {
	e := newEnv(t, false)
	c := e.client()
	r := c.get(e.srv.assets.url("app.css"))
	if r.code != http.StatusOK || !strings.Contains(r.hdr.Get("Cache-Control"), "immutable") || !strings.HasPrefix(r.hdr.Get("Content-Type"), "text/css") {
		t.Fatalf("css: %d %v", r.code, r.hdr)
	}
	if r := c.get("/static/fonts/host-grotesk-latin.woff2"); r.code != http.StatusOK || r.hdr.Get("Content-Type") != "font/woff2" {
		t.Fatalf("font: %d", r.code)
	}
	for _, p := range []string{"/static/nope.css", "/static/app.css.map", "/static/fonts/"} {
		if r := c.get(p); r.code != http.StatusNotFound {
			t.Errorf("%s: %d", p, r.code)
		}
	}
}

func TestLocalPath(t *testing.T) {
	for in, want := range map[string]string{
		"/users": "/users", "": "/", "users": "/", "//x": "/", "/\\x": "/", "/a\nb": "/", "https://x": "/",
	} {
		if got := localPath(in); got != want {
			t.Errorf("localPath(%q) = %q", in, got)
		}
	}
}
