//go:build integration

// Package integration drives a real Samba through the web console. It runs in
// a container next to the agent and the web roles: see run.sh, which sets the
// environment below.
package integration

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/yeppao-org/smbdeck/internal/state"
)

var (
	webURL    = env("SMBDECK_IT_WEB", "http://web:8080")
	smbHost   = env("SMBDECK_IT_SMB", "smb")
	stateDir  = env("SMBDECK_IT_STATE", "/state")
	statusDir = env("SMBDECK_IT_STATUS", "/status")
	rootView  = env("SMBDECK_IT_ROOT", "/roots-ro")
	setupCode = os.Getenv("SMBDECK_IT_SETUP_CODE")
)

// Throwaway credentials for a throwaway server. The account password holds
// characters outside ASCII: the NT hash is computed over UTF-16, and Samba
// must agree with the console on it.
const (
	adminPassword  = "integration-admin-pass"
	alicePassword  = "Ünïcødé-pässwörd-42"
	alicePassword2 = "a second password 4 alice"
)

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// --- a browser ---------------------------------------------------------------

type browser struct {
	t    *testing.T
	c    *http.Client
	page string
}

func newBrowser(t *testing.T) *browser {
	jar, _ := cookiejar.New(nil)
	return &browser{t: t, c: &http.Client{Jar: jar, Timeout: 20 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

type response struct {
	code int
	body string
	loc  string
}

func (b *browser) do(method, path string, form url.Values) response {
	b.t.Helper()
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequest(method, webURL+path, body)
	if err != nil {
		b.t.Fatal(err)
	}
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		// What a browser sends on a same-origin form post over plain HTTP.
		req.Header.Set("Origin", webURL)
	}
	res, err := b.c.Do(req)
	if err != nil {
		b.t.Fatal(err)
	}
	defer res.Body.Close()
	data, _ := io.ReadAll(res.Body)
	r := response{code: res.StatusCode, body: string(data), loc: res.Header.Get("Location")}
	if strings.HasPrefix(res.Header.Get("Content-Type"), "text/html") {
		b.page = r.body
	}
	return r
}

func (b *browser) get(path string) response { return b.do(http.MethodGet, path, nil) }

var (
	csrfRE = regexp.MustCompile(`name="csrf" value="([^"]+)"`)
	revRE  = regexp.MustCompile(`name="rev" value="(\d+)"`)
	preRE  = regexp.MustCompile(`name="pre" value="([^"]+)"`)
)

func find(re *regexp.Regexp, s string) string {
	if m := re.FindStringSubmatch(s); m != nil {
		return m[1]
	}
	return ""
}

// submit loads page, then posts kv to action with the page's CSRF token and
// revision, as a browser would.
func (b *browser) submit(page, action string, kv ...string) response {
	b.t.Helper()
	if r := b.get(page); r.code != http.StatusOK {
		b.t.Fatalf("GET %s: %d", page, r.code)
	}
	form := url.Values{"csrf": {find(csrfRE, b.page)}, "rev": {find(revRE, b.page)}}
	for i := 0; i+1 < len(kv); i += 2 {
		form.Add(kv[i], kv[i+1])
	}
	return b.do(http.MethodPost, action, form)
}

func (b *browser) mustSubmit(page, action string, kv ...string) {
	b.t.Helper()
	if r := b.submit(page, action, kv...); r.code != http.StatusSeeOther {
		b.t.Fatalf("POST %s: %d\n%s", action, r.code, excerpt(r.body))
	}
}

var errorsRE = regexp.MustCompile(`(?s)<div class="errors".*?</div>`)

func excerpt(body string) string {
	if m := errorsRE.FindString(body); m != "" {
		return m
	}
	if len(body) > 600 {
		return body[:600]
	}
	return body
}

// waitApplied polls the console until the agent reports the current
// revision as applied.
func (b *browser) waitApplied() {
	b.t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	var last string
	for time.Now().Before(deadline) {
		r := b.get("/api/status")
		var s struct {
			State            string
			Desired, Applied int64
		}
		if err := json.Unmarshal([]byte(r.body), &s); err == nil {
			last = fmt.Sprintf("%s %d/%d", s.State, s.Applied, s.Desired)
			if s.State == "applied" && s.Applied == s.Desired {
				return
			}
		}
		time.Sleep(300 * time.Millisecond)
	}
	b.t.Fatalf("agent did not apply in time (last status: %s)", last)
}

// --- SMB ---------------------------------------------------------------------

// smb runs smbclient commands on a share. The password goes through the
// environment, never the command line.
func smb(user, password, share string, commands string) (string, error) {
	cmd := exec.Command("smbclient", "//"+smbHost+"/"+share, "-U", user, "-c", commands)
	cmd.Env = append(os.Environ(), "PASSWD="+password)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func listShares(user, password string) (string, error) {
	cmd := exec.Command("smbclient", "-L", "//"+smbHost, "-U", user)
	cmd.Env = append(os.Environ(), "PASSWD="+password)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// session is an open, interactive smbclient session.
type session struct {
	cmd   *exec.Cmd
	stdin io.WriteCloser
	out   *bytes.Buffer
}

// openSession connects, lists the share once, and keeps the session open.
func openSession(t *testing.T, user, password, share string) *session {
	t.Helper()
	cmd := exec.Command("smbclient", "//"+smbHost+"/"+share, "-U", user)
	cmd.Env = append(os.Environ(), "PASSWD="+password)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	out := &bytes.Buffer{}
	cmd.Stdout, cmd.Stderr = out, out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	_, _ = io.WriteString(stdin, "ls\n")
	time.Sleep(2 * time.Second) // the session is open and has listed the share
	return &session{cmd: cmd, stdin: stdin, out: out}
}

// mustBeCut lists the share again on the open session and expects the
// server to have closed it meanwhile.
func (s *session) mustBeCut(t *testing.T) {
	t.Helper()
	_, _ = io.WriteString(s.stdin, "ls\nquit\n")
	_ = s.stdin.Close()
	done := make(chan error, 1)
	go func() { done <- s.cmd.Wait() }()
	select {
	case werr := <-done:
		_ = werr // smbclient exits with an error once disconnected: expected
	case <-time.After(20 * time.Second):
		_ = s.cmd.Process.Kill()
		t.Fatalf("smbclient still running:\n%s", s.out.String())
	}
	got := s.out.String()
	if strings.Count(got, "blocks of size") != 1 || !strings.Contains(got, "NT_STATUS_CONNECTION_DISCONNECTED") {
		t.Fatalf("the open session was not closed:\n%s", got)
	}
}

func mustSMB(t *testing.T, user, password, share, commands string) string {
	t.Helper()
	out, err := smb(user, password, share, commands)
	if err != nil || strings.Contains(out, "NT_STATUS_") {
		t.Fatalf("smbclient %s@%s %q: %v\n%s", user, share, commands, err, out)
	}
	return out
}

func mustFailSMB(t *testing.T, user, password, share, commands, status string) {
	t.Helper()
	out, _ := smb(user, password, share, commands)
	if !strings.Contains(out, status) {
		t.Fatalf("smbclient %s@%s %q: want %s, got:\n%s", user, share, commands, status, out)
	}
}

// --- the scenario ------------------------------------------------------------

func TestEndToEnd(t *testing.T) {
	if setupCode == "" {
		t.Fatal("SMBDECK_IT_SETUP_CODE is not set: run test/integration/run.sh")
	}
	admin := newBrowser(t)
	payload := filepath.Join(t.TempDir(), "hello.txt")
	if err := os.WriteFile(payload, []byte("written over SMB\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	t.Run("first administrator through the setup page", func(t *testing.T) {
		admin.t = t
		admin.get("/setup")
		r := admin.do(http.MethodPost, "/setup", url.Values{"pre": {find(preRE, admin.page)}, "code": {setupCode},
			"name": {"admin"}, "password": {adminPassword}, "confirm": {adminPassword}})
		if r.code != http.StatusSeeOther || r.loc != "/" {
			t.Fatalf("setup: %d %s\n%s", r.code, r.loc, excerpt(r.body))
		}
		if r := newBrowser(t).get("/setup"); r.loc != "/login" {
			t.Fatal("setup page still open")
		}
	})

	t.Run("writes without a CSRF token are refused", func(t *testing.T) {
		admin.t = t
		r := admin.do(http.MethodPost, "/users", url.Values{"name": {"mallory"}, "password": {"a long enough password"}})
		if r.code != http.StatusForbidden {
			t.Fatalf("no token: %d", r.code)
		}
	})

	t.Run("accounts and shares created through the console", func(t *testing.T) {
		admin.t = t
		admin.mustSubmit("/users", "/users", "name", "alice", "password", alicePassword)
		admin.mustSubmit("/shares/new", "/shares", "name", "Data", "root", "drive1", "path", "data", "access_alice", "rw")
		admin.mustSubmit("/shares/new", "/shares", "name", "ReadOnly", "root", "drive1", "path", "readonly", "access_alice", "ro")
		admin.mustSubmit("/shares/new", "/shares", "name", "Fresh", "root", "drive1", "path", "new/sub", "create_folder", "on", "access_alice", "rw")
		admin.mustSubmit("/shares/new", "/shares", "name", "Hidden", "root", "drive1", "path", "media", "access_admin", "ro")
		admin.waitApplied()
	})

	t.Run("an account reads and writes where it may", func(t *testing.T) {
		out := mustSMB(t, "alice", alicePassword, "Data", "put "+payload+" hello.txt; ls")
		if !strings.Contains(out, "hello.txt") {
			t.Fatalf("file not listed:\n%s", out)
		}
		// Files belong to the file owner, whatever the account.
		fi, err := os.Stat(filepath.Join(rootView, "data", "hello.txt"))
		if err != nil {
			t.Fatal(err)
		}
		st := fi.Sys().(*syscall.Stat_t)
		if st.Uid != 1000 || st.Gid != 1000 || fi.Mode().Perm() != 0o664 {
			t.Fatalf("file %d:%d %v, want 1000:1000 -rw-rw-r--", st.Uid, st.Gid, fi.Mode().Perm())
		}
		got := filepath.Join(t.TempDir(), "got.txt")
		mustSMB(t, "alice", alicePassword, "ReadOnly", "get file.txt "+got)
		if data, _ := os.ReadFile(got); string(data) != "hello\n" {
			t.Fatalf("read %q", data)
		}
	})

	t.Run("writing to a read-only share is refused", func(t *testing.T) {
		mustFailSMB(t, "alice", alicePassword, "ReadOnly", "put "+payload+" nope.txt", "NT_STATUS_ACCESS_DENIED")
		if _, err := os.Stat(filepath.Join(rootView, "readonly", "nope.txt")); err == nil {
			t.Fatal("the file was written anyway")
		}
	})

	t.Run("a wrong password is refused", func(t *testing.T) {
		mustFailSMB(t, "alice", "not the password", "Data", "ls", "NT_STATUS_LOGON_FAILURE")
		mustFailSMB(t, "nobody", "whatever", "Data", "ls", "NT_STATUS_LOGON_FAILURE")
	})

	t.Run("each account only sees its shares", func(t *testing.T) {
		out, err := listShares("alice", alicePassword)
		if err != nil {
			t.Fatalf("%v\n%s", err, out)
		}
		for _, s := range []string{"Data", "ReadOnly", "Fresh"} {
			if !strings.Contains(out, s) {
				t.Errorf("alice does not see %s:\n%s", s, out)
			}
		}
		if strings.Contains(out, "Hidden") {
			t.Errorf("alice sees Hidden:\n%s", out)
		}
		mustFailSMB(t, "alice", alicePassword, "Hidden", "ls", "NT_STATUS_ACCESS_DENIED")
	})

	t.Run("the agent created the missing folder inside the root", func(t *testing.T) {
		fi, err := os.Stat(filepath.Join(rootView, "new", "sub"))
		if err != nil || !fi.IsDir() {
			t.Fatalf("folder: %v", err)
		}
		st := fi.Sys().(*syscall.Stat_t)
		if st.Uid != 1000 || st.Gid != 1000 || fi.Mode()&os.ModeSetgid == 0 {
			t.Fatalf("folder %d:%d %v", st.Uid, st.Gid, fi.Mode())
		}
		mustSMB(t, "alice", alicePassword, "Fresh", "put "+payload+" in-fresh.txt")
	})

	t.Run("disabling an account closes its open sessions", func(t *testing.T) {
		admin.t = t
		sess := openSession(t, "alice", alicePassword, "Data")
		admin.mustSubmit("/users", "/users/alice/disable")
		admin.waitApplied()
		sess.mustBeCut(t)
		mustFailSMB(t, "alice", alicePassword, "Data", "ls", "NT_STATUS_ACCOUNT_DISABLED")
	})

	t.Run("a new password replaces the old one at once", func(t *testing.T) {
		admin.t = t
		admin.mustSubmit("/users", "/users/alice/enable")
		admin.mustSubmit("/users", "/users/alice/password", "password", alicePassword2)
		admin.waitApplied()
		mustFailSMB(t, "alice", alicePassword, "Data", "ls", "NT_STATUS_LOGON_FAILURE")
		mustSMB(t, "alice", alicePassword2, "Data", "ls")
	})

	t.Run("a password change requested over SMB is refused", func(t *testing.T) {
		// The passdb is rebuilt from the desired state: a change made by an
		// SMB client would be accepted, then silently undone.
		cmd := exec.Command("smbpasswd", "-r", smbHost, "-U", "alice", "-s")
		cmd.Stdin = strings.NewReader(alicePassword2 + "\nan-other-new-password\nan-other-new-password\n")
		out, err := cmd.CombinedOutput()
		if err == nil {
			t.Fatalf("password changed over SMB:\n%s", out)
		}
		mustSMB(t, "alice", alicePassword2, "Data", "ls")
		mustFailSMB(t, "alice", "an-other-new-password", "Data", "ls", "NT_STATUS_LOGON_FAILURE")
	})

	t.Run("deleting an account closes its open sessions and refuses it", func(t *testing.T) {
		admin.t = t
		// Once the account is gone from /etc/passwd, smbstatus names its
		// sessions by UID: they must still be found and closed.
		sess := openSession(t, "alice", alicePassword2, "Data")
		admin.mustSubmit("/users", "/users/alice/delete")
		admin.waitApplied()
		sess.mustBeCut(t)
		mustFailSMB(t, "alice", alicePassword2, "Data", "ls", "NT_STATUS_LOGON_FAILURE")
	})

	t.Run("an account named like a user or group of the image opens nothing it was not granted", func(t *testing.T) {
		admin.t = t
		names := strings.Fields(os.Getenv("SMBDECK_IT_IMAGE_NAMES"))
		const minNames = 20
		if len(names) < minNames {
			t.Fatalf("only %d names read from the image (want at least %d): SMBDECK_IT_IMAGE_NAMES=%q", len(names), minNames, names)
		}
		const password = "a long password for a named account"
		var created, refused []string
		for _, name := range names {
			if r := admin.submit("/users", "/users", "name", name, "password", password); r.code == http.StatusSeeOther {
				created = append(created, name)
			} else {
				refused = append(refused, name)
			}
		}
		t.Logf("image names: %d; refused by the console: %d (%s); created: %d (%s)",
			len(names), len(refused), strings.Join(refused, " "), len(created), strings.Join(created, " "))
		// One share open to every account created above, to prove each of
		// them works; "Hidden" (administrator only, made earlier) must stay
		// closed to all of them.
		kv := []string{"name", "Named", "root", "drive1", "path", "data", "access_admin", "ro"}
		for _, name := range created {
			kv = append(kv, "access_"+name, "ro")
		}
		admin.mustSubmit("/shares/new", "/shares", kv...)
		// And, for each of them, a share granted to that name alone: the
		// name is also a group of the image, and nobody else may enter.
		for _, name := range created {
			admin.mustSubmit("/shares/new", "/shares", "name", "Only-"+name, "root", "drive1", "path", "data", "access_"+name, "ro")
		}
		admin.waitApplied()
		for _, name := range created {
			mustSMB(t, name, password, "Only-"+name, "ls")
			mustFailSMB(t, "admin", adminPassword, "Only-"+name, "ls", "NT_STATUS_ACCESS_DENIED")
			for _, other := range created {
				if other != name {
					mustFailSMB(t, other, password, "Only-"+name, "ls", "NT_STATUS_ACCESS_DENIED")
				}
			}
		}
		for _, name := range created {
			mustSMB(t, name, password, "Named", "ls")
			mustFailSMB(t, name, password, "Hidden", "ls", "NT_STATUS_ACCESS_DENIED")
			out, err := listShares(name, password)
			if err != nil {
				t.Fatalf("list as %s: %v\n%s", name, err, out)
			}
			if strings.Contains(out, "Hidden") {
				t.Errorf("%s sees Hidden:\n%s", name, out)
			}
		}
	})

	t.Run("the agent refuses paths outside the root, even written by hand", func(t *testing.T) {
		admin.t = t
		path := filepath.Join(stateDir, state.DesiredFile)
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		d, err := state.Decode(data)
		if err != nil {
			t.Fatal(err)
		}
		d.Revision++
		all := map[string]state.Access{"admin": state.ReadWrite}
		d.Shares = append(d.Shares,
			state.Share{Name: "Escape", Root: "drive1", Path: "escape", Access: all},
			state.Share{Name: "Traversal", Root: "drive1", Path: "../../etc", Access: all},
			state.Share{Name: "x]\n[global]\nwide links = yes\n[y", Root: "drive1", Path: "data", Access: all},
			state.Share{Name: "Percent", Root: "drive1", Path: "data/%U", Access: all},
			// A link that stays inside the root is refused too: it could be
			// swapped by whoever writes there.
			state.Share{Name: "Inner", Root: "drive1", Path: "inner-link", Access: all},
		)
		out, err := json.Marshal(d)
		if err != nil {
			t.Fatal(err)
		}
		// Rewritten in place: owner and mode stay those the console set.
		if err := os.WriteFile(path, out, 0o600); err != nil {
			t.Fatal(err)
		}
		var st *state.Status
		deadline := time.Now().Add(30 * time.Second)
		for time.Now().Before(deadline) {
			if st, err = state.ReadStatus(statusDir); err == nil && st.ObservedRevision == d.Revision && st.AppliedRevision == d.Revision {
				break
			}
			time.Sleep(300 * time.Millisecond)
		}
		if st == nil || st.AppliedRevision != d.Revision {
			t.Fatalf("agent did not apply revision %d: %+v", d.Revision, st)
		}
		want := map[string]bool{
			"Escape:share.path.outside_root": false, "Traversal:share.path.invalid": false,
			":share.name.invalid": false, "Percent:share.path.invalid": false,
			"Inner:share.path.symlink": false,
		}
		for _, is := range st.Issues {
			key := is.Name + ":" + is.Code
			if _, ok := want[key]; ok {
				want[key] = true
			}
			if strings.ContainsAny(is.Name, "\n[]") {
				t.Errorf("status echoes an unsafe name: %q", is.Name)
			}
		}
		for k, seen := range want {
			if !seen {
				t.Errorf("issue %s not reported: %+v", k, st.Issues)
			}
		}
		list, _ := listShares("admin", adminPassword)
		for _, s := range []string{"Escape", "Traversal", "Percent", "Inner", "global"} {
			if strings.Contains(list, s) {
				t.Errorf("%s is published:\n%s", s, list)
			}
		}
		mustFailSMB(t, "admin", adminPassword, "Escape", "ls", "NT_STATUS_BAD_NETWORK_NAME")
		// The valid parts of the same revision are applied.
		mustSMB(t, "admin", adminPassword, "Hidden", "ls")
		// And the console shows why.
		if r := admin.get("/"); !strings.Contains(r.body, "leads outside its root") {
			t.Error("the console does not show the refused share")
		}
	})
}
