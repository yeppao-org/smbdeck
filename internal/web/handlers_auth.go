package web

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/yeppao-org/smbdeck/internal/audit"
	"github.com/yeppao-org/smbdeck/internal/i18n"
	"github.com/yeppao-org/smbdeck/internal/nthash"
	"github.com/yeppao-org/smbdeck/internal/state"
	"github.com/yeppao-org/smbdeck/internal/validate"
)

// authForm is the data of the login and setup pages.
type authForm struct {
	Pre       string
	Name      string
	SetupCode bool
	MinLength int
}

// preAuth issues the token that login and setup forms must send back: the
// same random value in a cookie and in a hidden field.
func (s *Server) preAuth(w http.ResponseWriter, r *http.Request) string {
	rc := reqCtxFrom(r)
	tok := randomToken(24)
	setCookie(w, cookiePreAuth, tok, s.secure(rc.client), time.Hour)
	return tok
}

func (s *Server) checkPreAuth(r *http.Request) bool {
	rc := reqCtxFrom(r)
	return equalTokens(r.PostFormValue("pre"), readCookie(r, cookiePreAuth, s.secure(rc.client)))
}

func (s *Server) initialized() bool {
	_, err := s.store.Load()
	return !errors.Is(err, state.ErrNotInitialized)
}

func (s *Server) handleLoginPage(w http.ResponseWriter, r *http.Request) {
	if !s.initialized() {
		http.Redirect(w, r, "/setup", http.StatusSeeOther)
		return
	}
	if rc := reqCtxFrom(r); rc.sess != nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	s.render(w, r, http.StatusOK, "login", &page{Title: "login.title", Data: authForm{Pre: s.preAuth(w, r)}})
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	rc := reqCtxFrom(r)
	name := strings.ToLower(strings.TrimSpace(r.PostFormValue("name")))
	password := r.PostFormValue("password")
	again := func(status int, key string, args ...string) {
		p := &page{Title: "login.title", Data: authForm{Pre: s.preAuth(w, r), Name: name}}
		p.Errors = []string{key}
		if len(args) > 0 {
			p.Flash = []flash{{Kind: "error", Key: key, Arg: args[0]}}
			p.Errors = nil
		}
		s.render(w, r, status, "login", p)
	}
	if !s.checkPreAuth(r) {
		again(http.StatusForbidden, "error.csrf")
		return
	}
	if len(name) > 64 {
		name = name[:64]
	}
	now := s.now()
	ipk := ipKey(rc.client.ip)
	accountKey := "account:" + name
	accountIPKey := accountKey + "|" + ipk

	// A browser that signed in to this account before is judged on its own
	// record; any other attempt on the address's and the (account, address)
	// pair's. The account as a whole is only slowed down, never locked: a
	// hard lock there would let anyone lock the administrator out.
	deviceID, known := s.device.verify(readCookie(r, cookieDevice, s.secure(rc.client)), name, now)
	type lock struct {
		lim *limiter
		key string
	}
	var locks []lock
	if known {
		locks = []lock{{s.deviceLimit, "device:" + deviceID}}
	} else {
		locks = []lock{{s.ipLimit, ipk}, {s.accountIPLimit, accountIPKey}}
	}
	for _, l := range locks {
		if ok, wait, first := l.lim.allow(l.key, now); !ok {
			secs := strconv.Itoa(int(wait.Round(time.Second).Seconds()) + 1)
			w.Header().Set("Retry-After", secs)
			if first {
				s.remember(r, "-", audit.LoginBlocked, "", audit.Denied)
			}
			again(http.StatusTooManyRequests, "auth.too_many", secs)
			return
		}
	}
	if !known {
		if d := s.slowdown(s.accountLimit.failures(accountKey, now)); d > 0 {
			time.Sleep(min(d, 2*time.Second))
		}
	}

	d, err := s.store.Load()
	if errors.Is(err, state.ErrNotInitialized) {
		http.Redirect(w, r, "/setup", http.StatusSeeOther)
		return
	}
	if err != nil {
		s.stateError(w, r, err)
		return
	}
	u := d.User(name)
	stored := s.dummyHash
	if u != nil {
		stored = u.NTHash
	}
	// The hash is always computed and compared, whether the account exists or
	// not, so that timing does not tell.
	match := nthash.Verify(password, stored)
	if !match || u == nil || u.Disabled {
		if known {
			s.deviceLimit.fail("device:"+deviceID, now)
		} else {
			s.ipLimit.fail(ipk, now)
			s.accountIPLimit.fail(accountIPKey, now)
			s.accountLimit.fail(accountKey, now)
		}
		actor := "-"
		if u != nil {
			actor = u.Name
		}
		s.remember(r, actor, audit.LoginFailed, "", audit.Denied)
		again(http.StatusUnauthorized, "auth.invalid")
		return
	}
	s.accountIPLimit.reset(accountIPKey)
	s.accountLimit.reset(accountKey)
	if known {
		s.deviceLimit.reset("device:" + deviceID)
	}
	s.startSession(w, r, u)
	setCookie(w, cookieDevice, s.device.issue(u.Name, now), s.secure(rc.client), deviceLifetime)
	s.remember(r, u.Name, audit.LoginOK, "", audit.OK)
	if u.Admin {
		http.Redirect(w, r, "/", http.StatusSeeOther)
	} else {
		http.Redirect(w, r, "/account", http.StatusSeeOther)
	}
}

// startSession signs u in on this browser, replacing any previous session
// cookie (no session fixation: the token is always new).
func (s *Server) startSession(w http.ResponseWriter, r *http.Request, u *state.User) *session {
	rc := reqCtxFrom(r)
	if rc.sess != nil {
		s.sessions.delete(rc.sess)
	}
	token, sess := s.sessions.create(u.Name, u.PasswordChangedAt, s.now())
	secure := s.secure(rc.client)
	setCookie(w, cookieSession, token, secure, s.cfg.SessionLifetime)
	setCookie(w, cookiePreAuth, "", secure, -1)
	rc.sess = sess
	return sess
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	rc := reqCtxFrom(r)
	s.sessions.delete(rc.sess)
	setCookie(w, cookieSession, "", s.secure(rc.client), -1)
	s.remember(r, rc.user.Name, audit.Logout, "", audit.OK)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (s *Server) handleSetupPage(w http.ResponseWriter, r *http.Request) {
	if s.initialized() {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	s.render(w, r, http.StatusOK, "setup", &page{Title: "setup.title",
		Data: authForm{Pre: s.preAuth(w, r), SetupCode: true, MinLength: s.cfg.PasswordMinLength}})
}

// handleSetup creates the first administrator. It works once: as soon as a
// desired state exists, the page redirects to the login.
func (s *Server) handleSetup(w http.ResponseWriter, r *http.Request) {
	rc := reqCtxFrom(r)
	s.setupMu.Lock()
	defer s.setupMu.Unlock()
	if s.initialized() {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	name := strings.ToLower(strings.TrimSpace(r.PostFormValue("name")))
	again := func(status int, codes ...string) {
		s.render(w, r, status, "setup", &page{Title: "setup.title", Errors: codes,
			Data: authForm{Pre: s.preAuth(w, r), Name: name, SetupCode: true, MinLength: s.cfg.PasswordMinLength}})
	}
	if !s.checkPreAuth(r) {
		again(http.StatusForbidden, "error.csrf")
		return
	}
	now := s.now()
	ipk := ipKey(rc.client.ip)
	if ok, _, first := s.ipLimit.allow(ipk, now); !ok {
		if first {
			s.remember(r, "-", audit.LoginBlocked, "", audit.Denied)
		}
		again(http.StatusTooManyRequests, "auth.too_many_short")
		return
	}
	code := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(r.PostFormValue("code")), " ", ""))
	if !equalTokens(code, s.setupCode) {
		s.ipLimit.fail(ipk, now)
		s.remember(r, "-", audit.SetupFailed, "", audit.Denied)
		again(http.StatusUnauthorized, "setup.bad_code")
		return
	}
	password := r.PostFormValue("password")
	var codes []string
	if c := validate.UserName(name); c != validate.OK {
		codes = append(codes, "err."+string(c))
	}
	if c := validate.Password(password, s.cfg.PasswordMinLength); c != validate.OK {
		codes = append(codes, "err."+string(c))
	} else if password != r.PostFormValue("confirm") {
		codes = append(codes, "err."+string(validate.PasswordMismatch))
	}
	if len(codes) > 0 {
		again(http.StatusUnprocessableEntity, codes...)
		return
	}
	u := state.User{Name: name, UID: state.FirstUID, NTHash: nthash.Sum(password).String(), Admin: true,
		CreatedAt: now.UTC(), PasswordChangedAt: now.UTC()}
	d, err := s.store.Create(&state.Desired{Users: []state.User{u}, Shares: []state.Share{}})
	if errors.Is(err, state.ErrExists) {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if err != nil {
		s.log.Error("setup", "err", err)
		s.fail(w, r, http.StatusInternalServerError, "error.state")
		return
	}
	s.setupCode = ""
	s.ipLimit.reset(ipk)
	s.startSession(w, r, d.User(name))
	s.remember(r, name, audit.SetupAdmin, name, audit.OK)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// handleLang stores the language choice and goes back to the page.
func (s *Server) handleLang(w http.ResponseWriter, r *http.Request) {
	lang := r.PathValue("lang")
	if !i18n.Supported(lang) {
		http.NotFound(w, r)
		return
	}
	rc := reqCtxFrom(r)
	// Secure whenever the request came over HTTPS (it cannot be on plain
	// HTTP); the value is a language code and nothing else.
	http.SetCookie(w, &http.Cookie{Name: cookieLang, Value: lang, Path: "/", MaxAge: 365 * 24 * 3600, //nolint:gosec // G124: see above
		HttpOnly: true, Secure: s.secure(rc.client), SameSite: http.SameSiteLaxMode})
	http.Redirect(w, r, localPath(r.URL.Query().Get("next")), http.StatusSeeOther) //nolint:gosec // G710: localPath keeps on-site paths only
}

// localPath returns p if it is a path on this site, "/" otherwise: no open
// redirect through "next".
func localPath(p string) string {
	if !strings.HasPrefix(p, "/") || strings.HasPrefix(p, "//") || strings.HasPrefix(p, "/\\") ||
		strings.ContainsAny(p, "\r\n\t\\") {
		return "/"
	}
	return p
}
