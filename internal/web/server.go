// Package web is the console: an unprivileged HTTP server that reads and
// writes the desired state and reads what the agent reports. It never touches
// Samba or the disks; nothing but the state volume is mounted in its
// container.
package web

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/yeppao-org/smbdeck/internal/audit"
	"github.com/yeppao-org/smbdeck/internal/i18n"
	"github.com/yeppao-org/smbdeck/internal/state"
	"github.com/yeppao-org/smbdeck/internal/validate"
)

// maxFormBytes bounds every request body.
const maxFormBytes = 64 << 10

// Server is the web console.
type Server struct {
	cfg      Config
	log      *slog.Logger
	version  string
	store    *state.Store
	audit    *audit.Log
	bundle   *i18n.Bundle
	sessions *sessionStore
	// Sign-in limits: per address (hard), per account and address (hard),
	// per known browser (hard), per account (a slowdown only: a hard lock
	// there would let anyone lock the account out).
	ipLimit        *limiter
	accountIPLimit *limiter
	deviceLimit    *limiter
	accountLimit   *limiter
	slowdown       func(failures int) time.Duration
	device         deviceSigner
	templates      map[string]*template.Template
	assets         *assetSet
	resolver       resolver
	now            func() time.Time
	// setupCode must be typed on the first-admin page. It exists only while
	// there is no desired state, and is printed in the logs. setupMu guards
	// it and serializes setup attempts.
	setupMu   sync.Mutex
	setupCode string
	// dummyHash is compared against when a login names no account, so that
	// the time taken does not reveal which accounts exist.
	dummyHash string
}

// New builds the console. It seeds the desired state if configured and
// needed, and otherwise prepares the first-admin setup.
func New(cfg Config, log *slog.Logger, version string) (*Server, error) {
	bundle, err := i18n.Load()
	if err != nil {
		return nil, err
	}
	as, err := loadAssets()
	if err != nil {
		return nil, err
	}
	tpl, err := parseTemplates(as)
	if err != nil {
		return nil, err
	}
	s := &Server{
		cfg: cfg, log: log, version: version,
		store:          state.NewStore(cfg.StateDir),
		audit:          audit.New(filepath.Join(cfg.StateDir, state.AuditFile), cfg.AuditMaxBytes),
		bundle:         bundle,
		sessions:       newSessionStore(cfg.SessionLifetime, cfg.SessionIdle),
		ipLimit:        newLimiter(10, time.Second, 15*time.Minute),
		accountIPLimit: newLimiter(5, time.Second, 15*time.Minute),
		deviceLimit:    newLimiter(5, time.Second, 15*time.Minute),
		accountLimit:   newLimiter(1<<30, time.Second, time.Second),
		slowdown:       defaultSlowdown,
		templates:      tpl,
		assets:         as,
		resolver:       resolver{trusted: cfg.TrustedProxies},
		now:            time.Now,
		dummyHash:      strings.Repeat("0", 32),
	}
	s.store.Check = s.checkChange
	key, err := loadDeviceKey(cfg.StateDir)
	if err != nil {
		log.Warn("device key not stored; known browsers are forgotten at restart", "err", err)
	}
	s.device = deviceSigner{key: key}
	if _, err := s.store.Load(); errors.Is(err, state.ErrNotInitialized) {
		if cfg.SeedFile != "" {
			if err := s.seed(); err != nil {
				return nil, fmt.Errorf("seed: %w", err)
			}
		} else {
			s.setupCode = newSetupCode()
			log.Warn("no account yet: open /setup in a browser and enter this setup code",
				"setupCode", s.setupCode)
		}
	} else if err != nil {
		// Degraded mode: the console keeps running and explains, rather than
		// exiting in a loop.
		log.Error("desired state unusable; serving an error until it is fixed", "err", err)
	}
	return s, nil
}

// newSetupCode returns 12 random characters in groups of four, from an
// alphabet without look-alikes.
func newSetupCode() string {
	raw := randomString("ABCDEFGHJKMNPQRSTVWXYZ23456789", 12)
	return raw[0:4] + "-" + raw[4:8] + "-" + raw[8:12]
}

// checkChange is the store's validation hook: a change may not introduce a
// problem the state did not already have. Problems written by hand into the
// file stay visible (the agent reports them) but do not block unrelated
// changes through the UI.
func (s *Server) checkChange(cur, next *state.Desired) error {
	roots := s.rootNames()
	after := validate.Check(next, roots)
	if after.Fatal != validate.OK {
		return &formError{codes: []validate.Code{after.Fatal}}
	}
	before := map[string]bool{}
	if cur != nil {
		for _, is := range validate.Check(cur, roots).Issues {
			before[issueKey(is)] = true
		}
	}
	var codes []validate.Code
	for _, is := range after.Issues {
		if !before[issueKey(is)] {
			codes = append(codes, validate.Code(is.Code))
		}
	}
	if len(codes) > 0 {
		return &formError{codes: codes}
	}
	return nil
}

func issueKey(is state.Issue) string {
	return is.Kind + "\x00" + is.Name + "\x00" + is.Field + "\x00" + is.Code
}

// rootNames returns the roots the agent declared, or nil if it has not
// reported yet.
func (s *Server) rootNames() map[string]bool {
	t, err := state.ReadTree(s.cfg.StatusDir)
	if err != nil {
		return nil
	}
	m := map[string]bool{}
	for _, r := range t.Roots {
		m[r.Name] = true
	}
	return m
}

// formError carries validation codes back to a form.
type formError struct {
	codes []validate.Code
}

func (e *formError) Error() string {
	parts := make([]string, len(e.codes))
	for i, c := range e.codes {
		parts[i] = string(c)
	}
	return "validation: " + strings.Join(parts, ", ")
}

// reqCtx is attached to every request.
type reqCtx struct {
	client clientInfo
	l      *i18n.Localizer
	sess   *session
	user   *state.User
	state  *state.Desired
}

type ctxKey struct{}

func reqCtxFrom(r *http.Request) *reqCtx {
	if rc, ok := r.Context().Value(ctxKey{}).(*reqCtx); ok {
		return rc
	}
	return &reqCtx{}
}

// Handler returns the console's HTTP handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /static/", s.assets.serve)
	mux.HandleFunc("GET /lang/{lang}", s.handleLang)
	mux.HandleFunc("GET /login", s.handleLoginPage)
	mux.HandleFunc("POST /login", s.handleLogin)
	mux.HandleFunc("GET /setup", s.handleSetupPage)
	mux.HandleFunc("POST /setup", s.handleSetup)
	mux.Handle("POST /logout", s.user(s.handleLogout))

	mux.Handle("GET /{$}", s.user(s.handleHome))
	mux.Handle("GET /account", s.user(s.handleAccount))
	mux.Handle("POST /account/password", s.user(s.handleAccountPassword))
	mux.Handle("GET /api/status", s.user(s.handleAPIStatus))

	mux.Handle("GET /users", s.admin(s.handleUsers))
	mux.Handle("POST /users", s.admin(s.handleUserCreate))
	mux.Handle("GET /users/{name}/password", s.admin(s.handleUserPasswordPage))
	mux.Handle("POST /users/{name}/password", s.admin(s.handleUserPassword))
	mux.Handle("GET /users/{name}/delete", s.admin(s.handleUserDeletePage))
	mux.Handle("POST /users/{name}/disable", s.admin(s.handleUserFlag("disable")))
	mux.Handle("POST /users/{name}/enable", s.admin(s.handleUserFlag("enable")))
	mux.Handle("POST /users/{name}/grant-admin", s.admin(s.handleUserFlag("grant")))
	mux.Handle("POST /users/{name}/revoke-admin", s.admin(s.handleUserFlag("revoke")))
	mux.Handle("POST /users/{name}/delete", s.admin(s.handleUserDelete))

	mux.Handle("GET /shares", s.admin(s.handleShares))
	mux.Handle("GET /shares/new", s.admin(s.handleShareNew))
	mux.Handle("POST /shares", s.admin(s.handleShareSave))
	mux.Handle("GET /shares/{name}", s.admin(s.handleShareEdit))
	mux.Handle("POST /shares/{name}", s.admin(s.handleShareSave))
	mux.Handle("GET /shares/{name}/delete", s.admin(s.handleShareDeletePage))
	mux.Handle("POST /shares/{name}/delete", s.admin(s.handleShareDelete))

	mux.Handle("GET /audit", s.admin(s.handleAudit))

	// Cross-origin writes are refused before any handler runs (Sec-Fetch-Site
	// and Origin). The CSRF token below is the second, independent check.
	cop := http.NewCrossOriginProtection()
	cop.SetDenyHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.fail(w, r, http.StatusForbidden, "error.forbidden")
	}))

	var h http.Handler = mux
	h = cop.Handler(h)
	h = s.withContext(h)
	h = s.hostGate(h)
	h = s.networkGate(h)
	h = securityHeaders(h)
	h = s.recoverer(h)

	root := http.NewServeMux()
	// The health check answers before the network gate: probes come from the
	// node or the container itself, and the answer reveals nothing.
	root.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write([]byte("ok\n"))
	})
	root.Handle("/", h)
	return root
}

func (s *Server) recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if v := recover(); v != nil {
				if err, ok := v.(error); ok && errors.Is(err, http.ErrAbortHandler) {
					panic(v)
				}
				s.log.Error("panic", "path", r.URL.Path, "panic", fmt.Sprint(v))
				http.Error(w, "internal error", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// networkGate refuses clients outside the allowed networks.
func (s *Server) networkGate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ci := s.resolver.resolve(r)
		if !ci.ip.IsValid() || !contains(s.cfg.AllowedNetworks, ci.ip) {
			s.log.Warn("request from outside the allowed networks", "ip", ci.ip.String(), "path", r.URL.Path)
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte("403 forbidden\n"))
			return
		}
		next.ServeHTTP(w, r)
	})
}

// hostGate answers 421 to a Host header that does not name this console
// (DNS rebinding: a page on the attacker's name, resolving to this address).
func (s *Server) hostGate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !hostAllowed(r.Host, s.cfg.AllowedHosts) {
			s.log.Warn("request for an unknown host name", "host", r.Host)
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusMisdirectedRequest)
			_, _ = w.Write([]byte("421 unknown host name: add it to SMBDECK_ALLOWED_HOSTS\n"))
			return
		}
		next.ServeHTTP(w, r)
	})
}

// withContext resolves the client, the language and the session, and reads
// the form of a write.
func (s *Server) withContext(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
		}
		ci := s.resolver.resolve(r)
		if ci.secure {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		}
		rc := &reqCtx{client: ci}
		rc.l = s.bundle.For(i18n.Match(readCookie(r, cookieLang, false), r.Header.Get("Accept-Language")))
		if tok := readCookie(r, cookieSession, s.secure(ci)); tok != "" {
			// The status polling of an open page is not activity: it must
			// not keep an idle session alive.
			rc.sess = s.sessions.get(tok, s.now(), r.URL.Path != "/api/status")
		}
		r = r.WithContext(context.WithValue(r.Context(), ctxKey{}, rc))
		if r.Method == http.MethodPost {
			if err := r.ParseForm(); err != nil {
				var tooLarge *http.MaxBytesError
				if errors.As(err, &tooLarge) {
					s.fail(w, r, http.StatusRequestEntityTooLarge, "error.too_large")
				} else {
					s.fail(w, r, http.StatusBadRequest, "error.bad_request")
				}
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) secure(ci clientInfo) bool {
	switch s.cfg.CookieSecure {
	case "always":
		return true
	case "never":
		return false
	}
	return ci.secure
}

// user wraps a handler that needs a signed-in, enabled account.
func (s *Server) user(h http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rc := reqCtxFrom(r)
		if !s.authenticate(w, r, rc) {
			return
		}
		h(w, r)
	})
}

// admin wraps a handler that needs an administrator.
func (s *Server) admin(h http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rc := reqCtxFrom(r)
		if !s.authenticate(w, r, rc) {
			return
		}
		if !rc.user.Admin {
			s.fail(w, r, http.StatusForbidden, "error.forbidden")
			return
		}
		h(w, r)
	})
}

// authenticate checks the session against the current state: the account
// must still exist, be enabled, and have the password it had at sign-in.
// Writes must also carry the session's CSRF token.
func (s *Server) authenticate(w http.ResponseWriter, r *http.Request, rc *reqCtx) bool {
	d, err := s.store.Load()
	if errors.Is(err, state.ErrNotInitialized) {
		http.Redirect(w, r, "/setup", http.StatusSeeOther)
		return false
	}
	if err != nil {
		s.stateError(w, r, err)
		return false
	}
	if rc.sess != nil {
		u := d.User(rc.sess.user)
		if u == nil || u.Disabled || !u.PasswordChangedAt.Equal(rc.sess.passwordAt) {
			s.sessions.delete(rc.sess)
			rc.sess = nil
		} else {
			rc.user, rc.state = u, d
		}
	}
	if rc.sess == nil {
		if r.Method == http.MethodGet && !strings.HasPrefix(r.URL.Path, "/api/") {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
		} else {
			s.fail(w, r, http.StatusUnauthorized, "error.signed_out")
		}
		return false
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		token := r.Header.Get("X-CSRF-Token")
		if token == "" {
			token = r.PostFormValue("csrf")
		}
		if !equalTokens(token, rc.sess.csrf) {
			s.fail(w, r, http.StatusForbidden, "error.csrf")
			return false
		}
	}
	return true
}

// stateError explains why the desired state cannot be used.
func (s *Server) stateError(w http.ResponseWriter, r *http.Request, err error) {
	s.log.Error("load desired state", "err", err)
	key := "error.state"
	switch {
	case errors.Is(err, state.ErrMissing):
		key = "error.state_missing"
	case errors.Is(err, state.ErrSchema):
		key = "error.state_schema"
	}
	s.fail(w, r, http.StatusServiceUnavailable, key)
}

// fail renders an error page (or a JSON error for the API).
func (s *Server) fail(w http.ResponseWriter, r *http.Request, status int, key string) {
	if strings.HasPrefix(r.URL.Path, "/api/") {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(status)
		_, _ = fmt.Fprintf(w, "{\"error\":%q}\n", strings.TrimPrefix(key, "error."))
		return
	}
	s.render(w, r, status, "error", &page{Title: "error.title", Errors: []string{key}})
}

// remember records an action in the journal.
func (s *Server) remember(r *http.Request, actor, action, target, result string) {
	rc := reqCtxFrom(r)
	ip := ""
	if rc.client.ip.IsValid() {
		ip = rc.client.ip.String()
	}
	if err := s.audit.Append(audit.Entry{Time: s.now(), Actor: actor, IP: ip, Action: action, Target: target, Result: result}); err != nil {
		s.log.Error("audit", "err", err)
	}
	s.log.Info("audit", "actor", actor, "action", action, "target", target, "result", result, "ip", ip)
}

// ListenAndServe serves until ctx ends.
func (s *Server) ListenAndServe(ctx context.Context) error {
	srv := &http.Server{
		Addr:              s.cfg.Listen,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    32 << 10,
		ErrorLog:          slog.NewLogLogger(s.log.Handler(), slog.LevelWarn),
		BaseContext:       func(net.Listener) context.Context { return ctx },
	}
	if s.cfg.TLSCert != "" {
		srv.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	errc := make(chan error, 1)
	go func() {
		s.log.Info("web console listening", "addr", s.cfg.Listen, "tls", s.cfg.TLSCert != "",
			"allowedNetworks", prefixesString(s.cfg.AllowedNetworks), "trustedProxies", prefixesString(s.cfg.TrustedProxies))
		if s.cfg.TLSCert != "" {
			errc <- srv.ListenAndServeTLS(s.cfg.TLSCert, s.cfg.TLSKey)
		} else {
			errc <- srv.ListenAndServe()
		}
	}()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return srv.Shutdown(shutdown)
	}
}

func prefixesString(ps []netip.Prefix) string {
	parts := make([]string, len(ps))
	for i, p := range ps {
		parts[i] = p.String()
	}
	return strings.Join(parts, ",")
}
