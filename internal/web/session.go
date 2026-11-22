package web

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"sync"
	"time"
)

// Cookie names. Over HTTPS the __Host- prefix pins the cookie to this exact
// origin (Secure, Path=/, no Domain).
const (
	cookieSession       = "smbdeck_session"
	cookiePreAuth       = "smbdeck_pre"
	cookieLang          = "smbdeck_lang"
	securePrefix        = "__Host-"
	maxSessionsPerUser  = 20
	maxSessionsTotal    = 5000
	flashPasswordMaxAge = 10 * time.Minute
)

// randomToken returns n random bytes, URL-safe base64 encoded.
func randomToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// randomBytes returns n bytes from the system's secure generator.
func randomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	return b
}

// randomString draws n characters uniformly from alphabet (rejection
// sampling: no modulo bias). alphabet must be shorter than 256 bytes.
func randomString(alphabet string, n int) string {
	limit := 256 - 256%len(alphabet)
	out := make([]byte, 0, n)
	for len(out) < n {
		for _, c := range randomBytes(n) {
			if int(c) < limit && len(out) < n {
				out = append(out, alphabet[int(c)%len(alphabet)])
			}
		}
	}
	return string(out)
}

func tokenID(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func equalTokens(a, b string) bool {
	return a != "" && len(a) == len(b) && subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// session is a signed-in browser. Sessions live in memory only: a restart
// signs everyone out, which is the safe direction.
type session struct {
	id      string // SHA-256 of the cookie token: the token itself is not kept
	user    string
	csrf    string
	created time.Time
	seen    time.Time
	// passwordAt is the account's passwordChangedAt at sign-in. When the
	// password changes elsewhere, the session no longer matches and ends.
	passwordAt time.Time

	mu     sync.Mutex
	flash  []flash
	reveal *revealed
}

// flash is a one-time message shown on the next page.
type flash struct {
	Kind string // "ok" or "error"
	Key  string // catalog key
	Arg  string // value for the {name} placeholder
}

// revealed is a generated password, shown once on the next page, then
// forgotten.
type revealed struct {
	User     string
	Password string
	At       time.Time
}

func (s *session) addFlash(f flash) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.flash) < 5 {
		s.flash = append(s.flash, f)
	}
}

func (s *session) takeFlash() []flash {
	s.mu.Lock()
	defer s.mu.Unlock()
	f := s.flash
	s.flash = nil
	return f
}

func (s *session) setReveal(r *revealed) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reveal = r
}

func (s *session) takeReveal(now time.Time) *revealed {
	s.mu.Lock()
	defer s.mu.Unlock()
	r := s.reveal
	s.reveal = nil
	if r == nil || now.Sub(r.At) > flashPasswordMaxAge {
		return nil
	}
	return r
}

type sessionStore struct {
	lifetime, idle time.Duration

	mu sync.Mutex
	m  map[string]*session
}

func newSessionStore(lifetime, idle time.Duration) *sessionStore {
	return &sessionStore{lifetime: lifetime, idle: idle, m: map[string]*session{}}
}

// create opens a session for user and returns its cookie token.
func (st *sessionStore) create(user string, passwordAt, now time.Time) (string, *session) {
	token := randomToken(32)
	s := &session{id: tokenID(token), user: user, csrf: randomToken(32), created: now, seen: now, passwordAt: passwordAt}
	st.mu.Lock()
	defer st.mu.Unlock()
	st.expire(now)
	// Bound the sessions of one account, then the total: the oldest go first.
	var mine []*session
	for _, o := range st.m {
		if o.user == user {
			mine = append(mine, o)
		}
	}
	for len(mine) >= maxSessionsPerUser {
		oldest := 0
		for i := range mine {
			if mine[i].seen.Before(mine[oldest].seen) {
				oldest = i
			}
		}
		delete(st.m, mine[oldest].id)
		mine = append(mine[:oldest], mine[oldest+1:]...)
	}
	for len(st.m) >= maxSessionsTotal {
		var oldest *session
		for _, o := range st.m {
			if oldest == nil || o.seen.Before(oldest.seen) {
				oldest = o
			}
		}
		delete(st.m, oldest.id)
	}
	st.m[s.id] = s
	return token, s
}

// get returns the live session for token, or nil. With touch, the request
// counts as activity for the idle timeout.
func (st *sessionStore) get(token string, now time.Time, touch bool) *session {
	if token == "" {
		return nil
	}
	id := tokenID(token)
	st.mu.Lock()
	defer st.mu.Unlock()
	s := st.m[id]
	if s == nil {
		return nil
	}
	if now.Sub(s.created) > st.lifetime || now.Sub(s.seen) > st.idle {
		delete(st.m, id)
		return nil
	}
	if touch {
		s.seen = now
	}
	return s
}

func (st *sessionStore) delete(s *session) {
	st.mu.Lock()
	defer st.mu.Unlock()
	delete(st.m, s.id)
}

// deleteUser ends every session of user except keep (may be nil).
func (st *sessionStore) deleteUser(user string, keep *session) {
	st.mu.Lock()
	defer st.mu.Unlock()
	for id, s := range st.m {
		if s.user == user && s != keep {
			delete(st.m, id)
		}
	}
}

func (st *sessionStore) expire(now time.Time) {
	for id, s := range st.m {
		if now.Sub(s.created) > st.lifetime || now.Sub(s.seen) > st.idle {
			delete(st.m, id)
		}
	}
}

// cookieName returns the name of a cookie for this request.
func cookieName(base string, secure bool) string {
	if secure {
		return securePrefix + base
	}
	return base
}

func setCookie(w http.ResponseWriter, base, value string, secure bool, maxAge time.Duration) {
	// Secure whenever the request came over HTTPS (SMBDECK_COOKIE_SECURE):
	// a Secure cookie would never come back over plain HTTP.
	c := &http.Cookie{ //nolint:gosec // G124: see above
		Name: cookieName(base, secure), Value: value, Path: "/",
		HttpOnly: true, Secure: secure, SameSite: http.SameSiteStrictMode,
	}
	if maxAge > 0 {
		c.MaxAge = int(maxAge.Seconds())
	} else if maxAge < 0 {
		c.MaxAge = -1
	}
	http.SetCookie(w, c)
}

func readCookie(r *http.Request, base string, secure bool) string {
	c, err := r.Cookie(cookieName(base, secure))
	if err != nil {
		return ""
	}
	return c.Value
}
