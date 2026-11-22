package web

import (
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// contentSecurityPolicy forbids every inline script and style, framing, and
// any origin but this one. The UI needs nothing else.
const contentSecurityPolicy = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; " +
	"font-src 'self'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'; " +
	"manifest-src 'self'"

// securityHeaders sets the response headers every page carries.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", contentSecurityPolicy)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		// same-origin, not no-referrer: with no-referrer, browsers send
		// "Origin: null" on form posts over plain HTTP (no Sec-Fetch-Site
		// there either), and the cross-origin check would refuse every
		// login. same-origin never lets the referrer leave this site.
		h.Set("Referrer-Policy", "same-origin")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		next.ServeHTTP(w, r)
	})
}

// clientInfo is what the console knows about the client of a request.
type clientInfo struct {
	ip     netip.Addr
	secure bool
}

// resolver finds the client address, believing X-Forwarded-For and
// X-Forwarded-Proto only from configured trusted proxies.
type resolver struct {
	trusted []netip.Prefix
}

func contains(prefixes []netip.Prefix, a netip.Addr) bool {
	for _, p := range prefixes {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

func (rs resolver) resolve(r *http.Request) clientInfo {
	ci := clientInfo{secure: r.TLS != nil}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	peer, err := netip.ParseAddr(host)
	if err != nil {
		return ci
	}
	ci.ip = peer.Unmap()
	if !contains(rs.trusted, ci.ip) {
		return ci
	}
	// The peer is a trusted proxy. Walk X-Forwarded-For from the right: the
	// client is the first address that is not itself a trusted proxy. A hop
	// that cannot be read makes the client unknown (refused): falling back to
	// the proxy's own address would let anyone in.
	var hops []string
	for _, v := range r.Header.Values("X-Forwarded-For") {
		hops = append(hops, strings.Split(v, ",")...)
	}
	for i := len(hops) - 1; i >= 0; i-- {
		a, err := netip.ParseAddr(strings.TrimSpace(hops[i]))
		if err != nil {
			ci.ip = netip.Addr{}
			break
		}
		ci.ip = a.Unmap()
		if !contains(rs.trusted, ci.ip) {
			break
		}
	}
	if strings.EqualFold(strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")), "https") {
		ci.secure = true
	}
	return ci
}

// limiter slows down repeated failures for one key (an address or an account):
// a few attempts are free, then each failure doubles the wait, up to a cap.
// Keys forget their failures after a quiet period.
type limiter struct {
	free   int
	base   time.Duration
	cap    time.Duration
	forget time.Duration
	max    int

	mu      sync.Mutex
	entries map[string]*limitEntry
}

type limitEntry struct {
	failures int
	until    time.Time
	last     time.Time
	// reported is set once the current lockout has been journaled.
	reported bool
}

func newLimiter(free int, base, cap time.Duration) *limiter {
	return &limiter{free: free, base: base, cap: cap, forget: time.Hour, max: 50000, entries: map[string]*limitEntry{}}
}

// allow reports whether key may try now, and otherwise how long to wait.
// first is set the first time a given lockout refuses a request, so that it
// is journaled once rather than at every attempt.
func (l *limiter) allow(key string, now time.Time) (ok bool, wait time.Duration, first bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	e := l.entries[key]
	if e == nil {
		return true, 0, false
	}
	if now.Sub(e.last) > l.forget {
		delete(l.entries, key)
		return true, 0, false
	}
	if now.Before(e.until) {
		first = !e.reported
		e.reported = true
		return false, e.until.Sub(now), first
	}
	return true, 0, false
}

// failures returns the recent failure count of key.
func (l *limiter) failures(key string, now time.Time) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	e := l.entries[key]
	if e == nil || now.Sub(e.last) > l.forget {
		return 0
	}
	return e.failures
}

// fail records a failure for key.
func (l *limiter) fail(key string, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	e := l.entries[key]
	if e == nil {
		if len(l.entries) >= l.max {
			l.sweep(now)
			if len(l.entries) >= l.max {
				return // every slot is a live lockout; the address limiter still applies
			}
		}
		e = &limitEntry{}
		l.entries[key] = e
	}
	if now.Sub(e.last) > l.forget {
		e.failures = 0
	}
	e.failures++
	e.last = now
	if over := e.failures - l.free; over > 0 {
		wait := l.base << min(over-1, 30)
		if wait > l.cap || wait <= 0 {
			wait = l.cap
		}
		e.until = now.Add(wait)
		e.reported = false
	}
}

// reset forgets key's failures.
func (l *limiter) reset(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.entries, key)
}

// sweep drops forgotten entries, then, if the table is still full, every
// entry that does not block anything right now. Entries that block are never
// evicted: flooding the table with new keys cannot lift a lockout. Called with
// the lock held.
func (l *limiter) sweep(now time.Time) {
	for k, e := range l.entries {
		if now.Sub(e.last) > l.forget {
			delete(l.entries, k)
		}
	}
	if len(l.entries) < l.max {
		return
	}
	for k, e := range l.entries {
		if !now.Before(e.until) {
			delete(l.entries, k)
		}
	}
}

// ipKey groups IPv6 clients by /64, the usual allocation to one host or site.
func ipKey(a netip.Addr) string {
	if a.Is6() && !a.Is4In6() {
		p, _ := a.Prefix(64)
		return "ip:" + p.String()
	}
	return "ip:" + a.String()
}

// hostAllowed reports whether the Host header names this console: an IP
// address, localhost, or one of the configured names. A name an attacker
// controls (DNS rebinding) is none of them.
func hostAllowed(host string, allowed []string) bool {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.TrimSuffix(strings.ToLower(strings.Trim(host, "[]")), ".")
	if host == "" {
		return false
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return true
	}
	if host == "localhost" {
		return true
	}
	for _, a := range allowed {
		if host == a {
			return true
		}
	}
	return false
}
