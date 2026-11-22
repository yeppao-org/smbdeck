package web

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/yeppao-org/smbdeck/internal/i18n"
	"github.com/yeppao-org/smbdeck/internal/state"
)

//go:embed assets/templates/*.html assets/static
var assets embed.FS

// pages are the templates rendered inside the full layout; barePages inside
// the minimal one (no navigation).
var (
	pages     = []string{"overview", "users", "shares", "share_form", "audit", "account", "error", "confirm"}
	barePages = []string{"login", "setup"}
)

// assetSet serves the static files under content-hashed names, so they can be
// cached forever and still change with each release.
type assetSet struct {
	byLogical map[string]string // "app.css" -> "app.1a2b3c4d5e.css"
	byHashed  map[string]string // reverse
	gzipped   map[string][]byte // compressed text assets, by logical name
	fsys      fs.FS
}

func loadAssets() (*assetSet, error) {
	sub, err := fs.Sub(assets, "assets/static")
	if err != nil {
		return nil, err
	}
	as := &assetSet{byLogical: map[string]string{}, byHashed: map[string]string{}, gzipped: map[string][]byte{}, fsys: sub}
	err = fs.WalkDir(sub, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		data, err := fs.ReadFile(sub, p)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(data)
		ext := path.Ext(p)
		hashed := strings.TrimSuffix(p, ext) + "." + hex.EncodeToString(sum[:5]) + ext
		as.byLogical[p] = hashed
		as.byHashed[hashed] = p
		switch ext {
		case ".css", ".js", ".svg", ".txt":
			var buf bytes.Buffer
			zw, _ := gzip.NewWriterLevel(&buf, gzip.BestCompression)
			_, _ = zw.Write(data)
			_ = zw.Close()
			as.gzipped[p] = buf.Bytes()
		}
		return nil
	})
	return as, err
}

func (as *assetSet) url(logical string) string {
	h, ok := as.byLogical[logical]
	if !ok {
		panic("unknown asset " + logical)
	}
	return "/static/" + h
}

// serve answers /static/<hashed name>.
func (as *assetSet) serve(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/static/")
	logical, hashed := as.byHashed[name]
	if !hashed {
		// Files referenced from the stylesheet (fonts) keep their plain name.
		if _, ok := as.byLogical[name]; !ok {
			http.NotFound(w, r)
			return
		}
		logical = name
	}
	data, err := fs.ReadFile(as.fsys, logical)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	switch path.Ext(logical) {
	case ".css":
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
	case ".js":
		w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	case ".woff2":
		w.Header().Set("Content-Type", "font/woff2")
	case ".svg":
		w.Header().Set("Content-Type", "image/svg+xml")
	case ".txt":
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	default:
		w.Header().Set("Content-Type", "application/octet-stream")
	}
	if hashed {
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	} else {
		w.Header().Set("Cache-Control", "public, max-age=86400")
	}
	if gz, ok := as.gzipped[logical]; ok {
		w.Header().Set("Vary", "Accept-Encoding")
		if acceptsGzip(r) {
			w.Header().Set("Content-Encoding", "gzip")
			data = gz
		}
	}
	_, _ = w.Write(data) //nolint:gosec // G705: embedded static files, served with their own type and nosniff
}

func templateFuncs(as *assetSet) template.FuncMap {
	return template.FuncMap{
		"asset": as.url,
		"smbURL": func(host, share string) string {
			return "smb://" + hostForURL(host) + "/" + (&url.URL{Path: share}).EscapedPath()
		},
		"uncPath": func(host, share string) string {
			return `\\` + host + `\` + share
		},
		"iso": func(t time.Time) string {
			if t.IsZero() {
				return ""
			}
			return t.UTC().Format(time.RFC3339)
		},
		"when": func(l *i18n.Localizer, t time.Time) string {
			if t.IsZero() {
				return "—"
			}
			return t.Local().Format(l.T("format.datetime"))
		},
		"errKey": func(code string) string { return "err." + code },
		"auditKey": func(action string) string {
			return "audit." + action
		},
		"levelKey": func(level state.Access) string { return "access." + string(level) },
		"add":      func(a, b int) int { return a + b },
		"dict": func(kv ...any) map[string]any {
			m := make(map[string]any, len(kv)/2)
			for i := 0; i+1 < len(kv); i += 2 {
				m[fmt.Sprint(kv[i])] = kv[i+1]
			}
			return m
		},
		"initial": func(name string) string {
			if name == "" {
				return "?"
			}
			return strings.ToUpper(name[:1])
		},
	}
}

// hostForURL brackets an IPv6 literal.
func hostForURL(h string) string {
	if strings.Contains(h, ":") && !strings.HasPrefix(h, "[") {
		return "[" + h + "]"
	}
	return h
}

func parseTemplates(as *assetSet) (map[string]*template.Template, error) {
	out := map[string]*template.Template{}
	funcs := templateFuncs(as)
	for _, p := range pages {
		t, err := template.New(p).Funcs(funcs).ParseFS(assets,
			"assets/templates/layout.html", "assets/templates/partials.html", "assets/templates/"+p+".html")
		if err != nil {
			return nil, fmt.Errorf("template %s: %w", p, err)
		}
		out[p] = t
	}
	for _, p := range barePages {
		t, err := template.New(p).Funcs(funcs).ParseFS(assets,
			"assets/templates/bare.html", "assets/templates/partials.html", "assets/templates/"+p+".html")
		if err != nil {
			return nil, fmt.Errorf("template %s: %w", p, err)
		}
		out[p] = t
	}
	return out, nil
}

// page is what every template receives.
type page struct {
	L       *i18n.Localizer
	Lang    string
	Langs   []langLink
	Path    string
	Nav     string
	Title   string
	User    *state.User
	CSRF    string
	Rev     int64
	Flash   []flash
	Reveal  *revealed
	Version string
	// TitleArg fills the {name} placeholder of Title.
	TitleArg string
	Errors   []string
	// MinLength is the password policy, for messages that mention it.
	MinLength int
	Data      any
}

type langLink struct {
	Code    string
	Label   string
	Current bool
	Href    string
}

func (s *Server) render(w http.ResponseWriter, r *http.Request, status int, name string, p *page) {
	t, ok := s.templates[name]
	if !ok {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	rc := reqCtxFrom(r)
	p.L, p.Lang, p.Version, p.Path = rc.l, rc.l.Lang, s.version, r.URL.Path
	p.MinLength = s.cfg.PasswordMinLength
	for _, code := range i18n.Languages {
		p.Langs = append(p.Langs, langLink{
			Code: code, Label: rc.l.T("lang." + code), Current: code == rc.l.Lang,
			Href: "/lang/" + code + "?next=" + url.QueryEscape(r.URL.Path),
		})
	}
	if rc.sess != nil {
		p.CSRF = rc.sess.csrf
		p.Flash = append(rc.sess.takeFlash(), p.Flash...)
		if p.Reveal == nil {
			p.Reveal = rc.sess.takeReveal(s.now())
		}
	}
	if p.User == nil {
		p.User = rc.user
	}
	root := "layout"
	for _, b := range barePages {
		if b == name {
			root = "bare"
		}
	}
	var buf bytes.Buffer
	if err := t.ExecuteTemplate(&buf, root, p); err != nil {
		s.log.Error("render", "page", name, "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write(buf.Bytes())
}

func acceptsGzip(r *http.Request) bool {
	for _, part := range strings.Split(r.Header.Get("Accept-Encoding"), ",") {
		enc, params, _ := strings.Cut(strings.TrimSpace(part), ";")
		if strings.EqualFold(enc, "gzip") && strings.ReplaceAll(params, " ", "") != "q=0" {
			return true
		}
	}
	return false
}
