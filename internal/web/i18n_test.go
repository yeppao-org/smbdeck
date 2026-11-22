package web

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"unicode"

	"github.com/yeppao-org/smbdeck/internal/audit"
	"github.com/yeppao-org/smbdeck/internal/i18n"
	"github.com/yeppao-org/smbdeck/internal/validate"
)

var (
	actionRE   = regexp.MustCompile(`(?s)\{\{.*?\}\}`)
	commentRE  = regexp.MustCompile(`(?s)<!--.*?-->`)
	tagRE      = regexp.MustCompile(`(?s)<[^>]*>`)
	attrRE     = regexp.MustCompile(`\b(placeholder|title|aria-label|alt|label)="([^"]*)"`)
	tKeyRE     = regexp.MustCompile(`\.T "([^"]+)"`)
	goKeyRE    = regexp.MustCompile(`"((?:error|auth|setup|login|users|shares|account|overview|audit|agent)\.[a-z_.]+)"`)
	placeRE    = regexp.MustCompile(`\{[a-z]+\}`)
	letterTest = func(s string) bool { return strings.IndexFunc(s, unicode.IsLetter) >= 0 }
)

func templates(t *testing.T) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := fs.WalkDir(assets, "assets/templates", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		data, err := fs.ReadFile(assets, p)
		out[p] = string(data)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(out) < 8 {
		t.Fatalf("only %d templates found: the walk is broken", len(out))
	}
	return out
}

// Templates carry no text: every word goes through a catalog. What remains
// once actions and tags are removed must hold no letter, and neither may the
// attributes people read (placeholder, title, labels).
func TestTemplatesHaveNoHardcodedText(t *testing.T) {
	checked := 0
	for name, src := range templates(t) {
		noActions := actionRE.ReplaceAllString(commentRE.ReplaceAllString(src, ""), "")
		for _, m := range attrRE.FindAllStringSubmatch(noActions, -1) {
			if letterTest(m[2]) {
				t.Errorf("%s: %s=%q is hard-coded", name, m[1], m[2])
			}
		}
		// The product name is the one word that is never translated.
		text := strings.ReplaceAll(tagRE.ReplaceAllString(noActions, " "), "smbdeck", "")
		for _, line := range strings.Split(text, "\n") {
			checked++
			if letterTest(line) {
				t.Errorf("%s: hard-coded text %q", name, strings.TrimSpace(line))
			}
		}
	}
	if checked < 100 {
		t.Fatalf("only %d lines checked", checked)
	}
}

// The check above must catch a hard-coded word: prove it on a sample.
func TestHardcodedTextCheckBites(t *testing.T) {
	sample := `<p class="x">{{.L.T "a"}} Delete</p><input placeholder="Name">`
	noActions := actionRE.ReplaceAllString(sample, "")
	if !letterTest(tagRE.ReplaceAllString(noActions, " ")) {
		t.Fatal("text check misses a word")
	}
	if m := attrRE.FindStringSubmatch(noActions); m == nil || !letterTest(m[2]) {
		t.Fatal("attribute check misses a word")
	}
}

func bundle(t *testing.T) *i18n.Bundle {
	t.Helper()
	b, err := i18n.Load()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestCatalogsMatch(t *testing.T) {
	b := bundle(t)
	en, fr := b.Keys("en"), b.Keys("fr")
	if len(en) < 150 {
		t.Fatalf("only %d English keys", len(en))
	}
	if !slices.Equal(en, fr) {
		for _, k := range en {
			if !b.Has("fr", k) {
				t.Errorf("fr lacks %s", k)
			}
		}
		for _, k := range fr {
			if !b.Has("en", k) {
				t.Errorf("en lacks %s", k)
			}
		}
	}
	le, lf := b.For("en"), b.For("fr")
	for _, k := range en {
		e, f := le.T(k), lf.T(k)
		if strings.TrimSpace(e) == "" || strings.TrimSpace(f) == "" {
			t.Errorf("%s is empty", k)
		}
		pe, pf := placeRE.FindAllString(e, -1), placeRE.FindAllString(f, -1)
		slices.Sort(pe)
		slices.Sort(pf)
		if !slices.Equal(pe, pf) {
			t.Errorf("%s: placeholders differ: %v / %v", k, pe, pf)
		}
	}
}

func TestEveryKeyInUseExists(t *testing.T) {
	b := bundle(t)
	var keys []string
	for _, src := range templates(t) {
		for _, m := range tKeyRE.FindAllStringSubmatch(src, -1) {
			keys = append(keys, m[1])
		}
	}
	goFiles, _ := filepath.Glob("*.go")
	for _, f := range goFiles {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range goKeyRE.FindAllStringSubmatch(string(src), -1) {
			keys = append(keys, m[1])
		}
	}
	for _, c := range validate.AllCodes() {
		keys = append(keys, "err."+string(c))
	}
	for _, a := range audit.Actions() {
		keys = append(keys, "audit."+a)
	}
	for _, s := range []string{agentApplied, agentPending, agentRefused, agentDown, agentUnknown} {
		keys = append(keys, "agent."+s)
	}
	for _, l := range i18n.Languages {
		keys = append(keys, "lang."+l)
	}
	keys = append(keys, "access.ro", "access.rw", "access.none")
	if len(keys) < 200 {
		t.Fatalf("only %d keys collected", len(keys))
	}
	for _, k := range keys {
		for _, lang := range i18n.Languages {
			if !b.Has(lang, k) {
				t.Errorf("%s: missing key %s", lang, k)
			}
		}
	}
}

func TestMatchLanguage(t *testing.T) {
	cases := map[[2]string]string{
		{"", ""}:                            "en",
		{"", "fr-CA,fr;q=0.9"}:              "fr",
		{"", "de-DE,de;q=0.9,fr;q=0.5"}:     "fr",
		{"", "en;q=0.4,fr;q=0.8"}:           "fr",
		{"", "fr;q=0"}:                      "en",
		{"en", "fr"}:                        "en",
		{"xx", "fr"}:                        "fr",
		{"", "*;q=0.1, garbage;;q=2, fr;q"}: "fr",
	}
	for in, want := range cases {
		if got := i18n.Match(in[0], in[1]); got != want {
			t.Errorf("Match(%q, %q) = %q, want %q", in[0], in[1], got, want)
		}
	}
}
