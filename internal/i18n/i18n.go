// Package i18n holds the UI catalogs (English and French) and picks a language
// for each request. Templates never contain text: every string goes through a
// catalog key, and error messages are catalog entries keyed by code.
package i18n

import (
	"embed"
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"
)

//go:embed locales/*.json
var files embed.FS

// Default is the language used when nothing else matches.
const Default = "en"

// Languages lists the supported languages, in display order.
var Languages = []string{"en", "fr"}

// Bundle holds every catalog.
type Bundle struct {
	cats map[string]map[string]string
}

// Load reads the embedded catalogs.
func Load() (*Bundle, error) {
	b := &Bundle{cats: map[string]map[string]string{}}
	for _, lang := range Languages {
		data, err := files.ReadFile("locales/" + lang + ".json")
		if err != nil {
			return nil, err
		}
		var cat map[string]string
		if err := json.Unmarshal(data, &cat); err != nil {
			return nil, fmt.Errorf("i18n: %s: %w", lang, err)
		}
		b.cats[lang] = cat
	}
	return b, nil
}

// Keys returns the keys of a catalog, sorted (for tests).
func (b *Bundle) Keys(lang string) []string {
	keys := make([]string, 0, len(b.cats[lang]))
	for k := range b.cats[lang] {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// Has reports whether lang's catalog has key.
func (b *Bundle) Has(lang, key string) bool {
	_, ok := b.cats[lang][key]
	return ok
}

// Supported reports whether lang is a supported language code.
func Supported(lang string) bool {
	return slices.Contains(Languages, lang)
}

// Match picks the language: the explicit choice (cookie) when supported, else
// the best match in Accept-Language, else Default.
func Match(choice, acceptLanguage string) string {
	if Supported(choice) {
		return choice
	}
	type pref struct {
		lang string
		q    float64
		pos  int
	}
	var prefs []pref
	for i, part := range strings.Split(acceptLanguage, ",") {
		tag, params, _ := strings.Cut(strings.TrimSpace(part), ";")
		q := 1.0
		if v, ok := strings.CutPrefix(strings.TrimSpace(params), "q="); ok {
			f, err := strconv.ParseFloat(v, 64)
			if err != nil || f < 0 || f > 1 {
				continue
			}
			q = f
		}
		primary, _, _ := strings.Cut(strings.ToLower(strings.TrimSpace(tag)), "-")
		if q > 0 && Supported(primary) {
			prefs = append(prefs, pref{primary, q, i})
		}
	}
	sort.SliceStable(prefs, func(i, j int) bool { return prefs[i].q > prefs[j].q })
	if len(prefs) > 0 {
		return prefs[0].lang
	}
	return Default
}

// Localizer translates for one language.
type Localizer struct {
	Lang string
	cat  map[string]string
	def  map[string]string
}

// For returns the localizer of lang (Default if unsupported).
func (b *Bundle) For(lang string) *Localizer {
	if !Supported(lang) {
		lang = Default
	}
	return &Localizer{Lang: lang, cat: b.cats[lang], def: b.cats[Default]}
}

// T returns the text of key, with {name} placeholders replaced by the given
// name/value pairs. A missing key falls back to English, then to the key
// itself (the tests make sure that never happens).
func (l *Localizer) T(key string, args ...any) string {
	s, ok := l.cat[key]
	if !ok {
		if s, ok = l.def[key]; !ok {
			return key
		}
	}
	for i := 0; i+1 < len(args); i += 2 {
		s = strings.ReplaceAll(s, "{"+fmt.Sprint(args[i])+"}", fmt.Sprint(args[i+1]))
	}
	return s
}
