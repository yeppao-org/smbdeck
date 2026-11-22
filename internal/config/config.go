// Package config reads settings from the environment. Every role reads its own
// variables (all prefixed SMBDECK_) and fails at start-up on a bad value,
// rather than running with a guess.
package config

import (
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"
)

// Env reads variables. Tests pass a map; programs pass os.Getenv.
type Env func(string) string

// MapEnv returns an Env backed by a map.
func MapEnv(m map[string]string) Env {
	return func(k string) string { return m[k] }
}

// OS is the process environment.
var OS Env = os.Getenv

// String returns the trimmed value of key, or def when unset or empty.
func (e Env) String(key, def string) string {
	if v := strings.TrimSpace(e(key)); v != "" {
		return v
	}
	return def
}

// Int returns the integer value of key, or def; it fails outside [lo, hi].
func (e Env) Int(key string, def, lo, hi int) (int, error) {
	v := strings.TrimSpace(e(key))
	if v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < lo || n > hi {
		return 0, fmt.Errorf("%s: want an integer between %d and %d", key, lo, hi)
	}
	return n, nil
}

// Duration returns the duration value of key, or def; it fails outside [lo, hi].
func (e Env) Duration(key string, def, lo, hi time.Duration) (time.Duration, error) {
	v := strings.TrimSpace(e(key))
	if v == "" {
		return def, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil || d < lo || d > hi {
		return 0, fmt.Errorf("%s: want a duration between %s and %s", key, lo, hi)
	}
	return d, nil
}

// List splits a comma-separated value, trimming and dropping empty items.
func (e Env) List(key string) []string {
	var out []string
	for _, item := range strings.Split(e(key), ",") {
		if item = strings.TrimSpace(item); item != "" {
			out = append(out, item)
		}
	}
	return out
}

// Prefixes parses a list of networks. A bare address is a single-host network.
// It returns def when the variable is unset.
func (e Env) Prefixes(key string, def []netip.Prefix) ([]netip.Prefix, error) {
	items := e.List(key)
	if len(items) == 0 {
		return def, nil
	}
	return ParsePrefixes(key, items)
}

// ParsePrefixes parses networks in CIDR notation or bare addresses.
func ParsePrefixes(key string, items []string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(items))
	for _, item := range items {
		if p, err := netip.ParsePrefix(item); err == nil {
			out = append(out, p.Masked())
			continue
		}
		a, err := netip.ParseAddr(item)
		if err != nil {
			return nil, fmt.Errorf("%s: %q is neither a network (CIDR) nor an address", key, item)
		}
		a = a.Unmap()
		out = append(out, netip.PrefixFrom(a, a.BitLen()))
	}
	return out, nil
}

// Logger builds the process logger from SMBDECK_LOG_LEVEL (debug, info, warn,
// error) and SMBDECK_LOG_FORMAT (text or json).
func Logger(e Env, role string) (*slog.Logger, error) {
	var level slog.Level
	switch strings.ToLower(e.String("SMBDECK_LOG_LEVEL", "info")) {
	case "debug":
		level = slog.LevelDebug
	case "info":
		level = slog.LevelInfo
	case "warn", "warning":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		return nil, fmt.Errorf("SMBDECK_LOG_LEVEL: want debug, info, warn or error")
	}
	opts := &slog.HandlerOptions{Level: level}
	var h slog.Handler
	switch strings.ToLower(e.String("SMBDECK_LOG_FORMAT", "text")) {
	case "text":
		h = slog.NewTextHandler(os.Stderr, opts)
	case "json":
		h = slog.NewJSONHandler(os.Stderr, opts)
	default:
		return nil, fmt.Errorf("SMBDECK_LOG_FORMAT: want text or json")
	}
	return slog.New(h).With("role", role), nil
}
