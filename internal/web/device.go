package web

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/yeppao-org/smbdeck/internal/fsutil"
)

// Device cookies (OWASP's answer to account lockout by a third party): after
// a successful sign-in, the browser gets a signed cookie naming the account.
// A browser that presents it for that account is not subject to the
// account's lockout, only to a lockout of its own: someone who fails on
// purpose, even from the same address, cannot lock a known browser out.
const (
	cookieDevice   = "smbdeck_device"
	deviceLifetime = 180 * 24 * time.Hour
	deviceKeyFile  = "device.key"
)

type deviceSigner struct {
	key []byte
}

// loadDeviceKey reads the signing key from the state directory, creating it
// if needed. A key that cannot be stored is kept in memory: device cookies
// then last until the next restart.
func loadDeviceKey(dir string) ([]byte, error) {
	path := filepath.Join(dir, deviceKeyFile)
	data, err := fsutil.ReadLimited(path, 1024)
	if err == nil && len(data) == 32 {
		return data, nil
	}
	key := randomBytes(32)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return key, err
	}
	return key, fsutil.WriteAtomic(path, key, 0o600)
}

func (d deviceSigner) mac(payload string) []byte {
	m := hmac.New(sha256.New, d.key)
	m.Write([]byte(payload))
	return m.Sum(nil)
}

// issue returns a cookie value for user.
func (d deviceSigner) issue(user string, now time.Time) string {
	payload := user + "|" + randomToken(16) + "|" + strconv.FormatInt(now.Unix(), 10)
	return base64.RawURLEncoding.EncodeToString([]byte(payload)) + "." + base64.RawURLEncoding.EncodeToString(d.mac(payload))
}

// verify returns the cookie's identifier if it is genuine, recent and names
// user.
func (d deviceSigner) verify(value, user string, now time.Time) (string, bool) {
	p64, m64, ok := strings.Cut(value, ".")
	if !ok {
		return "", false
	}
	payload, err1 := base64.RawURLEncoding.DecodeString(p64)
	mac, err2 := base64.RawURLEncoding.DecodeString(m64)
	if err1 != nil || err2 != nil || !hmac.Equal(mac, d.mac(string(payload))) {
		return "", false
	}
	parts := strings.Split(string(payload), "|")
	if len(parts) != 3 || parts[0] != user {
		return "", false
	}
	issued, err := strconv.ParseInt(parts[2], 10, 64)
	if err != nil || now.Sub(time.Unix(issued, 0)) > deviceLifetime {
		return "", false
	}
	return parts[1], true
}

// defaultSlowdown is the delay imposed on sign-in attempts for an account
// that failed many times recently, from browsers it does not know. It slows
// guessing down without locking anyone out.
func defaultSlowdown(failures int) time.Duration {
	if failures <= 5 {
		return 0
	}
	return min(100*time.Millisecond<<min(failures-6, 8), 2*time.Second)
}
