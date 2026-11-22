// Package nthash computes and compares NT hashes, the password digests Samba
// stores for SMB authentication: MD4 over the UTF-16LE encoding of the
// password.
//
// MD4 is broken as a general-purpose hash and the NT hash is unsalted. It is
// nevertheless the only form Samba accepts without storing the password
// itself. smbdeck therefore stores this hash and nothing else, keeps it in a
// 0600 file, and treats it as a secret equivalent to the password (see
// SECURITY.md).
package nthash

import (
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strings"
	"unicode/utf16"
	"unicode/utf8"

	"golang.org/x/crypto/md4" //nolint:gosec,staticcheck // G506: the NT hash is MD4 by definition; Samba accepts nothing else
)

// Size is the length of an NT hash in bytes.
const Size = 16

// Hash is an NT hash.
type Hash [Size]byte

// ErrInvalid is returned for a hash that is not 32 hexadecimal characters.
var ErrInvalid = errors.New("nthash: invalid hash")

// Sum returns the NT hash of password. The password must be valid UTF-8;
// callers validate it first (see Valid).
func Sum(password string) Hash {
	u := utf16.Encode([]rune(password))
	b := make([]byte, 2*len(u))
	for i, c := range u {
		binary.LittleEndian.PutUint16(b[2*i:], c)
	}
	h := md4.New() //nolint:gosec // G406: see the package comment
	h.Write(b)
	var out Hash
	copy(out[:], h.Sum(nil))
	// Best effort: the encoded password does not outlive this call.
	clear(b)
	return out
}

// Valid reports whether password can be hashed faithfully: valid UTF-8 and no
// NUL byte (Samba's tools stop at NUL).
func Valid(password string) bool {
	return utf8.ValidString(password) && !strings.ContainsRune(password, 0)
}

// String returns the hash as 32 upper-case hexadecimal characters, the form
// Samba writes.
func (h Hash) String() string {
	return strings.ToUpper(hex.EncodeToString(h[:]))
}

// Parse reads 32 hexadecimal characters, in either case.
func Parse(s string) (Hash, error) {
	var h Hash
	if len(s) != 2*Size {
		return h, ErrInvalid
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !isHex(c) {
			return h, ErrInvalid
		}
	}
	if _, err := hex.Decode(h[:], []byte(s)); err != nil {
		return h, ErrInvalid
	}
	return h, nil
}

func isHex(c byte) bool {
	return '0' <= c && c <= '9' || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F'
}

// Equal compares two hashes in constant time.
func Equal(a, b Hash) bool {
	return subtle.ConstantTimeCompare(a[:], b[:]) == 1
}

// Verify hashes password and compares it, in constant time, with stored (hex).
// A stored value that does not parse never matches, but the password is
// hashed anyway so that the time taken does not depend on the stored value.
func Verify(password, stored string) bool {
	got := Sum(password)
	want, err := Parse(stored)
	ok := Equal(got, want)
	return ok && err == nil && Valid(password)
}
