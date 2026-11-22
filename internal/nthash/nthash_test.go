package nthash

import (
	"strings"
	"testing"
)

// Reference values, written byte by byte as the specifications print them:
// the empty input, and NTOWFv1("Password") from [MS-NLMP] section 4.2.2.1.2.
// The third one is the hash of a lower-case word, as tabulated in Samba's
// test suite.
func TestSumKnownVectors(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"", "31 d6 cf e0 d1 6a e9 31 b7 3c 59 d7 e0 c0 89 c0"},
		{"Password", "a4 f4 9c 40 65 10 bd ca b6 82 4e e7 c3 0f d8 52"},
		{"password", "88 46 f7 ea ee 8f b1 17 ad 06 bd d8 30 b7 58 6c"},
		// U+1F600, outside the BMP: a surrogate pair (D83D DE00) in UTF-16.
		// Computed independently (Python: md4 over the UTF-16LE bytes); an
		// encoding truncated to 16 bits per character gives 3ef50c42….
		{"\U0001F600", "4b 58 a1 0c c2 0a 4e 7d 80 8d 21 8e 1f 80 aa bc"},
	}
	for _, c := range cases {
		want := strings.ToUpper(strings.ReplaceAll(c.want, " ", ""))
		if got := Sum(c.in).String(); got != want {
			t.Errorf("Sum(%q) = %s, want %s", c.in, got, want)
		}
	}
}

// The hash is computed over UTF-16LE: characters outside the BMP are encoded
// as surrogate pairs. A naive per-byte or per-rune encoding gives another value.
func TestSumEncodesUTF16LE(t *testing.T) {
	ascii := Sum("ab")
	if Sum("ab") != ascii {
		t.Fatal("Sum is not deterministic")
	}
	// "é" is U+00E9: one UTF-16 unit, two UTF-8 bytes. Hashing the UTF-8 bytes
	// as if they were Latin-1 would give the hash of "Ã©".
	if Sum("é") == Sum("Ã©") {
		t.Fatal("é and Ã© hash the same: UTF-8 bytes were hashed instead of UTF-16 units")
	}
	// U+1F600 needs a surrogate pair (D83D DE00).
	if Sum("\U0001F600") == Sum("�") {
		t.Fatal("non-BMP character collapsed")
	}
}

func TestParse(t *testing.T) {
	h := Sum("password")
	for _, s := range []string{h.String(), strings.ToLower(h.String())} {
		got, err := Parse(s)
		if err != nil || got != h {
			t.Errorf("Parse(%q) = %v, %v", s, got, err)
		}
	}
	for _, bad := range []string{
		"", "00", strings.Repeat("0", 31), strings.Repeat("0", 33),
		strings.Repeat("g", 32), strings.Repeat("0", 31) + "\n",
		" " + strings.Repeat("0", 31), strings.Repeat("0", 30) + "0x",
	} {
		if _, err := Parse(bad); err == nil {
			t.Errorf("Parse(%q) accepted", bad)
		}
	}
}

func TestVerify(t *testing.T) {
	stored := Sum("correct horse").String()
	if !Verify("correct horse", stored) {
		t.Fatal("right password refused")
	}
	if !Verify("correct horse", strings.ToLower(stored)) {
		t.Fatal("lower-case stored hash refused")
	}
	for _, bad := range []string{"", "correct horse ", "Correct horse", "correct horse\x00"} {
		if Verify(bad, stored) {
			t.Errorf("Verify(%q) accepted", bad)
		}
	}
	if Verify("", "") || Verify("x", "not-a-hash") {
		t.Fatal("unparseable stored hash matched")
	}
	// The empty password hashes to a well-known value; a stored hash equal to it
	// must still only match the empty password.
	if Verify("x", Sum("").String()) {
		t.Fatal("wrong password matched the empty-password hash")
	}
}

func TestValid(t *testing.T) {
	if !Valid("pässwörd ✓") {
		t.Fatal("valid UTF-8 refused")
	}
	if Valid("bad\xffutf8") || Valid("nul\x00inside") {
		t.Fatal("invalid password accepted")
	}
}
