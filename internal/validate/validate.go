// Package validate holds every rule a value must pass before it reaches Samba.
//
// Both roles use it: the web console to refuse a bad form early, and the agent,
// which re-validates everything it reads and is the one that counts. Rules
// return codes, never free text: the UI translates codes, and nothing read
// from the desired state is ever echoed back as a message.
package validate

import (
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/yeppao-org/smbdeck/internal/nthash"
	"github.com/yeppao-org/smbdeck/internal/state"
)

// Code identifies a validation failure. The UI translates it ("err.<code>").
type Code string

// Validation codes. Every code here must have a translation in every catalog
// (enforced by the i18n tests through AllCodes).
const (
	OK Code = ""

	UserNameInvalid   Code = "user.name.invalid"
	UserNameReserved  Code = "user.name.reserved"
	UserNameDuplicate Code = "user.name.duplicate"
	UserUIDInvalid    Code = "user.uid.invalid"
	UserUIDDuplicate  Code = "user.uid.duplicate"
	UserHashInvalid   Code = "user.hash.invalid"

	ShareNameInvalid       Code = "share.name.invalid"
	ShareNameReserved      Code = "share.name.reserved"
	ShareNameDuplicate     Code = "share.name.duplicate"
	ShareRootUnknown       Code = "share.root.unknown"
	ShareRootUnavailable   Code = "share.root.unavailable"
	SharePathInvalid       Code = "share.path.invalid"
	SharePathOutsideRoot   Code = "share.path.outside_root"
	SharePathMissing       Code = "share.path.missing"
	SharePathNotDirectory  Code = "share.path.not_directory"
	SharePathSymlink       Code = "share.path.symlink"
	SharePathCreateFailed  Code = "share.path.create_failed"
	SharePathOwnership     Code = "share.path.ownership_failed"
	ShareAccessInvalid     Code = "share.access.invalid"
	ShareAccessUnknownUser Code = "share.access.unknown_user"
	ShareTimeMachineSize   Code = "share.timemachine.size_invalid"

	PasswordTooShort Code = "password.too_short"
	PasswordTooLong  Code = "password.too_long"
	PasswordInvalid  Code = "password.invalid"
	PasswordMismatch Code = "password.mismatch"

	StateNoAdmin           Code = "state.no_admin"
	StateSchemaUnsupported Code = "state.schema_unsupported"
	StateUnreadable        Code = "state.unreadable"
	StateTooManyUsers      Code = "state.too_many_users"
	StateTooManyShares     Code = "state.too_many_shares"
	StateMissing           Code = "state.missing"
	StateApplyFailed       Code = "state.apply_failed"
)

// AllCodes lists every code, for the translation tests.
func AllCodes() []Code {
	return []Code{
		UserNameInvalid, UserNameReserved, UserNameDuplicate, UserUIDInvalid, UserUIDDuplicate, UserHashInvalid,
		ShareNameInvalid, ShareNameReserved, ShareNameDuplicate, ShareRootUnknown, ShareRootUnavailable,
		SharePathInvalid, SharePathOutsideRoot, SharePathMissing, SharePathNotDirectory, SharePathSymlink, SharePathCreateFailed, SharePathOwnership,
		ShareAccessInvalid, ShareAccessUnknownUser, ShareTimeMachineSize,
		PasswordTooShort, PasswordTooLong, PasswordInvalid, PasswordMismatch,
		StateNoAdmin, StateSchemaUnsupported, StateUnreadable, StateTooManyUsers, StateTooManyShares,
		StateMissing, StateApplyFailed,
	}
}

// Limits on the size of the desired state.
const (
	MaxUsers  = state.MaxUsers
	MaxShares = state.MaxShares
	// MaxPasswordLength bounds the work done hashing a password.
	MaxPasswordLength = 256
	// MaxPathLength bounds a share path relative to its root.
	MaxPathLength = 1024
)

var (
	userNameRE  = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)
	shareNameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$`)
	rootNameRE  = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,31}$`)
	tmSizeRE    = regexp.MustCompile(`^[1-9][0-9]{0,5}[KMGTP]$`)
)

// reservedUsers are names that exist in the agent image or mean something to
// Samba or to the system. Accounts can never take them.
var reservedUsers = map[string]bool{
	"root": true, "daemon": true, "bin": true, "sys": true, "adm": true, "lp": true,
	"sync": true, "shutdown": true, "halt": true, "mail": true, "news": true,
	"uucp": true, "operator": true, "man": true, "postmaster": true, "cron": true,
	"ftp": true, "sshd": true, "at": true, "squid": true, "xfs": true, "games": true,
	"cyrus": true, "vpopmail": true, "ntp": true, "smmsp": true, "guest": true,
	"nobody": true, "nogroup": true, "avahi": true, "messagebus": true,
	"smbdeck": true, "smbdeck-files": true, "administrator": true, "users": true, "wheel": true, "kmem": true, "tty": true,
	"disk": true, "dialout": true, "audio": true, "video": true, "input": true,
	"kvm": true, "netdev": true, "utmp": true, "www-data": true, "shadow": true,
	// Names Samba resolves to well-known SIDs before local accounts (World,
	// NT Authority, Local and BUILTIN domains). As an account, "everyone" in
	// "valid users" would mean every account.
	"everyone": true, "world": true, "builtin": true, "local": true,
	"dialup": true, "network": true, "batch": true, "interactive": true,
	"service": true, "anonymous": true, "proxy": true, "self": true,
	"restricted": true, "system": true, "administrators": true,
	"guests": true, "replicator": true,
}

// sidLike matches what Samba's string_to_sid would read as a SID ("S-1-…",
// case-insensitive): "s-1-1-0" in "valid users" is Everyone.
var sidLike = regexp.MustCompile(`^s-[0-9]`)

// reservedShares are section names with a special meaning in smb.conf.
var reservedShares = map[string]bool{
	"global": true, "homes": true, "printers": true, "print$": true, "ipc$": true,
}

// UserName checks an account name.
func UserName(name string) Code {
	if !userNameRE.MatchString(name) {
		return UserNameInvalid
	}
	if reservedUsers[name] || sidLike.MatchString(name) {
		return UserNameReserved
	}
	return OK
}

// ShareName checks a share name. The name becomes an smb.conf section header.
func ShareName(name string) Code {
	if !shareNameRE.MatchString(name) || strings.HasSuffix(name, " ") || strings.HasSuffix(name, ".") {
		return ShareNameInvalid
	}
	if reservedShares[strings.ToLower(name)] {
		return ShareNameReserved
	}
	return OK
}

// RootName checks the name of a declared root.
func RootName(name string) bool {
	return rootNameRE.MatchString(name)
}

// UID checks an account UID.
func UID(uid int) Code {
	if uid < state.FirstUID || uid > state.LastUID {
		return UserUIDInvalid
	}
	return OK
}

// NTHash checks a stored hash.
func NTHash(s string) Code {
	if _, err := nthash.Parse(s); err != nil {
		return UserHashInvalid
	}
	return OK
}

// TimeMachineSize checks a Time Machine size cap ("" means no cap).
func TimeMachineSize(s string) Code {
	if s == "" || tmSizeRE.MatchString(s) {
		return OK
	}
	return ShareTimeMachineSize
}

// Password checks a new password against the length policy.
func Password(pw string, minLen int) Code {
	if !nthash.Valid(pw) {
		return PasswordInvalid
	}
	for _, r := range pw {
		if unicode.IsControl(r) {
			return PasswordInvalid
		}
	}
	n := utf8.RuneCountInString(pw)
	if n < minLen {
		return PasswordTooShort
	}
	if n > MaxPasswordLength {
		return PasswordTooLong
	}
	return OK
}

// PathComponent reports whether one folder name may appear in a share path.
//
// A share path is written to smb.conf after "path = /roots/<root>/". Samba
// expands %-substitutions in paths ("%U", "%$(VAR)"), reads a trailing
// backslash as a line continuation, and trims surrounding spaces. Each of
// those would make the published folder differ from the one validated, so
// they are refused, with control characters and quotes.
func PathComponent(name string) bool {
	if name == "" || name == "." || name == ".." || len(name) > 255 {
		return false
	}
	if !utf8.ValidString(name) {
		return false
	}
	if strings.TrimSpace(name) != name {
		return false
	}
	for _, r := range name {
		switch {
		case r == '/', r == '\\', r == '%', r == '"', r == 0:
			return false
		case unicode.IsControl(r), r == '\u2028', r == '\u2029', r == '\uFEFF':
			return false
		}
	}
	return true
}

// RelPath checks a share path relative to its root and returns it cleaned
// (no leading or trailing slash, no duplicate slash). "" is the root itself.
// It does not touch the disk: see Resolve.
func RelPath(p string) (string, Code) {
	if p == "" || p == "/" || p == "." {
		return "", OK
	}
	if len(p) > MaxPathLength || !utf8.ValidString(p) {
		return "", SharePathInvalid
	}
	if strings.HasPrefix(p, "/") {
		// Absolute paths are refused rather than silently made relative: the
		// author meant something else.
		return "", SharePathInvalid
	}
	parts := strings.Split(strings.TrimSuffix(p, "/"), "/")
	for _, part := range parts {
		if !PathComponent(part) {
			return "", SharePathInvalid
		}
	}
	return strings.Join(parts, "/"), OK
}
