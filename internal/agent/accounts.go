package agent

import (
	"bufio"
	"bytes"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/yeppao-org/smbdeck/internal/state"
)

// Default names of the file-owner identity, used when the image's base files
// do not already name that UID or GID.
const (
	filesUserName  = "smbdeck-files"
	filesGroupName = "smbdeck-files"
)

// baseAccounts is the content of the image's /etc/passwd and /etc/group,
// before any account is added.
type baseAccounts struct {
	passwd, group []byte
	userByName    map[string]bool
	userByUID     map[int]string
	groupByGID    map[int]string
}

func parseBase(passwd, group []byte) baseAccounts {
	b := baseAccounts{
		passwd: passwd, group: group,
		userByName: map[string]bool{}, userByUID: map[int]string{}, groupByGID: map[int]string{},
	}
	scan(passwd, func(f []string) {
		if len(f) >= 3 {
			b.userByName[f[0]] = true
			if id, err := strconv.Atoi(f[2]); err == nil {
				if _, seen := b.userByUID[id]; !seen {
					b.userByUID[id] = f[0]
				}
			}
		}
	})
	scan(group, func(f []string) {
		if len(f) >= 3 {
			if id, err := strconv.Atoi(f[2]); err == nil {
				if _, seen := b.groupByGID[id]; !seen {
					b.groupByGID[id] = f[0]
				}
			}
		}
	})
	return b
}

func scan(data []byte, fn func([]string)) {
	s := bufio.NewScanner(bytes.NewReader(data))
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fn(strings.Split(line, ":"))
	}
}

// filesIdentity returns the user and group names Samba must use for
// "force user" and "force group": the base names when the image already has
// that UID or GID (GID 100 is "users"), smbdeck-files otherwise.
func (b baseAccounts) filesIdentity(uid, gid int) (user, group string) {
	user, group = filesUserName, filesGroupName
	if n, ok := b.userByUID[uid]; ok {
		user = n
	}
	if n, ok := b.groupByGID[gid]; ok {
		group = n
	}
	return user, group
}

// conflicts reports whether an account would clash with an entry of the base
// files. Such an account is refused: it would share an identity with a
// system user.
func (b baseAccounts) conflicts(u state.User) bool {
	if b.userByName[u.Name] {
		return true
	}
	_, ok := b.userByUID[u.UID]
	return ok
}

// renderPasswd returns /etc/passwd: the base entries, the file owner, and one
// entry per account, without shell or home.
func renderPasswd(b baseAccounts, filesUID, filesGID int, users []state.User) []byte {
	var out bytes.Buffer
	out.Write(bytes.TrimRight(b.passwd, "\n"))
	out.WriteByte('\n')
	if _, ok := b.userByUID[filesUID]; !ok {
		fmt.Fprintf(&out, "%s:x:%d:%d:smbdeck file owner:/nonexistent:/sbin/nologin\n", filesUserName, filesUID, filesGID)
	}
	for _, u := range users {
		fmt.Fprintf(&out, "%s:x:%d:%d:smbdeck account:/nonexistent:/sbin/nologin\n", u.Name, u.UID, filesGID)
	}
	return out.Bytes()
}

// renderGroup returns /etc/group: the base entries and the file group.
func renderGroup(b baseAccounts, filesGID int) []byte {
	var out bytes.Buffer
	out.Write(bytes.TrimRight(b.group, "\n"))
	out.WriteByte('\n')
	if _, ok := b.groupByGID[filesGID]; !ok {
		fmt.Fprintf(&out, "%s:x:%d:\n", filesGroupName, filesGID)
	}
	return out.Bytes()
}

// renderSMBPasswd returns the smbpasswd file Samba authenticates against
// ("passdb backend = smbpasswd"). Samba reads it on every authentication, so
// replacing it atomically takes effect at once, without a restart, and
// nothing but the desired state needs to persist.
//
// Format: name:uid:LM hash:NT hash:[flags]:LCT-<hex time>: — the LM hash is
// never set; U = user account, D = disabled, X = password does not expire.
func renderSMBPasswd(users []state.User) []byte {
	var out bytes.Buffer
	for _, u := range users {
		flags := "UX"
		if u.Disabled {
			flags = "UDX"
		}
		fmt.Fprintf(&out, "%s:%d:%s:%s:[%-11s]:LCT-%08X:\n",
			u.Name, u.UID, strings.Repeat("X", 32), strings.ToUpper(u.NTHash), flags, lct(u.PasswordChangedAt))
	}
	return out.Bytes()
}

func lct(t time.Time) uint32 {
	if t.IsZero() || t.Unix() < 0 || t.Unix() > 0xFFFFFFFF {
		return 0
	}
	return uint32(t.Unix()) //nolint:gosec // G115: range checked above
}
