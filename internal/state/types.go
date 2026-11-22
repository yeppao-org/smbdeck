// Package state defines the files shared by the web console and the agent, and
// the store the web console uses to change the desired state.
//
// Three files live in the state directory:
//
//   - desired.json, written by the web console only: accounts, shares and access.
//   - status.json, written by the agent only: what was applied, and what was refused.
//   - tree.json, written by the agent only: folder names under each root, so the
//     web console can offer a folder picker without mounting any disk.
//
// The agent never trusts desired.json: it validates every value again before
// using it (package validate).
package state

import "time"

// SchemaVersion is the version of desired.json this build reads and writes.
const SchemaVersion = 1

// File names. desired.json, audit.log and the marker live in the state
// directory, which the web console writes; status.json, tree.json and the
// last applied state live in the status directory, which only the agent
// writes (the web console mounts it read-only).
const (
	DesiredFile     = "desired.json"
	AuditFile       = "audit.log"
	InitializedFile = ".initialized"
	StatusFile      = "status.json"
	TreeFile        = "tree.json"
	AppliedFile     = "applied.json"
)

// Size bounds of the files read across roles, so that a corrupted or hostile
// file cannot exhaust memory.
const (
	MaxDesiredSize = 1 << 20
	MaxReportSize  = 4 << 20
)

// Element bounds of the desired state, enforced while decoding.
const (
	MaxUsers  = 1000
	MaxShares = 500
)

// Access is the level an account has on a share.
type Access string

// Access levels. An account absent from a share's access map has no access.
const (
	ReadOnly  Access = "ro"
	ReadWrite Access = "rw"
)

// Desired is the state the web console asks for.
type Desired struct {
	SchemaVersion int   `json:"schemaVersion"`
	Revision      int64 `json:"revision"`
	// NextUID is the UID the next account gets. It only grows: a UID is
	// never handed out twice (clients see it as the account's SID).
	NextUID int     `json:"nextUid,omitempty"`
	Users   []User  `json:"users"`
	Shares  []Share `json:"shares"`
}

// User is a Samba account. It is also a Unix account inside the agent
// container (no shell, no home), with a stable UID.
type User struct {
	Name string `json:"name"`
	UID  int    `json:"uid"`
	// NTHash is the NT hash of the password (MD4 over UTF-16LE), 32 hex
	// characters. It is what Samba needs; the password itself is never stored.
	// It is equivalent to the password for SMB: see SECURITY.md.
	NTHash            string    `json:"ntHash"`
	Admin             bool      `json:"admin"`
	Disabled          bool      `json:"disabled"`
	CreatedAt         time.Time `json:"createdAt"`
	PasswordChangedAt time.Time `json:"passwordChangedAt"`
}

// Share is a folder under a declared root, published over SMB.
type Share struct {
	Name string `json:"name"`
	// Root is the name of a root declared to the agent (SMBDECK_ROOTS).
	Root string `json:"root"`
	// Path is relative to the root. Empty means the root itself.
	Path string `json:"path"`
	// CreateFolder asks the agent to create Path when it does not exist.
	CreateFolder bool              `json:"createFolder"`
	TimeMachine  TimeMachine       `json:"timeMachine"`
	Access       map[string]Access `json:"access"`
}

// TimeMachine makes a share a macOS Time Machine destination.
type TimeMachine struct {
	Enabled bool `json:"enabled"`
	// MaxSize caps the backup size, for example "500G" or "2T". Empty means
	// no cap.
	MaxSize string `json:"maxSize"`
}

// Status is what the agent reports after each pass.
type Status struct {
	SchemaVersion int `json:"schemaVersion"`
	// Revision and SHA256 of the desired state the agent last read.
	ObservedRevision int64  `json:"observedRevision"`
	ObservedSHA256   string `json:"observedSha256"`
	// Revision of the desired state currently applied to Samba.
	AppliedRevision int64     `json:"appliedRevision"`
	AppliedAt       time.Time `json:"appliedAt"`
	// UpdatedAt is refreshed regularly: an old value means the agent is down.
	UpdatedAt    time.Time    `json:"updatedAt"`
	AgentVersion string       `json:"agentVersion"`
	SMBD         SMBDStatus   `json:"smbd"`
	Roots        []RootStatus `json:"roots"`
	// Issues lists what the agent refused. Elements are identified by kind and
	// index, plus their name only when that name is valid: no free text read
	// from the desired state is ever echoed back.
	Issues []Issue `json:"issues"`
}

// SMBDStatus describes the supervised smbd process.
type SMBDStatus struct {
	Running  bool      `json:"running"`
	Since    time.Time `json:"since"`
	Restarts int       `json:"restarts"`
}

// RootStatus tells whether a declared root is usable.
type RootStatus struct {
	Name      string `json:"name"`
	Available bool   `json:"available"`
}

// Issue kinds.
const (
	KindState = "state"
	KindUser  = "user"
	KindShare = "share"
	KindRoot  = "root"
)

// Issue is one refused element, identified by kind and index, with a code.
type Issue struct {
	Kind  string `json:"kind"`
	Index int    `json:"index"`
	Name  string `json:"name,omitempty"`
	Field string `json:"field,omitempty"`
	Code  string `json:"code"`
}

// Tree lists folder names under each root, two levels deep.
type Tree struct {
	GeneratedAt time.Time  `json:"generatedAt"`
	Roots       []TreeRoot `json:"roots"`
}

// TreeRoot is the folder list of one root.
type TreeRoot struct {
	Name      string `json:"name"`
	Available bool   `json:"available"`
	// Folders are slash-separated paths relative to the root, sorted. Names
	// that could never pass validation are left out.
	Folders   []string `json:"folders"`
	Truncated bool     `json:"truncated"`
}

// Clone returns a deep copy.
func (d *Desired) Clone() *Desired {
	if d == nil {
		return nil
	}
	c := *d
	c.Users = append([]User(nil), d.Users...)
	c.Shares = make([]Share, len(d.Shares))
	for i, s := range d.Shares {
		c.Shares[i] = s
		if s.Access != nil {
			c.Shares[i].Access = make(map[string]Access, len(s.Access))
			for k, v := range s.Access {
				c.Shares[i].Access[k] = v
			}
		}
	}
	return &c
}

// User returns the account with this name, or nil.
func (d *Desired) User(name string) *User {
	for i := range d.Users {
		if d.Users[i].Name == name {
			return &d.Users[i]
		}
	}
	return nil
}

// Share returns the share with this name (case-insensitive, as Samba), or nil.
func (d *Desired) Share(name string) *Share {
	for i := range d.Shares {
		if equalFold(d.Shares[i].Name, name) {
			return &d.Shares[i]
		}
	}
	return nil
}

// ActiveAdmins counts admins that are not disabled.
func (d *Desired) ActiveAdmins() int {
	n := 0
	for _, u := range d.Users {
		if u.Admin && !u.Disabled {
			n++
		}
	}
	return n
}

// AllocUID returns the UID for a new account and moves the counter past it:
// above every UID in use and every UID ever handed out, never below FirstUID.
func (d *Desired) AllocUID() int {
	next := max(d.NextUID, FirstUID)
	for _, u := range d.Users {
		if u.UID >= next {
			next = u.UID + 1
		}
	}
	d.NextUID = next + 1
	return next
}

// UID range of accounts. Below FirstUID are the system and file-owner
// identities; LastUID keeps clear of nobody (65534) and overflow UIDs.
const (
	FirstUID = 20000
	LastUID  = 59999
)

func equalFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if 'A' <= ca && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if 'A' <= cb && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}
