package validate

import (
	"maps"
	"slices"
	"strings"

	"github.com/yeppao-org/smbdeck/internal/state"
)

// Report is the outcome of checking a whole desired state without touching
// the disk.
type Report struct {
	// Fatal is set when the state cannot be used at all (unknown schema,
	// oversized lists). The other fields are then empty.
	Fatal  Code
	Issues []state.Issue
	// UserOK and ShareOK tell, per index, whether the element passed.
	UserOK  []bool
	ShareOK []bool
	// Access holds, per share index, the access entries that passed: known,
	// valid accounts with a valid level. Refused entries are reported in Issues.
	Access []map[string]state.Access
}

// HasIssues reports whether anything was refused.
func (r *Report) HasIssues() bool {
	return r.Fatal != OK || len(r.Issues) > 0
}

// Check validates a desired state. roots is the set of declared root names;
// nil means "unknown" and skips that check (the web console before the agent
// has published its roots).
func Check(d *state.Desired, roots map[string]bool) Report {
	var r Report
	if d.SchemaVersion != state.SchemaVersion {
		r.Fatal = StateSchemaUnsupported
		return r
	}
	if len(d.Users) > MaxUsers {
		r.Fatal = StateTooManyUsers
		return r
	}
	if len(d.Shares) > MaxShares {
		r.Fatal = StateTooManyShares
		return r
	}

	r.UserOK = make([]bool, len(d.Users))
	names := make(map[string]bool, len(d.Users))
	uids := make(map[int]bool, len(d.Users))
	validUsers := make(map[string]bool, len(d.Users))
	for i, u := range d.Users {
		ok := true
		nameCode := UserName(u.Name)
		displayName := ""
		if nameCode == OK {
			displayName = u.Name
		}
		add := func(field string, c Code) {
			r.Issues = append(r.Issues, state.Issue{Kind: state.KindUser, Index: i, Name: displayName, Field: field, Code: string(c)})
			ok = false
		}
		switch {
		case nameCode != OK:
			add("name", nameCode)
		case names[u.Name]:
			add("name", UserNameDuplicate)
		}
		if c := UID(u.UID); c != OK {
			add("uid", c)
		} else if uids[u.UID] {
			add("uid", UserUIDDuplicate)
		}
		if c := NTHash(u.NTHash); c != OK {
			add("ntHash", c)
		}
		if nameCode == OK {
			names[u.Name] = true
		}
		if UID(u.UID) == OK {
			uids[u.UID] = true
		}
		r.UserOK[i] = ok
		if ok {
			validUsers[u.Name] = true
		}
	}

	r.ShareOK = make([]bool, len(d.Shares))
	r.Access = make([]map[string]state.Access, len(d.Shares))
	shareNames := make(map[string]bool, len(d.Shares))
	for i, s := range d.Shares {
		ok := true
		nameCode := ShareName(s.Name)
		displayName := ""
		if nameCode == OK {
			displayName = s.Name
		}
		add := func(field string, c Code, fatal bool) {
			r.Issues = append(r.Issues, state.Issue{Kind: state.KindShare, Index: i, Name: displayName, Field: field, Code: string(c)})
			if fatal {
				ok = false
			}
		}
		lower := strings.ToLower(s.Name)
		switch {
		case nameCode != OK:
			add("name", nameCode, true)
		case shareNames[lower]:
			add("name", ShareNameDuplicate, true)
		}
		if nameCode == OK {
			shareNames[lower] = true
		}
		if !RootName(s.Root) || (roots != nil && !roots[s.Root]) {
			add("root", ShareRootUnknown, true)
		}
		if _, c := RelPath(s.Path); c != OK {
			add("path", c, true)
		}
		if c := TimeMachineSize(s.TimeMachine.MaxSize); c != OK {
			add("timeMachine.maxSize", c, true)
		}
		access := make(map[string]state.Access, len(s.Access))
		for _, user := range slices.Sorted(maps.Keys(s.Access)) {
			level := s.Access[user]
			switch {
			case !validUsers[user]:
				// Unknown or refused account: the entry is dropped, the share stays.
				add("access", ShareAccessUnknownUser, false)
			case level != state.ReadOnly && level != state.ReadWrite:
				add("access", ShareAccessInvalid, false)
			default:
				access[user] = level
			}
		}
		r.ShareOK[i] = ok
		r.Access[i] = access
	}

	activeAdmins := 0
	for i, u := range d.Users {
		if r.UserOK[i] && u.Admin && !u.Disabled {
			activeAdmins++
		}
	}
	if activeAdmins == 0 {
		r.Issues = append(r.Issues, state.Issue{Kind: state.KindState, Index: 0, Code: string(StateNoAdmin)})
	}
	return r
}
