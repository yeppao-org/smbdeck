package agent

import (
	"errors"
	"maps"
	"os"
	"slices"
	"strings"

	"github.com/yeppao-org/smbdeck/internal/smbconf"
	"github.com/yeppao-org/smbdeck/internal/state"
	"github.com/yeppao-org/smbdeck/internal/validate"
)

// plan is what the agent applies: only elements that passed every check.
type plan struct {
	revision int64
	digest   string
	users    []state.User
	shares   []plannedShare
	issues   []state.Issue
	roots    []state.RootStatus
}

type plannedShare struct {
	name   string
	path   string
	access map[string]state.Access
	conf   smbconf.Share
}

// user returns the planned account with this name, or nil.
func (p *plan) user(name string) *state.User {
	for i := range p.users {
		if p.users[i].Name == name {
			return &p.users[i]
		}
	}
	return nil
}

func (p *plan) share(name string) *plannedShare {
	for i := range p.shares {
		if strings.EqualFold(p.shares[i].name, name) {
			return &p.shares[i]
		}
	}
	return nil
}

// folderCreator creates a missing share folder (createFolder; tests may
// replace it).
type folderCreator func(rootDir, rel string) error

// buildPlan turns a desired state into a plan. Every value is validated again,
// whatever the web console checked, and every share path is resolved on disk
// inside its root.
func buildPlan(d *state.Desired, roots []Root, base baseAccounts, filesUser, filesGroup string, mkdir folderCreator) plan {
	p := plan{revision: d.Revision}
	rootDirs := make(map[string]string, len(roots))
	rootNames := make(map[string]bool, len(roots))
	for _, r := range roots {
		fi, err := os.Stat(r.Dir)
		ok := err == nil && fi.IsDir()
		p.roots = append(p.roots, state.RootStatus{Name: r.Name, Available: ok})
		rootNames[r.Name] = true
		if ok {
			rootDirs[r.Name] = r.Dir
		}
	}

	report := validate.Check(d, rootNames)
	if report.Fatal != validate.OK {
		p.issues = append(p.issues, state.Issue{Kind: state.KindState, Code: string(report.Fatal)})
		return p
	}
	p.issues = append(p.issues, report.Issues...)

	for i, u := range d.Users {
		if !report.UserOK[i] {
			continue
		}
		if base.conflicts(u) {
			p.issues = append(p.issues, state.Issue{Kind: state.KindUser, Index: i, Name: u.Name, Field: "name", Code: string(validate.UserNameReserved)})
			continue
		}
		u.NTHash = strings.ToUpper(u.NTHash)
		p.users = append(p.users, u)
	}

	for i, s := range d.Shares {
		if !report.ShareOK[i] {
			continue
		}
		issue := func(field string, c validate.Code) {
			p.issues = append(p.issues, state.Issue{Kind: state.KindShare, Index: i, Name: s.Name, Field: field, Code: string(c)})
		}
		rootDir, ok := rootDirs[s.Root]
		if !ok {
			issue("root", validate.ShareRootUnavailable)
			continue
		}
		path, code := validate.Resolve(rootDir, s.Path)
		if code == validate.SharePathMissing && s.CreateFolder && mkdir != nil {
			rel, _ := validate.RelPath(s.Path)
			if err := mkdir(rootDir, rel); err != nil {
				if errors.Is(err, errOwnership) {
					issue("path", validate.SharePathOwnership)
				} else {
					issue("path", validate.SharePathCreateFailed)
				}
				continue
			}
			path, code = validate.Resolve(rootDir, s.Path)
		}
		if code != validate.OK {
			issue("path", code)
			continue
		}

		access := map[string]state.Access{}
		var read, write []string
		for _, name := range slices.Sorted(maps.Keys(report.Access[i])) {
			u := p.user(name)
			if u == nil {
				continue
			}
			level := report.Access[i][name]
			access[name] = level
			if u.Disabled {
				// Disabled accounts cannot log in anyway; they stay out of the
				// lists so the file says exactly who can connect.
				continue
			}
			if level == state.ReadWrite {
				write = append(write, name)
			} else {
				read = append(read, name)
			}
		}
		p.shares = append(p.shares, plannedShare{
			name: s.Name, path: path, access: access,
			conf: smbconf.Share{
				Name: s.Name, Path: path, ReadUsers: read, WriteUsers: write,
				FilesUser: filesUser, FilesGroup: filesGroup,
				TimeMachine: s.TimeMachine.Enabled, TimeMachineMaxSize: s.TimeMachine.MaxSize,
			},
		})
	}
	return p
}

// sessionsToClose lists the accounts, by UID, whose open SMB sessions must
// end when moving from the applied plan old to next: deleted or disabled
// accounts, changed passwords, and any access that shrank, moved or went from
// read-only to read-write (Samba fixes the write right when the client
// connects to the share, so only a new connection gets the widened right).
// An access that is new on a share closes nothing: the account has no
// connection to it yet.
func sessionsToClose(old, next *plan) map[int]string {
	out := map[int]string{}
	if old == nil {
		return out
	}
	uid := map[string]int{}
	for _, u := range old.users {
		uid[u.Name] = u.UID
		n := next.user(u.Name)
		switch {
		case n == nil, n.Disabled && !u.Disabled, n.NTHash != u.NTHash, n.UID != u.UID:
			out[u.UID] = u.Name
		}
	}
	for _, s := range old.shares {
		ns := next.share(s.name)
		for name, level := range s.access {
			id, ok := uid[name]
			if !ok {
				continue
			}
			switch {
			case ns == nil, ns.path != s.path:
				out[id] = name
			case ns.access[name] == "":
				out[id] = name
			case level == state.ReadWrite && ns.access[name] == state.ReadOnly:
				out[id] = name
			case level == state.ReadOnly && ns.access[name] == state.ReadWrite:
				out[id] = name
			}
		}
	}
	return out
}
