package web

import (
	"net"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/yeppao-org/smbdeck/internal/state"
)

// Agent states shown in the UI.
const (
	agentApplied = "applied"
	agentPending = "pending"
	agentRefused = "refused"
	agentDown    = "down"
	agentUnknown = "unknown"
)

type statusView struct {
	State     string
	Desired   int64
	Applied   int64
	SMBD      bool
	UpdatedAt time.Time
	Issues    []issueView
	Roots     []state.RootStatus
}

type issueView struct {
	Kind, Name, Field, Code string
}

// agentStatus compares the desired revision with what the agent reports.
func (s *Server) agentStatus(d *state.Desired) statusView {
	v := statusView{State: agentUnknown, Issues: []issueView{}}
	if d != nil {
		v.Desired = d.Revision
	}
	st, err := state.ReadStatus(s.cfg.StatusDir)
	if err != nil {
		return v
	}
	v.Applied, v.SMBD = st.AppliedRevision, st.SMBD.Running
	v.UpdatedAt, v.Roots = st.UpdatedAt, st.Roots
	current := st.ObservedRevision == v.Desired
	if current {
		for _, is := range st.Issues {
			v.Issues = append(v.Issues, issueView{Kind: is.Kind, Name: is.Name, Field: is.Field, Code: is.Code})
		}
	}
	switch {
	case s.now().Sub(st.UpdatedAt) > s.cfg.AgentStale:
		v.State = agentDown
	case current && st.AppliedRevision >= v.Desired:
		v.State = agentApplied
	case current && hasStateIssue(st.Issues):
		v.State = agentRefused
	default:
		v.State = agentPending
	}
	return v
}

func hasStateIssue(issues []state.Issue) bool {
	for _, is := range issues {
		if is.Kind == state.KindState && is.Code != "state.no_admin" {
			return true
		}
	}
	return false
}

func (v statusView) shareIssues(name string) []string {
	var out []string
	for _, is := range v.Issues {
		if is.Kind == state.KindShare && strings.EqualFold(is.Name, name) {
			out = append(out, is.Code)
		}
	}
	return out
}

type accessView struct {
	User     string
	Level    state.Access
	Disabled bool
}

type shareView struct {
	Name, Root, Path string
	CreateFolder     bool
	TimeMachine      bool
	TimeMachineMax   string
	Access           []accessView
	Issues           []string
	// Live: at least one enabled account may open it and the agent reported
	// nothing against it.
	Live bool
}

func shareViews(d *state.Desired, st statusView) []shareView {
	out := make([]shareView, 0, len(d.Shares))
	for _, sh := range d.Shares {
		v := shareView{Name: sh.Name, Root: sh.Root, Path: sh.Path, CreateFolder: sh.CreateFolder,
			TimeMachine: sh.TimeMachine.Enabled, TimeMachineMax: sh.TimeMachine.MaxSize,
			Issues: st.shareIssues(sh.Name)}
		enabled := 0
		for _, name := range sortedKeys(sh.Access) {
			u := d.User(name)
			disabled := u == nil || u.Disabled
			if !disabled {
				enabled++
			}
			v.Access = append(v.Access, accessView{User: name, Level: sh.Access[name], Disabled: disabled})
		}
		v.Live = enabled > 0 && len(v.Issues) == 0
		out = append(out, v)
	}
	return out
}

type userShare struct {
	Share string
	Level state.Access
}

type userView struct {
	Name              string
	Admin, Disabled   bool
	Self              bool
	CreatedAt         time.Time
	PasswordChangedAt time.Time
	Shares            []userShare
}

func userViews(d *state.Desired, self string) []userView {
	out := make([]userView, 0, len(d.Users))
	for _, u := range d.Users {
		out = append(out, userView{Name: u.Name, Admin: u.Admin, Disabled: u.Disabled, Self: u.Name == self,
			CreatedAt: u.CreatedAt, PasswordChangedAt: u.PasswordChangedAt, Shares: sharesOf(d, u.Name)})
	}
	return out
}

func sharesOf(d *state.Desired, user string) []userShare {
	var out []userShare
	for _, sh := range d.Shares {
		if level, ok := sh.Access[user]; ok {
			out = append(out, userShare{Share: sh.Name, Level: level})
		}
	}
	return out
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

// smbHosts returns the names to show in connection strings: the configured
// ones, or the host the browser used to reach the console.
func (s *Server) smbHosts(r *http.Request) []string {
	if len(s.cfg.SMBHosts) > 0 {
		return s.cfg.SMBHosts
	}
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	if host == "" || (!hostRE.MatchString(host) && net.ParseIP(host) == nil) {
		return nil
	}
	return []string{host}
}

type folderView struct {
	Path  string
	Name  string
	Depth int
}

type rootView struct {
	Name      string
	Available bool
	Folders   []folderView
	Truncated bool
}

// rootViews reads the folder tree the agent published.
func (s *Server) rootViews() ([]rootView, bool) {
	t, err := state.ReadTree(s.cfg.StatusDir)
	if err != nil {
		return nil, false
	}
	out := make([]rootView, 0, len(t.Roots))
	for _, r := range t.Roots {
		rv := rootView{Name: r.Name, Available: r.Available, Truncated: r.Truncated}
		for _, f := range r.Folders {
			depth := strings.Count(f, "/")
			name := f[strings.LastIndex(f, "/")+1:]
			rv.Folders = append(rv.Folders, folderView{Path: f, Name: name, Depth: depth})
		}
		out = append(out, rv)
	}
	return out, true
}
