package web

import (
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/yeppao-org/smbdeck/internal/audit"
	"github.com/yeppao-org/smbdeck/internal/nthash"
	"github.com/yeppao-org/smbdeck/internal/state"
	"github.com/yeppao-org/smbdeck/internal/validate"
)

// generatePassword returns 20 random characters (about 116 bits) in groups
// of five, from an alphabet without look-alikes.
func generatePassword() string {
	raw := randomString("abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789", 20)
	return raw[0:5] + "-" + raw[5:10] + "-" + raw[10:15] + "-" + raw[15:20]
}

// revision reads the "rev" field every write form carries.
func revision(r *http.Request) int64 {
	n, _ := strconv.ParseInt(r.PostFormValue("rev"), 10, 64)
	return n
}

// update applies fn to the desired state at the revision the form was built
// from. On failure it returns the catalog keys explaining why.
func (s *Server) update(r *http.Request, fn func(*state.Desired) error) (*state.Desired, []string, bool) {
	d, err := s.store.Update(revision(r), fn)
	if err != nil {
		return nil, s.updateErrors(err), false
	}
	return d, nil, true
}

// updateErrors turns an update failure into catalog keys.
func (s *Server) updateErrors(err error) []string {
	var fe *formError
	switch {
	case errors.As(err, &fe):
		keys := make([]string, 0, len(fe.codes))
		for _, c := range fe.codes {
			keys = append(keys, "err."+string(c))
		}
		return keys
	case errors.Is(err, state.ErrConflict):
		return []string{"error.conflict"}
	case errors.Is(err, errNotFound):
		return []string{"error.not_found"}
	case errors.Is(err, state.ErrMissing):
		return []string{"error.state_missing"}
	default:
		s.log.Error("update desired state", "err", err)
		return []string{"error.state"}
	}
}

var errNotFound = errors.New("not found")

func (s *Server) flashErrors(r *http.Request, keys []string) {
	rc := reqCtxFrom(r)
	for _, k := range keys {
		rc.sess.addFlash(flash{Kind: "error", Key: k})
	}
}

func (s *Server) flashOK(r *http.Request, key, arg string) {
	reqCtxFrom(r).sess.addFlash(flash{Kind: "ok", Key: key, Arg: arg})
}

func (s *Server) handleHome(w http.ResponseWriter, r *http.Request) {
	rc := reqCtxFrom(r)
	if !rc.user.Admin {
		http.Redirect(w, r, "/account", http.StatusSeeOther)
		return
	}
	d := rc.state
	st := s.agentStatus(d)
	active, admins := 0, 0
	for _, u := range d.Users {
		if !u.Disabled {
			active++
			if u.Admin {
				admins++
			}
		}
	}
	s.render(w, r, http.StatusOK, "overview", &page{Title: "overview.title", Nav: "overview", Rev: d.Revision,
		Data: overviewData{Status: st, Shares: shareViews(d, st), Users: userViews(d, rc.user.Name),
			Hosts: s.smbHosts(r), Active: active, Admins: admins}})
}

type overviewData struct {
	Status statusView
	Shares []shareView
	Users  []userView
	Hosts  []string
	Active int
	Admins int
}

// --- Accounts ---------------------------------------------------------------

type usersData struct {
	Users     []userView
	Status    statusView
	MinLength int
	Form      userForm
}

type userForm struct {
	Name  string
	Admin bool
	Open  bool
}

func (s *Server) renderUsers(w http.ResponseWriter, r *http.Request, status int, form userForm, errs []string) {
	rc := reqCtxFrom(r)
	d, err := s.store.Load()
	if err != nil {
		s.fail(w, r, http.StatusServiceUnavailable, "error.state")
		return
	}
	s.render(w, r, status, "users", &page{Title: "users.title", Nav: "users", Rev: d.Revision, Errors: errs,
		Data: usersData{Users: userViews(d, rc.user.Name), Status: s.agentStatus(d),
			MinLength: s.cfg.PasswordMinLength, Form: form}})
}

func (s *Server) handleUsers(w http.ResponseWriter, r *http.Request) {
	s.renderUsers(w, r, http.StatusOK, userForm{}, nil)
}

func (s *Server) handleUserCreate(w http.ResponseWriter, r *http.Request) {
	rc := reqCtxFrom(r)
	form := userForm{Name: strings.ToLower(strings.TrimSpace(r.PostFormValue("name"))),
		Admin: r.PostFormValue("admin") == "on", Open: true}
	password := r.PostFormValue("password")
	generated := password == ""
	if generated {
		password = generatePassword()
	}
	var errs []string
	if c := validate.UserName(form.Name); c != validate.OK {
		errs = append(errs, "err."+string(c))
	}
	if c := validate.Password(password, s.cfg.PasswordMinLength); c != validate.OK {
		errs = append(errs, "err."+string(c))
	}
	if len(errs) > 0 {
		s.renderUsers(w, r, http.StatusUnprocessableEntity, form, errs)
		return
	}
	now := s.now().UTC()
	_, errs, ok := s.update(r, func(d *state.Desired) error {
		if d.User(form.Name) != nil {
			return &formError{codes: []validate.Code{validate.UserNameDuplicate}}
		}
		d.Users = append(d.Users, state.User{Name: form.Name, UID: d.AllocUID(), NTHash: nthash.Sum(password).String(),
			Admin: form.Admin, CreatedAt: now, PasswordChangedAt: now})
		return nil
	})
	if !ok {
		s.renderUsers(w, r, http.StatusUnprocessableEntity, form, errs)
		return
	}
	s.remember(r, rc.user.Name, audit.UserCreated, form.Name, audit.OK)
	if generated {
		rc.sess.setReveal(&revealed{User: form.Name, Password: password, At: s.now()})
	}
	s.flashOK(r, "users.created", form.Name)
	http.Redirect(w, r, "/users", http.StatusSeeOther)
}

func (s *Server) handleUserPassword(w http.ResponseWriter, r *http.Request) {
	rc := reqCtxFrom(r)
	name := r.PathValue("name")
	password := r.PostFormValue("password")
	generated := password == ""
	if generated {
		password = generatePassword()
	}
	if c := validate.Password(password, s.cfg.PasswordMinLength); c != validate.OK {
		s.flashErrors(r, []string{"err." + string(c)})
		http.Redirect(w, r, "/users", http.StatusSeeOther)
		return
	}
	now := s.now().UTC()
	d, errs, ok := s.update(r, func(d *state.Desired) error {
		u := d.User(name)
		if u == nil {
			return errNotFound
		}
		u.NTHash = nthash.Sum(password).String()
		u.PasswordChangedAt = now
		return nil
	})
	if !ok {
		s.flashErrors(r, errs)
		http.Redirect(w, r, "/users", http.StatusSeeOther)
		return
	}
	// Every session of that account ends, except this one if it is the
	// administrator's own: it is renewed with the new password date.
	s.sessions.deleteUser(name, nil)
	if name == rc.user.Name {
		s.startSession(w, r, d.User(name))
	}
	s.remember(r, rc.user.Name, audit.UserPasswordReset, name, audit.OK)
	if generated {
		rc.sess.setReveal(&revealed{User: name, Password: password, At: s.now()})
	}
	s.flashOK(r, "users.password_set", name)
	http.Redirect(w, r, "/users", http.StatusSeeOther)
}

var userFlagMeta = map[string]struct{ action, key string }{
	"disable": {audit.UserDisabled, "users.disabled"},
	"enable":  {audit.UserEnabled, "users.enabled"},
	"grant":   {audit.UserAdminGranted, "users.admin_granted"},
	"revoke":  {audit.UserAdminRevoked, "users.admin_revoked"},
}

// handleUserFlag disables, enables, grants or revokes administration.
func (s *Server) handleUserFlag(kind string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rc := reqCtxFrom(r)
		name := r.PathValue("name")
		_, errs, ok := s.update(r, func(d *state.Desired) error {
			u := d.User(name)
			if u == nil {
				return errNotFound
			}
			switch kind {
			case "disable":
				u.Disabled = true
			case "enable":
				u.Disabled = false
			case "grant":
				u.Admin = true
			case "revoke":
				u.Admin = false
			}
			return nil
		})
		if !ok {
			s.flashErrors(r, errs)
			http.Redirect(w, r, "/users", http.StatusSeeOther)
			return
		}
		action, key := userFlagMeta[kind].action, userFlagMeta[kind].key
		if kind == "disable" {
			s.sessions.deleteUser(name, nil)
		}
		s.remember(r, rc.user.Name, action, name, audit.OK)
		if (kind == "disable" || kind == "revoke") && name == rc.user.Name {
			// Signed out or no longer an administrator: leave the admin pages.
			http.Redirect(w, r, "/account", http.StatusSeeOther)
			return
		}
		s.flashOK(r, key, name)
		http.Redirect(w, r, "/users", http.StatusSeeOther)
	}
}

func (s *Server) handleUserDelete(w http.ResponseWriter, r *http.Request) {
	rc := reqCtxFrom(r)
	name := r.PathValue("name")
	_, errs, ok := s.update(r, func(d *state.Desired) error {
		i := -1
		for j := range d.Users {
			if d.Users[j].Name == name {
				i = j
			}
		}
		if i < 0 {
			return errNotFound
		}
		d.Users = append(d.Users[:i], d.Users[i+1:]...)
		for _, sh := range d.Shares {
			delete(sh.Access, name)
		}
		return nil
	})
	if !ok {
		s.flashErrors(r, errs)
		http.Redirect(w, r, "/users", http.StatusSeeOther)
		return
	}
	s.sessions.deleteUser(name, nil)
	s.remember(r, rc.user.Name, audit.UserDeleted, name, audit.OK)
	if name == rc.user.Name {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	s.flashOK(r, "users.deleted", name)
	http.Redirect(w, r, "/users", http.StatusSeeOther)
}

// --- Shares -----------------------------------------------------------------

type sharesData struct {
	Shares []shareView
	Status statusView
	Hosts  []string
}

func (s *Server) handleShares(w http.ResponseWriter, r *http.Request) {
	d := reqCtxFrom(r).state
	st := s.agentStatus(d)
	s.render(w, r, http.StatusOK, "shares", &page{Title: "shares.title", Nav: "shares", Rev: d.Revision,
		Data: sharesData{Shares: shareViews(d, st), Status: st, Hosts: s.smbHosts(r)}})
}

type shareForm struct {
	Editing      bool
	Original     string
	Name         string
	Root         string
	Path         string
	CreateFolder bool
	TimeMachine  bool
	TMMax        string
	Access       map[string]string
	Users        []userView
	Roots        []rootView
	Reported     bool
	Issues       []string
}

func (s *Server) renderShareForm(w http.ResponseWriter, r *http.Request, status int, f shareForm, errs []string) {
	d, err := s.store.Load()
	if err != nil {
		s.fail(w, r, http.StatusServiceUnavailable, "error.state")
		return
	}
	f.Users = userViews(d, reqCtxFrom(r).user.Name)
	f.Roots, f.Reported = s.rootViews()
	if f.Root == "" && len(f.Roots) > 0 {
		f.Root = f.Roots[0].Name
	}
	if f.Editing {
		f.Issues = s.agentStatus(d).shareIssues(f.Original)
	}
	title := "shares.new_title"
	if f.Editing {
		title = "shares.edit_title"
	}
	s.render(w, r, status, "share_form", &page{Title: title, Nav: "shares", Rev: d.Revision, Errors: errs, Data: f})
}

func (s *Server) handleShareNew(w http.ResponseWriter, r *http.Request) {
	s.renderShareForm(w, r, http.StatusOK, shareForm{Access: map[string]string{}, CreateFolder: true}, nil)
}

func (s *Server) handleShareEdit(w http.ResponseWriter, r *http.Request) {
	d := reqCtxFrom(r).state
	sh := d.Share(r.PathValue("name"))
	if sh == nil {
		s.fail(w, r, http.StatusNotFound, "error.not_found")
		return
	}
	f := shareForm{Editing: true, Original: sh.Name, Name: sh.Name, Root: sh.Root, Path: sh.Path,
		CreateFolder: sh.CreateFolder, TimeMachine: sh.TimeMachine.Enabled, TMMax: sh.TimeMachine.MaxSize,
		Access: map[string]string{}}
	for u, level := range sh.Access {
		f.Access[u] = string(level)
	}
	s.renderShareForm(w, r, http.StatusOK, f, nil)
}

func (s *Server) handleShareSave(w http.ResponseWriter, r *http.Request) {
	rc := reqCtxFrom(r)
	original := r.PathValue("name")
	f := shareForm{
		Editing: original != "", Original: original,
		Name: strings.TrimSpace(r.PostFormValue("name")), Root: r.PostFormValue("root"),
		Path:         strings.Trim(strings.TrimSpace(r.PostFormValue("path")), "/"),
		CreateFolder: r.PostFormValue("create_folder") == "on",
		TimeMachine:  r.PostFormValue("timemachine") == "on",
		TMMax:        strings.ToUpper(strings.TrimSpace(r.PostFormValue("timemachine_max"))),
		Access:       map[string]string{},
	}
	if !f.TimeMachine {
		f.TMMax = ""
	}
	var errs []string
	if c := validate.ShareName(f.Name); c != validate.OK {
		errs = append(errs, "err."+string(c))
	}
	clean, c := validate.RelPath(f.Path)
	if c != validate.OK {
		errs = append(errs, "err."+string(c))
	}
	f.Path = clean
	if c := validate.TimeMachineSize(f.TMMax); c != validate.OK {
		errs = append(errs, "err."+string(c))
	}
	if roots := s.rootNames(); roots == nil || !roots[f.Root] {
		errs = append(errs, "err."+string(validate.ShareRootUnknown))
	}
	d := rc.state
	for _, u := range d.Users {
		switch level := r.PostFormValue("access_" + u.Name); level {
		case "ro", "rw":
			f.Access[u.Name] = level
		case "", "none":
		default:
			errs = append(errs, "err."+string(validate.ShareAccessInvalid))
		}
	}
	// A folder picked without JavaScript: the form comes back with the
	// folder filled in, nothing is saved.
	if pick := r.PostFormValue("pick"); pick != "" {
		root, rel, _ := strings.Cut(pick, "/")
		if clean, c := validate.RelPath(rel); c == validate.OK && s.rootNames()[root] {
			f.Root, f.Path = root, clean
		}
		s.renderShareForm(w, r, http.StatusOK, f, nil)
		return
	}
	if len(errs) > 0 {
		s.renderShareForm(w, r, http.StatusUnprocessableEntity, f, errs)
		return
	}
	_, errs, ok := s.update(r, func(d *state.Desired) error {
		if f.Editing {
			cur := d.Share(f.Original)
			if cur == nil {
				return errNotFound
			}
			if other := d.Share(f.Name); other != nil && other != cur {
				return &formError{codes: []validate.Code{validate.ShareNameDuplicate}}
			}
			*cur = f.toShare()
			return nil
		}
		if d.Share(f.Name) != nil {
			return &formError{codes: []validate.Code{validate.ShareNameDuplicate}}
		}
		d.Shares = append(d.Shares, f.toShare())
		return nil
	})
	if !ok {
		s.renderShareForm(w, r, http.StatusUnprocessableEntity, f, errs)
		return
	}
	action, key := audit.ShareCreated, "shares.created"
	if f.Editing {
		action, key = audit.ShareUpdated, "shares.updated"
	}
	s.remember(r, rc.user.Name, action, f.Name, audit.OK)
	s.flashOK(r, key, f.Name)
	http.Redirect(w, r, "/shares", http.StatusSeeOther)
}

func (f shareForm) toShare() state.Share {
	sh := state.Share{Name: f.Name, Root: f.Root, Path: f.Path, CreateFolder: f.CreateFolder,
		TimeMachine: state.TimeMachine{Enabled: f.TimeMachine, MaxSize: f.TMMax},
		Access:      map[string]state.Access{}}
	for u, level := range f.Access {
		sh.Access[u] = state.Access(level)
	}
	return sh
}

func (s *Server) handleShareDelete(w http.ResponseWriter, r *http.Request) {
	rc := reqCtxFrom(r)
	name := r.PathValue("name")
	_, errs, ok := s.update(r, func(d *state.Desired) error {
		for i := range d.Shares {
			if strings.EqualFold(d.Shares[i].Name, name) {
				d.Shares = append(d.Shares[:i], d.Shares[i+1:]...)
				return nil
			}
		}
		return errNotFound
	})
	if !ok {
		s.flashErrors(r, errs)
		http.Redirect(w, r, "/shares/"+url.PathEscape(name), http.StatusSeeOther)
		return
	}
	s.remember(r, rc.user.Name, audit.ShareDeleted, name, audit.OK)
	s.flashOK(r, "shares.deleted", name)
	http.Redirect(w, r, "/shares", http.StatusSeeOther)
}

// --- Journal ----------------------------------------------------------------

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	entries, err := s.audit.Recent(300)
	if err != nil {
		s.log.Error("read audit", "err", err)
	}
	s.render(w, r, http.StatusOK, "audit", &page{Title: "audit.title", Nav: "audit", Data: entries})
}

// --- Confirmations without JavaScript ---------------------------------------

// confirmData is a confirmation page: the same form as the dialog, for
// browsers without JavaScript. Every field but Name and the paths is a
// catalog key.
type confirmData struct {
	Eyebrow, Title, Text, Submit string
	Name                         string
	Action, Back                 string
	Danger, Password             bool
}

func (s *Server) renderConfirm(w http.ResponseWriter, r *http.Request, c confirmData) {
	d := reqCtxFrom(r).state
	s.render(w, r, http.StatusOK, "confirm", &page{Title: c.Title, TitleArg: c.Name, Nav: "users", Rev: d.Revision, Data: c})
}

func (s *Server) handleUserPasswordPage(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if reqCtxFrom(r).state.User(name) == nil {
		s.fail(w, r, http.StatusNotFound, "error.not_found")
		return
	}
	s.renderConfirm(w, r, confirmData{Eyebrow: "users.reset_eyebrow", Title: "users.reset_title", Text: "users.reset_text",
		Submit: "users.reset_submit", Name: name, Action: "/users/" + name + "/password", Back: "/users", Password: true})
}

func (s *Server) handleUserDeletePage(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if reqCtxFrom(r).state.User(name) == nil {
		s.fail(w, r, http.StatusNotFound, "error.not_found")
		return
	}
	s.renderConfirm(w, r, confirmData{Eyebrow: "dialog.irreversible", Title: "users.delete_title", Text: "users.delete_text",
		Submit: "users.delete_submit", Name: name, Action: "/users/" + name + "/delete", Back: "/users", Danger: true})
}

func (s *Server) handleShareDeletePage(w http.ResponseWriter, r *http.Request) {
	sh := reqCtxFrom(r).state.Share(r.PathValue("name"))
	if sh == nil {
		s.fail(w, r, http.StatusNotFound, "error.not_found")
		return
	}
	s.renderConfirm(w, r, confirmData{Eyebrow: "dialog.irreversible", Title: "shares.delete_title", Text: "shares.delete_text",
		Submit: "shares.delete_submit", Name: sh.Name, Action: "/shares/" + url.PathEscape(sh.Name) + "/delete",
		Back: "/shares/" + url.PathEscape(sh.Name), Danger: true})
}
