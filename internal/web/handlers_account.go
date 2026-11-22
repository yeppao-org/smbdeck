package web

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/yeppao-org/smbdeck/internal/audit"
	"github.com/yeppao-org/smbdeck/internal/nthash"
	"github.com/yeppao-org/smbdeck/internal/state"
	"github.com/yeppao-org/smbdeck/internal/validate"
)

type accountData struct {
	Shares    []userShare
	Hosts     []string
	MinLength int
	Status    statusView
}

func (s *Server) renderAccount(w http.ResponseWriter, r *http.Request, status int, errs []string) {
	rc := reqCtxFrom(r)
	d := rc.state
	s.render(w, r, status, "account", &page{Title: "account.title", Nav: "account", Rev: d.Revision, Errors: errs,
		Data: accountData{Shares: sharesOf(d, rc.user.Name), Hosts: s.smbHosts(r),
			MinLength: s.cfg.PasswordMinLength, Status: s.agentStatus(d)}})
}

func (s *Server) handleAccount(w http.ResponseWriter, r *http.Request) {
	s.renderAccount(w, r, http.StatusOK, nil)
}

// handleAccountPassword lets anyone change their own password. The current
// password is required (and rate-limited like a login): a borrowed session
// alone cannot take over the account.
func (s *Server) handleAccountPassword(w http.ResponseWriter, r *http.Request) {
	rc := reqCtxFrom(r)
	now := s.now()
	key := "account:" + rc.user.Name + "|" + ipKey(rc.client.ip)
	if ok, _, _ := s.accountIPLimit.allow(key, now); !ok {
		s.renderAccount(w, r, http.StatusTooManyRequests, []string{"auth.too_many_short"})
		return
	}
	if !nthash.Verify(r.PostFormValue("current"), rc.user.NTHash) {
		s.accountIPLimit.fail(key, now)
		s.renderAccount(w, r, http.StatusUnauthorized, []string{"account.bad_current"})
		return
	}
	password := r.PostFormValue("password")
	if c := validate.Password(password, s.cfg.PasswordMinLength); c != validate.OK {
		s.renderAccount(w, r, http.StatusUnprocessableEntity, []string{"err." + string(c)})
		return
	}
	if password != r.PostFormValue("confirm") {
		s.renderAccount(w, r, http.StatusUnprocessableEntity, []string{"err." + string(validate.PasswordMismatch)})
		return
	}
	name := rc.user.Name
	changed := now.UTC()
	// No revision check: this change touches one field of one's own account
	// and cannot conflict with what an administrator changed meanwhile.
	d, err := s.store.Update(-1, func(d *state.Desired) error {
		u := d.User(name)
		if u == nil {
			return errNotFound
		}
		u.NTHash = nthash.Sum(password).String()
		u.PasswordChangedAt = changed
		return nil
	})
	if err != nil {
		s.renderAccount(w, r, http.StatusConflict, s.updateErrors(err))
		return
	}
	s.accountIPLimit.reset(key)
	// Other browsers signed in as this account are signed out; this one gets
	// a fresh session.
	s.sessions.deleteUser(name, nil)
	s.startSession(w, r, d.User(name))
	s.remember(r, name, audit.UserPasswordChanged, name, audit.OK)
	s.flashOK(r, "account.password_changed", "")
	http.Redirect(w, r, "/account", http.StatusSeeOther)
}

// apiStatus is what the live status indicator polls.
type apiStatus struct {
	State     string    `json:"state"`
	Desired   int64     `json:"desired"`
	Applied   int64     `json:"applied"`
	SMBD      bool      `json:"smbd"`
	Issues    int       `json:"issues"`
	UpdatedAt time.Time `json:"updatedAt"`
	Label     string    `json:"label"`
}

func (s *Server) handleAPIStatus(w http.ResponseWriter, r *http.Request) {
	rc := reqCtxFrom(r)
	st := s.agentStatus(rc.state)
	out := apiStatus{State: st.State, Desired: st.Desired, Applied: st.Applied, SMBD: st.SMBD,
		Issues: len(st.Issues), UpdatedAt: st.UpdatedAt, Label: rc.l.T("agent." + st.State)}
	if !rc.user.Admin {
		// Accounts that are not administrators learn whether their change was
		// applied, nothing about other elements.
		out.Issues = 0
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(out)
}
