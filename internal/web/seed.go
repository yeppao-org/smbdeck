package web

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/yeppao-org/smbdeck/internal/audit"
	"github.com/yeppao-org/smbdeck/internal/fsutil"
	"github.com/yeppao-org/smbdeck/internal/nthash"
	"github.com/yeppao-org/smbdeck/internal/state"
	"github.com/yeppao-org/smbdeck/internal/validate"
)

// seedFile is the format of SMBDECK_SEED_FILE: initial accounts and shares.
// Passwords are not in it: each comes from <SMBDECK_SEED_PASSWORDS_DIR>/<name>
// (one file per account, for example a mounted Kubernetes Secret), is hashed,
// and is never stored.
type seedFile struct {
	Users []struct {
		Name     string `json:"name"`
		Admin    bool   `json:"admin"`
		Disabled bool   `json:"disabled"`
	} `json:"users"`
	Shares []struct {
		Name         string                  `json:"name"`
		Root         string                  `json:"root"`
		Path         string                  `json:"path"`
		CreateFolder bool                    `json:"createFolder"`
		TimeMachine  state.TimeMachine       `json:"timeMachine"`
		Access       map[string]state.Access `json:"access"`
	} `json:"shares"`
}

// seed writes the first desired state from the seed file. It runs only when
// no desired state exists; afterwards the seed is ignored.
func (s *Server) seed() error {
	data, err := fsutil.ReadConfig(s.cfg.SeedFile, 1<<20)
	if err != nil {
		return err
	}
	var sf seedFile
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&sf); err != nil {
		return fmt.Errorf("%s: %w", s.cfg.SeedFile, err)
	}
	now := s.now().UTC()
	d := &state.Desired{SchemaVersion: state.SchemaVersion, Users: []state.User{}, Shares: []state.Share{}}
	for _, su := range sf.Users {
		if c := validate.UserName(su.Name); c != validate.OK {
			return fmt.Errorf("account %q: %s", su.Name, c)
		}
		pw, err := readSeedPassword(s.cfg.SeedPasswordsDir, su.Name)
		if err != nil {
			return err
		}
		if !nthash.Valid(pw) || pw == "" {
			return fmt.Errorf("account %s: the password file is empty or not valid UTF-8", su.Name)
		}
		if c := validate.Password(pw, s.cfg.PasswordMinLength); c != validate.OK {
			// Accepted, so an existing password can be carried over, but said.
			s.log.Warn("seed password does not meet the policy; change it from the console", "user", su.Name, "code", string(c))
		}
		d.Users = append(d.Users, state.User{Name: su.Name, UID: d.AllocUID(), NTHash: nthash.Sum(pw).String(),
			Admin: su.Admin, Disabled: su.Disabled, CreatedAt: now, PasswordChangedAt: now})
	}
	for _, ss := range sf.Shares {
		d.Shares = append(d.Shares, state.Share{Name: ss.Name, Root: ss.Root, Path: ss.Path,
			CreateFolder: ss.CreateFolder, TimeMachine: ss.TimeMachine, Access: ss.Access})
	}
	// The seed must be fully valid (roots are checked by the agent, which
	// reports unknown ones).
	report := validate.Check(d, nil)
	if report.HasIssues() {
		var codes []string
		for _, is := range report.Issues {
			codes = append(codes, fmt.Sprintf("%s #%d %s: %s", is.Kind, is.Index, is.Field, is.Code))
		}
		if report.Fatal != validate.OK {
			codes = append(codes, string(report.Fatal))
		}
		return errors.New(strings.Join(codes, "; "))
	}
	if _, err := s.store.Create(d); err != nil {
		return err
	}
	if err := s.audit.Append(audit.Entry{Time: now, Actor: "seed", Action: audit.SeedApplied, Result: audit.OK}); err != nil {
		s.log.Error("audit", "err", err)
	}
	s.log.Info("desired state seeded", "users", len(d.Users), "shares", len(d.Shares))
	return nil
}

func readSeedPassword(dir, name string) (string, error) {
	data, err := fsutil.ReadConfig(filepath.Join(dir, name), 4096)
	if errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("account %s: no password file %s", name, filepath.Join(dir, name))
	}
	if err != nil {
		return "", err
	}
	// One trailing newline (as written by echo or most editors) is not part
	// of the password.
	pw := strings.TrimSuffix(string(data), "\n")
	pw = strings.TrimSuffix(pw, "\r")
	return pw, nil
}
