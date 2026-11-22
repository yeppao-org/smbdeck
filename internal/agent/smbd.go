package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// supervisor runs smbd in the foreground and restarts it when it exits, with
// a growing delay.
type supervisor struct {
	path, configFile string
	log              *slog.Logger
	stdout, stderr   io.Writer
	// changed receives a signal whenever smbd starts or stops.
	changed chan struct{}

	mu       sync.Mutex
	running  bool
	since    time.Time
	restarts int
	pid      int
}

func (s *supervisor) snapshot() (running bool, since time.Time, restarts int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.running, s.since, s.restarts
}

func (s *supervisor) mainPID() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.pid
}

// run blocks until ctx ends, then stops smbd and waits for it.
func (s *supervisor) run(ctx context.Context) {
	backoff := time.Second
	for {
		started := time.Now()
		err := s.once(ctx)
		if ctx.Err() != nil {
			return
		}
		s.log.Error("smbd exited, restarting", "err", err, "delay", backoff)
		s.mu.Lock()
		s.restarts++
		s.mu.Unlock()
		if time.Since(started) > time.Minute {
			backoff = time.Second
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff = min(2*backoff, 30*time.Second)
	}
}

func (s *supervisor) once(ctx context.Context) error {
	cmd := exec.Command(s.path, //nolint:gosec // G204: fixed program path from the configuration
		"--foreground", "--no-process-group", "--debug-stdout",
		"--configfile="+s.configFile)
	cmd.Stdout, cmd.Stderr = s.stdout, s.stderr
	// smbd starts with an empty environment: nothing from the agent's
	// configuration leaks to it or to the processes it forks.
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	if err := cmd.Start(); err != nil {
		return err
	}
	s.mu.Lock()
	s.running, s.since, s.pid = true, time.Now(), cmd.Process.Pid
	s.mu.Unlock()
	s.log.Info("smbd started", "pid", cmd.Process.Pid)
	s.notify()

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	var err error
	select {
	case err = <-done:
	case <-ctx.Done():
		_ = cmd.Process.Signal(syscall.SIGTERM)
		select {
		case err = <-done:
		case <-time.After(10 * time.Second):
			_ = cmd.Process.Kill()
			err = <-done
		}
	}
	s.mu.Lock()
	s.running, s.pid = false, 0
	s.mu.Unlock()
	s.notify()
	return err
}

func (s *supervisor) notify() {
	select {
	case s.changed <- struct{}{}:
	default:
	}
}

// samba runs Samba's control programs.
type samba struct {
	smbcontrol, smbstatus, configFile string
	log                               *slog.Logger
}

func (b samba) command(ctx context.Context, name string, args ...string) *exec.Cmd {
	//nolint:gosec // G204: fixed program paths; arguments are constants or PIDs from smbstatus
	cmd := exec.CommandContext(ctx, name, append([]string{"--configfile=" + b.configFile}, args...)...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	return cmd
}

// reload asks smbd to read smb.conf again.
func (b samba) reload(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	out, err := b.command(ctx, b.smbcontrol, "smbd", "reload-config").CombinedOutput()
	if err != nil {
		return fmt.Errorf("smbcontrol reload-config: %w: %s", err, firstLine(out))
	}
	return nil
}

// smbstatusOutput is the part of `smbstatus --json` the agent reads. The
// session's "username" comes from the UID through /etc/passwd: once an
// account is removed, it is the UID in digits. Sessions are therefore
// matched on "uid".
type smbstatusOutput struct {
	Sessions map[string]struct {
		UID      int `json:"uid"`
		ServerID struct {
			PID string `json:"pid"`
		} `json:"server_id"`
	} `json:"sessions"`
}

// sessionPIDs returns, for each UID in accounts, the smbd processes serving
// its sessions.
func sessionPIDs(data []byte, accounts map[int]string) (map[int][]int, error) {
	var out smbstatusOutput
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	pids := map[int][]int{}
	for _, s := range out.Sessions {
		if _, want := accounts[s.UID]; !want {
			continue
		}
		pid, err := strconv.Atoi(s.ServerID.PID)
		if err != nil || pid <= 1 {
			continue
		}
		pids[s.UID] = append(pids[s.UID], pid)
	}
	return pids, nil
}

// closeSessions ends every SMB session of the given accounts (UID to name).
// Each session lives in its own smbd process, which is asked to shut down
// (smbcontrol shutdown); only if that fails is it sent SIGTERM, and never the
// main smbd process. Clients reconnect and must authenticate again against
// what the desired state now says.
func (b samba) closeSessions(ctx context.Context, accounts map[int]string, mainPID int) error {
	if len(accounts) == 0 {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	out, err := b.command(ctx, b.smbstatus, "--json").Output()
	if err != nil {
		return fmt.Errorf("smbstatus: %w", err)
	}
	pids, err := sessionPIDs(out, accounts)
	if err != nil {
		return fmt.Errorf("smbstatus output: %w", err)
	}
	for uid, list := range pids {
		for _, pid := range list {
			if pid == mainPID {
				continue
			}
			if cerr := b.command(ctx, b.smbcontrol, strconv.Itoa(pid), "shutdown").Run(); cerr != nil {
				b.log.Warn("smbcontrol shutdown failed, sending SIGTERM", "pid", pid, "err", cerr)
				if isSMBD(pid) {
					_ = syscall.Kill(pid, syscall.SIGTERM)
				}
			}
			b.log.Info("closed SMB session", "user", accounts[uid], "uid", uid, "pid", pid)
		}
	}
	return nil
}

// isSMBD reports whether pid is an smbd process.
func isSMBD(pid int) bool {
	comm, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/comm")
	return err == nil && strings.HasPrefix(string(comm), "smbd")
}

func firstLine(b []byte) string {
	for i, c := range b {
		if c == '\n' {
			return string(b[:i])
		}
	}
	if len(b) > 200 {
		b = b[:200]
	}
	return string(b)
}
