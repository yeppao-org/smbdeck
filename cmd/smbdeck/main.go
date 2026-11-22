// Command smbdeck is a small, container-first web console for Samba.
//
// One binary, three roles, each in its own container:
//
//	smbdeck web                   the console (unprivileged, no disk mounted)
//	smbdeck agent                 runs smbd and applies the desired state (reduced root)
//	smbdeck discovery [mode]      mDNS and WS-Discovery announcements (unprivileged, host network)
//
// and two helpers:
//
//	smbdeck healthcheck           used by the image's HEALTHCHECK
//	smbdeck version
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	_ "time/tzdata" // time zones without the system's tzdata: TZ=Europe/Paris works in the image

	"github.com/yeppao-org/smbdeck/internal/agent"
	"github.com/yeppao-org/smbdeck/internal/config"
	"github.com/yeppao-org/smbdeck/internal/discovery"
	"github.com/yeppao-org/smbdeck/internal/state"
	"github.com/yeppao-org/smbdeck/internal/web"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

const usage = `usage: smbdeck <command>

commands:
  web                     serve the console (unprivileged)
  agent                   run smbd and apply the desired state (reduced root)
  discovery [mdns|wsd|all]  announce the server on the local network (default: all)
  healthcheck             check the role running in this container
  version                 print the version

Configuration comes from SMBDECK_* environment variables: see README.md.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	var err error
	switch os.Args[1] {
	case "web":
		err = runWeb(ctx)
	case "agent":
		err = runAgent(ctx)
	case "discovery":
		mode := discovery.ModeAll
		if len(os.Args) > 2 {
			mode = os.Args[2]
		}
		err = runDiscovery(ctx, mode)
	case "healthcheck":
		err = healthcheck()
	case "version", "--version", "-v":
		fmt.Println(version)
	case "help", "--help", "-h":
		fmt.Print(usage)
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "smbdeck:", err)
		os.Exit(1)
	}
}

func runWeb(ctx context.Context) error {
	log, err := config.Logger(config.OS, "web")
	if err != nil {
		return err
	}
	if os.Geteuid() == 0 {
		return fmt.Errorf("the web role refuses to run as root: run it as an unprivileged user (the image uses 10001)")
	}
	cfg, err := web.FromEnv(config.OS)
	if err != nil {
		return err
	}
	srv, err := web.New(cfg, log, version)
	if err != nil {
		return err
	}
	return srv.ListenAndServe(ctx)
}

func runAgent(ctx context.Context) error {
	log, err := config.Logger(config.OS, "agent")
	if err != nil {
		return err
	}
	cfg, err := agent.FromEnv(config.OS)
	if err != nil {
		return err
	}
	a, err := agent.New(cfg, log, version)
	if err != nil {
		return err
	}
	return a.Run(ctx)
}

func runDiscovery(ctx context.Context, mode string) error {
	log, err := config.Logger(config.OS, "discovery")
	if err != nil {
		return err
	}
	if os.Geteuid() == 0 {
		return fmt.Errorf("the discovery role refuses to run as root: run avahi as UID 86 and wsdd2 as nobody (see README.md)")
	}
	cfg, err := discovery.FromEnv(config.OS, mode)
	if err != nil {
		return err
	}
	return discovery.Run(ctx, cfg, log)
}

// healthcheck checks whatever role this container runs, found from the
// command line of PID 1 (tini, then smbdeck <role>) or SMBDECK_ROLE.
func healthcheck() error {
	role := os.Getenv("SMBDECK_ROLE")
	if role == "" {
		if raw, err := os.ReadFile("/proc/1/cmdline"); err == nil {
			args := strings.Split(string(bytes.TrimRight(raw, "\x00")), "\x00")
			for i, a := range args {
				if filepath.Base(a) == "smbdeck" && i+1 < len(args) {
					role = args[i+1]
				}
			}
		}
	}
	switch role {
	case "web":
		return checkWeb()
	case "agent":
		return checkAgent()
	case "discovery":
		return nil
	default:
		return fmt.Errorf("cannot tell which role runs here (set SMBDECK_ROLE)")
	}
}

// checkAgent: smbd answers, and the agent wrote its status recently.
func checkAgent() error {
	conn, err := net.DialTimeout("tcp", "127.0.0.1:445", 3*time.Second)
	if err != nil {
		return fmt.Errorf("smbd not reachable: %w", err)
	}
	_ = conn.Close()
	st, err := state.ReadStatus(config.OS.String("SMBDECK_STATUS_DIR", "/status"))
	if err != nil {
		return fmt.Errorf("status: %w", err)
	}
	if age := time.Since(st.UpdatedAt); age > 3*time.Minute {
		return fmt.Errorf("status not refreshed for %s", age.Round(time.Second))
	}
	return nil
}

// checkWeb calls /healthz where the console listens (SMBDECK_LISTEN): on the
// given address, or on the loopback when it listens on every address.
func checkWeb() error {
	listen := config.OS.String("SMBDECK_LISTEN", ":8080")
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return err
	}
	if ip := net.ParseIP(host); host == "" || (ip != nil && ip.IsUnspecified()) {
		host = "127.0.0.1"
	}
	scheme := "http"
	client := &http.Client{Timeout: 3 * time.Second}
	if config.OS.String("SMBDECK_TLS_CERT", "") != "" {
		scheme = "https"
		// Our own process: the certificate names the public host, not this one.
		client.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}} //nolint:gosec
	}
	resp, err := client.Get(scheme + "://" + net.JoinHostPort(host, port) + "/healthz")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("healthz: %s", resp.Status)
	}
	return nil
}
