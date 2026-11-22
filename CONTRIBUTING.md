# Contributing

Thanks for your interest. smbdeck stays small on purpose: a change is welcome
when it keeps the console simple, the privileges separated, and every value
validated by the agent.

## Setup

Only Docker is required. Every tool runs in a container pinned by digest (see
the `Makefile`); Go modules and the build cache live in one named volume,
`smbdeck-gomod` (`make clean-cache` removes it).

```bash
make test               # unit tests with the race detector
make lint               # golangci-lint (configuration: .golangci.yml)
make fmt                # gofmt
make image              # build smbdeck:dev for your platform
make test-integration   # real Samba in Docker, driven through the console
make demo               # http://localhost:8080 with fake accounts; make demo-down
make screenshots        # regenerate docs/screenshots from a fresh demo
make helm-lint          # lint and render the Helm chart
```

`make test-integration` needs the image (`make image` first). It starts the
agent and the console with the production privileges, checks them, then runs
`test/integration` (build tag `integration`) in a Go container on the same
network, with `smbclient`. Everything it creates is removed at the end.

## Layout

| Path | |
|---|---|
| `cmd/smbdeck` | the binary and its sub-commands |
| `internal/state` | the files shared by the roles, the atomic store |
| `internal/validate` | every rule a value must pass; the agent's checks |
| `internal/smbconf` | the `smb.conf` generator |
| `internal/agent` | accounts, `smbpasswd`, smbd supervision, sessions, folder tree |
| `internal/web` | the console: handlers, sessions, security, templates, CSS, JS |
| `internal/i18n` | the English and French catalogs |
| `internal/discovery` | avahi and wsdd2 configuration |
| `deploy/` | Compose example, demo, Helm chart |

## Rules

- **The agent validates everything it reads**, even what the console already
  checked. A new field in the desired state needs a rule in
  `internal/validate`, a test that feeds it hostile values (line breaks, `[`,
  `;`, `#`, `%`, `..`, links), and, if it reaches `smb.conf`, a check in the
  generator.
- **The console stays unprivileged** and never mounts a disk.
- **No text in templates.** Every string is a catalog key, present in both
  `en.json` and `fr.json` (`TestTemplatesHaveNoHardcodedText`,
  `TestCatalogsMatch` and `TestEveryKeyInUseExists` enforce it). Errors are
  codes, translated as `err.<code>`.
- **No inline script or style**: the Content Security Policy forbids them.
  The JavaScript is progressive enhancement only; every page must work
  without it.
- **Dependencies**: the standard library first. A new module needs a reason in
  the pull request.
- **Tests describe rules, not the current state**, and a new rule is seen
  failing before it is fixed.
- Accessibility: keyboard reachable, visible focus, labels, AA contrast in
  both themes, `prefers-reduced-motion` respected.

## Commits and pull requests

Small, focused commits with a message that says why. Run `make lint test`
before pushing; CI also runs the integration test, the Helm checks, a
multi-arch build and Trivy.

## Security issues

Do not open a public issue: see [SECURITY.md](SECURITY.md).
