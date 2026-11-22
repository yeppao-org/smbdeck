# Changelog

All notable changes are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] - 2026-11-22

### Added

- First version: one image with three roles.
  - `web`: the console, unprivileged, with nothing but the state volume
    mounted. Sign-in with Samba accounts; accounts, shares, per-account read
    or write access, Time Machine destinations, folder picker, journal,
    "My account" for accounts that are not administrators; English and
    French; light and dark themes.
  - `agent`: runs smbd with reduced root privileges, validates the desired
    state again and applies what passes, closes the SMB sessions of accounts
    that lose access or whose access goes from read-only to read-write (the
    client reconnects and gets the write right at once), reports refused
    elements by code.
  - `discovery`: mDNS/Bonjour (avahi) and WS-Discovery (wsdd2), unprivileged.
- First administrator through a one-time setup page protected by a code from
  the logs, or a seed file with password files.
- Docker Compose example and demo, Helm chart.
- Unit tests, HTTP tests of the console, and an integration test with a real
  Samba in Docker.

### Security

Fixes from the first review, each with a test that failed before:

- The SMB sessions of a deleted account are closed (they were looked up by
  name, which smbstatus no longer knows once the account is gone).
- The agent writes its reports to its own directory, read-only for the
  console, and reads `desired.json` without following links or blocking on
  FIFOs, 1 MiB at most, with bounded lists.
- The agent mounts the state read-only (Compose files, Helm chart and
  integration test): it only ever reads `desired.json`, and the integration
  test checks that a write to `/state` from the agent fails.
- Account names Samba reads as SIDs or well-known groups (`s-1-1-0`,
  `everyone`, `users`…) are reserved: they opened shares to every account.
- Sign-in limits per (account, address) and per address, a slowdown only per
  account, and device cookies: a third party can no longer lock the
  administrator out. Lockouts are journaled.
- Unreadable `X-Forwarded-For` hops are refused; the `Host` header is
  checked (DNS rebinding); HSTS over HTTPS.
- SMB signing required, SMB3 POSIX extensions off, password changes over SMB
  refused.
- Share folders are created through descriptors, never through a link.

### Fixed

- The agent keeps the last applied state when `desired.json` is unreadable,
  missing or from another version, also across restarts, and smbd always
  starts.
- Status polling no longer keeps idle sessions alive; oversized requests get
  413; one's own password change no longer fails on unrelated changes; times
  show their zone; UIDs are never reused; the folder tree is breadth first;
  confirmations and the folder picker work without JavaScript; contrast of
  disabled items in the light theme.
