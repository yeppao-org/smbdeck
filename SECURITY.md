# Security

## Reporting a vulnerability

Please report vulnerabilities privately, through GitHub's private
vulnerability reporting on this repository ("Security" tab, "Report a
vulnerability"). Do not open a public issue. You will get an answer within a
week; fixes are released as soon as they are ready, with credit if you wish.

## Threat model

smbdeck is meant for a home or small-office network: a trusted operator, a
few accounts, clients on the LAN or on an overlay network (Tailscale and
similar). It defends against:

- a visitor on an allowed network who has no account, or the wrong one;
- a signed-in account that is not an administrator;
- a malicious web page open in an administrator's browser (CSRF, framing);
- a value in the desired state that tries to change the meaning of
  `smb.conf`, or a path that tries to leave its root, including a desired
  state edited by hand, and links created on the shares;
- a compromised web console trying to take over the agent or the host: it
  holds no privilege, mounts no disk, and the agent believes nothing it
  writes (links, FIFOs, oversized or malformed files are refused).

It does not defend against a compromised host, a malicious administrator, or
someone who can read the state volume (see "What is secret" below).

**What the separation does not protect: the data on the shares.** The
console decides who may open what, and it holds the NT hashes, which are as
good as passwords for SMB. Whoever controls the console (or can write the
state volume) can give an account access to every share, or authenticate as
any account, including from inside the pod, to `127.0.0.1:445`. The
separation keeps such an attacker away from root, from the host, and from
anything outside the declared roots; it does not keep them away from what the
roots contain. Protect the console and the state volume accordingly.

## Separation of privileges

| Role | Privileges | Mounted |
|---|---|---|
| web | UID 10001, no capability, `no-new-privileges`, read-only root file system | the state volume; the status volume, read-only |
| agent | root reduced to `CHOWN FOWNER DAC_OVERRIDE SETUID SETGID NET_BIND_SERVICE`, `no-new-privileges`, read-only root file system | the state volume (it only reads it), the status volume, the share roots, a tmpfs |
| discovery | avahi as UID 86, wsdd2 as `nobody`, no capability, read-only root file system | a tmpfs |

The integration test checks on the running containers: for the console, its
UID, an empty `CapEff`, `NoNewPrivs`, no share root present or mounted, a
read-only root file system, a writable state volume and a read-only status
volume; for the agent, its exact `CapEff` (the six capabilities) and
`NoNewPrivs`. The agent's read-only root file system and the discovery role's
settings are set by the deployment files, not checked by the test.

The agent writes nothing in the state volume, which the console controls: its
reports (`status.json`, `tree.json`, the copy of the last applied state) go to
a volume of their own. It reads `desired.json` without following a link,
without blocking on a FIFO, from a regular file of at most 1 MiB, and decodes
it as a stream with bounded lists; a hostile file costs it neither memory nor
a hash of another file published in its status.

`SETUID`/`SETGID` let smbd switch to each account; `CHOWN`, `FOWNER` and
`DAC_OVERRIDE` let the agent manage Samba's private files and create share
folders for the file owner; `NET_BIND_SERVICE` binds port 445. The agent has
no `CAP_FSETID`, `CAP_SYS_ADMIN`, `CAP_NET_ADMIN` or `CAP_KILL`.

## The agent trusts nothing it reads

The web console validates input for the user's sake; the agent validates again
for safety, every time it reads the desired state, and applies only what
passes. Refused elements are reported by kind, index and code: no free text
from the desired state is echoed back.

- Account names: `^[a-z_][a-z0-9_-]{0,31}$`, not a system name (root, nobody,
  daemon, avahi, smbdeck…), not a name Samba reads as something else in
  `valid users` (anything starting with `s-` and a digit is read as a SID,
  `s-1-1-0` being Everyone; well-known names such as `everyone`, `users`,
  `guests`, `system`, `network` resolve to groups before local accounts),
  unique; UIDs in 20000–59999, unique and never handed out twice; NT hashes
  of exactly 32 hexadecimal characters. An account that collides with an
  entry of the image's `/etc/passwd` is refused.
- Share names: `^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$`, not `global`, `homes`,
  `printers`, `print$` or `ipc$`, unique without case.
- Paths: relative, cleaned, without `..`, `\`, `%` (Samba expands `%U`,
  `%$(VAR)`…), quotes, control characters, or leading and trailing spaces.
  They are resolved twice, independently, and must stay inside their root:
  with `filepath.EvalSymlinks` plus a prefix check, and through `os.Root`,
  which refuses traversal out of its directory by construction. A share path
  may not go through any symbolic link (only the root itself may be one): a
  link inside a share can be replaced by whoever writes there, and would point
  another share at a folder it was never meant to expose. Everything is
  re-validated every minute (`SMBDECK_RESYNC_INTERVAL`), since links can
  change on disk; Samba itself runs with `wide links = no`.
- `smb.conf` is written by a generator that refuses, whatever its origin, any
  value with a line break or control character, a trailing backslash (line
  continuation), a `%`, or a leading `;`, `#` or `[`. A share that no account
  may open is left out: an empty `valid users` would let every account in.
- Folders created on request are made component by component, each opened
  relative to its parent's descriptor without following links, and their
  owner and mode are set on their own descriptor. If the owner cannot be set
  (exFAT, NTFS), the new folder is removed and the share reported, rather than
  published with the wrong owner at the next pass.
- When `desired.json` cannot be used (unreadable, missing after it existed,
  another schema version), the agent keeps the last state it applied, also
  across restarts, and reports why.

## The web console

- **Sign-in** uses the Samba accounts. The NT hash is compared in constant
  time; an unknown account is compared against a dummy hash, so timing does
  not reveal which accounts exist.
- **Sessions** live in memory only (a restart signs everyone out): a random
  32-byte token, of which the server keeps only the SHA-256; cookie
  `HttpOnly`, `SameSite=Strict`, `Secure` and `__Host-` prefixed over HTTPS.
  12 hours at most, 2 hours idle; the status polling of an open page does not
  count as activity. A session ends when its account is disabled, deleted or
  given a new password, wherever the change came from.
- **CSRF**: every write carries a per-session token, checked in constant time;
  sign-in and setup use a double-submit token. Independently, Go's
  cross-origin protection refuses writes whose `Sec-Fetch-Site` or `Origin`
  says another site.
- **Sign-in limits** that a third party cannot turn into a lockout: a hard
  lock per address (IPv6 per /64) and per (account, address) pair, after a
  few free attempts, with a doubling wait up to 15 minutes; for the account as
  a whole, only a slowdown (up to 2 seconds per attempt). A browser that
  signed in to the account before carries a signed device cookie (180 days)
  and is judged on its own record only, so an attacker failing on purpose,
  even from the same address, does not lock it out. A flood of new names
  cannot evict an active lock. Each lock is journaled once (`login.blocked`).
  Residual risk: someone behind the same address as an administrator (NAT)
  who has never signed in from this browser can make that administrator wait
  up to 15 minutes; and guessing from many addresses is only slowed down.
- **Allowed networks**: requests from elsewhere get 403 before any handler
  runs. `X-Forwarded-For` and `X-Forwarded-Proto` are ignored unless the peer
  is in `SMBDECK_TRUSTED_PROXIES`; the client is then the rightmost address
  that is not a trusted proxy, and a hop that cannot be read refuses the
  request. Behind Docker's userland proxy or a Kubernetes Service with
  `externalTrafficPolicy: Cluster`, the console sees a gateway or node
  address: the deployment files publish on an explicit address and default
  to `Local`, and the chart refuses an ingress without trusted proxies.
- **Host header**: the console answers only to IP addresses, `localhost` and
  the names in `SMBDECK_ALLOWED_HOSTS` (421 otherwise), so a page on an
  attacker's name that resolves to the console (DNS rebinding) gets nothing.
- **Headers**: `Content-Security-Policy: default-src 'none'; script-src
  'self'; style-src 'self'; …; frame-ancestors 'none'` (no inline script or
  style anywhere), `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`,
  `Referrer-Policy: same-origin`, `Permissions-Policy`, `Cross-Origin-Opener-
  Policy`, `Cross-Origin-Resource-Policy`, `Cache-Control: no-store` on pages,
  and `Strict-Transport-Security` over HTTPS.
  The referrer policy is `same-origin` rather than `no-referrer` on purpose:
  with `no-referrer`, browsers send `Origin: null` on form posts over plain
  HTTP, which would defeat the origin check (and refuse every sign-in). With
  `same-origin`, no referrer ever leaves the site.
- **First administrator**: without any state, the setup page works once and
  asks for a random code printed in the web container's logs, so that someone
  else on the network cannot claim the server first.
- **Optimistic concurrency**: every write states the revision it was based
  on; a stale form is refused rather than overwriting someone else's change.
- **Journal**: who, what, when and from which address; never a password or a
  hash. A failed sign-in records the account only if it exists (people
  sometimes type their password in the name field). The file is bounded.
- **Passwords**: 12 characters at least by default; generated ones are 20
  characters from 56 (about 116 bits), shown once and kept nowhere.

## Samba

`smb.conf` asks for SMB 2.1 at least, offers encryption, requires signing
(`SMBDECK_SMB_SIGNING=auto` relaxes it for very old clients), turns SMB1 and
SMB3 POSIX extensions off, refuses guests and anonymous listing, keeps
`wide links = no`, and refuses password changes requested by SMB clients
(`check password script = /bin/false`): passwords come from the desired
state only. A disabled, deleted or re-keyed account, or one whose access
shrank, moved or went from read-only to read-write (Samba fixes the write
right when the client connects), loses its open sessions, found by UID
through `smbstatus` and closed with `smbcontrol`; a failure is retried at the
next pass.

## What is secret

Samba authenticates SMB clients with NTLM, which needs the **NT hash** of each
password (MD4 over UTF-16LE, unsalted). smbdeck stores that hash and never the
password. The NT hash is **equivalent to the password for SMB**: whoever reads
it can authenticate as that account. Hence:

- `desired.json` is written with mode 0600, owned by the web console's UID
  (in the image, `/state` is a 0700 directory); the agent's `smbpasswd` file
  is 0600 in a 0700 directory on a tmpfs.
- Back up the state volume as you would back up passwords, and restrict who
  can read it (on Kubernetes, who can exec into the pod or read the PVC).
- An NT hash also reveals weak passwords to an offline dictionary attack:
  hence the length policy and the generator.

Seed password files (`SMBDECK_SEED_PASSWORDS_DIR`) are read once, hashed, and
never copied; you may delete them after the first start.

## Known limits

- Over plain HTTP, credentials cross the network in clear text. Use HTTPS
  (`SMBDECK_TLS_CERT`, or a reverse proxy declared in
  `SMBDECK_TRUSTED_PROXIES`) or an encrypted overlay network.
- SMB encryption is offered (`server smb encrypt = desired`), not required:
  old clients still connect, unencrypted.
- A share inside another share: an account with write access to the outer one
  can replace the inner folder with a link. The agent refuses the inner share
  at its next pass, but until then (one minute by default,
  `SMBDECK_RESYNC_INTERVAL`) new connections to it follow the link. Avoid
  nesting shares that different accounts can write, or lower the interval.
- The web console keeps sessions in memory: run one replica.
- wsdd2's upstream repository no longer exists; the image builds it from the
  original tarball kept by the Debian archive, checked by SHA-256.
- Seed passwords shorter than the policy are accepted (to carry an existing
  password over) with a warning in the logs.
