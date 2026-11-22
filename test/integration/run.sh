#!/usr/bin/env bash
# Integration test: a real Samba in Docker, driven through the web console.
#
#   agent    the image's agent role, with the capabilities and file system
#            restrictions documented in README.md
#   web      the image's web role: non-root, no capability, read-only, and
#            nothing but the state volume mounted
#   driver   a Go test (test/integration, build tag "integration") that uses
#            the console over HTTP (CSRF included) and checks the result with
#            smbclient
#
# Everything is created under a unique prefix and removed on exit, whatever
# happens. Requires Docker only.
set -euo pipefail

cd "$(dirname "$0")/../.."
IMAGE=${IMAGE:-smbdeck:dev}
GO_IMAGE=${GO_IMAGE:-golang:1.27.4-alpine3.24@sha256:70bd7ddea8b6cbe5d6943cde279d6b67feb10cc924fb9100d1d8757c1575b280}
ALPINE_IMAGE=${ALPINE_IMAGE:-alpine:3.24.3@sha256:b3413572228e34bd1c9245f5565e6cd127005655e8a7899aef33d8e83255c9e6}
GO_CACHE=${GO_CACHE:-smbdeck-gomod}
ID="smbdeck-it-$$"
NET="$ID" STATE="$ID-state" STATUS="$ID-status" ROOT="$ID-root"

log() { printf '\n== %s\n' "$*"; }
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }

cleanup() {
  status=$?
  if [ "$status" -ne 0 ]; then
    log "agent logs"; docker logs "$ID-agent" 2>&1 | tail -40 || true
    log "web logs"; docker logs "$ID-web" 2>&1 | tail -20 || true
  fi
  docker rm -f "$ID-driver" "$ID-agent" "$ID-web" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
  docker volume rm "$STATE" "$STATUS" "$ROOT" >/dev/null 2>&1 || true
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

docker image inspect "$IMAGE" >/dev/null 2>&1 || fail "image $IMAGE not found: run 'make image' first"

log "network and volumes"
docker network create "$NET" >/dev/null
docker volume create "$STATE" >/dev/null
docker volume create "$STATUS" >/dev/null
docker volume create "$ROOT" >/dev/null
# The share root: folders owned by the file owner (1000:1000), a file to read,
# and a link that leads out of the root.
docker run --rm --memory=128m -v "$ROOT":/r "$ALPINE_IMAGE" sh -c '
  mkdir -p /r/data /r/readonly /r/media/films &&
  echo hello > /r/readonly/file.txt &&
  ln -s /etc /r/escape &&
  ln -s readonly /r/inner-link &&
  chown -R 1000:1000 /r'

log "agent"
docker run -d --name "$ID-agent" --network "$NET" --network-alias smb \
  --user 0:0 --read-only --tmpfs /run/smbdeck:size=64m --tmpfs /tmp:size=16m \
  --cap-drop ALL --cap-add CHOWN --cap-add FOWNER --cap-add DAC_OVERRIDE \
  --cap-add SETUID --cap-add SETGID --cap-add NET_BIND_SERVICE \
  --security-opt no-new-privileges --memory=512m --pids-limit=256 \
  -e SMBDECK_ROOTS=drive1=/roots/drive1 -e SMBDECK_FILES_UID=1000 -e SMBDECK_FILES_GID=1000 \
  -e SMBDECK_POLL_INTERVAL=300ms \
  -v "$STATE":/state:ro -v "$STATUS":/status -v "$ROOT":/roots/drive1 \
  "$IMAGE" agent >/dev/null

log "web"
docker run -d --name "$ID-web" --network "$NET" --network-alias web \
  --read-only --tmpfs /tmp:size=8m --cap-drop ALL --security-opt no-new-privileges \
  --memory=256m --pids-limit=128 \
  -e SMBDECK_ALLOWED_HOSTS=web \
  -v "$STATE":/state -v "$STATUS":/status:ro \
  "$IMAGE" web >/dev/null

for _ in $(seq 1 50); do
  code=$(docker logs "$ID-web" 2>&1 | sed -n 's/.*setupCode=\([A-Z0-9-]*\).*/\1/p' | tail -1)
  [ -n "$code" ] && break
  sleep 0.2
done
[ -n "${code:-}" ] || fail "no setup code in the web logs"

log "the web container: not root, no capability, read-only, no disk"
docker exec "$ID-web" sh -c 'test "$(id -u)" = 10001' || fail "web runs as $(docker exec "$ID-web" id -u)"
docker exec "$ID-web" sh -c 'grep -Eq "^CapEff:[[:space:]]+0+$" /proc/self/status' || fail "web has capabilities"
docker exec "$ID-web" sh -c 'grep -Eq "^NoNewPrivs:[[:space:]]+1$" /proc/self/status' || fail "web may gain privileges"
docker exec "$ID-web" sh -c 'test ! -e /roots/drive1' || fail "web sees the share root"
docker exec "$ID-web" sh -c '! grep -q " /roots" /proc/self/mountinfo' || fail "a root is mounted in web"
docker exec "$ID-web" sh -c '! touch /usr/local/bin/x 2>/dev/null' || fail "web root file system is writable"
docker exec "$ID-web" sh -c 'test -w /state' || fail "web cannot write the state"
docker exec "$ID-web" sh -c '! touch /status/x 2>/dev/null' || fail "web can write the agent's reports"

log "the agent container: reduced root"
caps=$(docker exec "$ID-agent" sh -c 'sed -n "s/^CapEff:[[:space:]]*//p" /proc/1/status')
# CHOWN(0) DAC_OVERRIDE(1) FOWNER(3) SETGID(6) SETUID(7) NET_BIND_SERVICE(10)
[ "$caps" = "00000000000004cb" ] || fail "agent capabilities are $caps, want 00000000000004cb"
docker exec "$ID-agent" sh -c 'grep -Eq "^NoNewPrivs:[[:space:]]+1$" /proc/1/status' || fail "agent may gain privileges"
docker exec "$ID-agent" sh -c '! touch /state/x 2>/dev/null' || fail "agent can write the state"

# The user and group names of the image, which the agent starts from (the
# files in /etc are links into a directory that only exists in the agent).
IMAGE_NAMES=$(docker run --rm --memory=64m --entrypoint cut "$IMAGE" -d: -f1 /usr/share/smbdeck/passwd /usr/share/smbdeck/group)

log "driver: HTTP and SMB"
docker run --rm --name "$ID-driver" --network "$NET" --memory=1536m --cpus=2 \
  -v "$PWD":/src:ro -w /src \
  -v "$GO_CACHE":/cache -e GOMODCACHE=/cache/mod -e GOCACHE=/cache/build \
  -e GOFLAGS="-buildvcs=false -mod=readonly" -e GOTOOLCHAIN=local \
  -v "$STATE":/state -v "$STATUS":/status:ro -v "$ROOT":/roots-ro:ro \
  -e SMBDECK_IT_WEB=http://web:8080 -e SMBDECK_IT_SMB=smb -e SMBDECK_IT_STATE=/state -e SMBDECK_IT_STATUS=/status \
  -e SMBDECK_IT_ROOT=/roots-ro -e SMBDECK_IT_SETUP_CODE="$code" -e SMBDECK_IT_IMAGE_NAMES="$IMAGE_NAMES" \
  "$GO_IMAGE" sh -c 'apk add --no-cache -q samba-client samba-common-tools >/dev/null && go test -tags integration -count=1 -v -timeout 5m ./test/integration/'

log "agent still healthy"
docker exec "$ID-agent" /usr/local/bin/smbdeck healthcheck || fail "agent health check"
docker exec "$ID-web" /usr/local/bin/smbdeck healthcheck || fail "web health check"

log "OK"
