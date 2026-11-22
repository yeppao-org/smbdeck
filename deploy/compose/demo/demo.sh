#!/usr/bin/env bash
# Local demo with fake accounts: ./demo.sh up | down
set -euo pipefail
cd "$(dirname "$0")"
export IMAGE=${IMAGE:-smbdeck:dev}
project=smbdeck-demo
case "${1:-up}" in
  up)
    docker image inspect "$IMAGE" >/dev/null 2>&1 || { echo "image $IMAGE not found: run 'make image' first" >&2; exit 1; }
    docker compose -p "$project" -f compose.yml up -d --wait
    cat <<MSG

smbdeck demo running (fake data only).
  Console  http://localhost:8080   admin / demo-admin-password
                                   alice / demo-alice-password (not an administrator)
  SMB      smbclient -p 1445 //127.0.0.1/Photos -U alice
Stop and remove everything: make demo-down
MSG
    ;;
  down)
    docker compose -p "$project" -f compose.yml down -v --remove-orphans
    ;;
  *)
    echo "usage: $0 up|down" >&2
    exit 2
    ;;
esac
