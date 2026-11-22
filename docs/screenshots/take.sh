#!/usr/bin/env bash
# Takes the README screenshots from a fresh local demo (fake data only), then
# removes the demo. The Playwright image carries the browsers; the Python
# package of the same version is installed in a throwaway directory.
set -euo pipefail
cd "$(dirname "$0")/../.."
SHOTS_IMAGE=${SHOTS_IMAGE:-mcr.microsoft.com/playwright/python:v1.64.1-noble@sha256:330d401ae23c905896a0c26c66c36fc971b621519e7b11b435a8328d7bf6e031}
./deploy/compose/demo/demo.sh down >/dev/null 2>&1 || true
./deploy/compose/demo/demo.sh up
trap './deploy/compose/demo/demo.sh down' EXIT
docker run --rm --network smbdeck-demo_default --memory=1g --shm-size=512m \
  -v "$PWD/docs/screenshots":/work:ro -v "$PWD/docs/screenshots":/out \
  -e UPSTREAM_HOST=web -e UPSTREAM_PORT=8080 -e OUT=/out \
  "$SHOTS_IMAGE" sh -c 'pip install -q --disable-pip-version-check --target /tmp/pw playwright==1.64.1 && PYTHONPATH=/tmp/pw python3 /work/take.py'
