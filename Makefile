# Everything runs in containers: the only requirement on the host is Docker.
#
#   make test               unit tests with the race detector
#   make lint               golangci-lint
#   make vulncheck          govulncheck (known vulnerabilities in the code paths used)
#   make image              build the image (local platform)
#   make test-integration   real Samba in Docker, driven through the web UI
#   make demo               local demo on http://localhost:8080 (fake accounts)
#   make screenshots        README screenshots from the demo (headless Chromium)
#   make helm-lint          lint and render the Helm chart
#
# Containers are started with --rm and bounded in memory. Go modules and the
# build cache live in one named volume ($(GO_CACHE), or a directory when
# given an absolute path, as in CI); `make clean-cache` removes the volume.

GO_IMAGE      ?= golang:1.27.4-alpine3.24@sha256:70bd7ddea8b6cbe5d6943cde279d6b67feb10cc924fb9100d1d8757c1575b280
LINT_IMAGE    ?= golangci/golangci-lint:v2.15.0-alpine@sha256:2ba875b990f1d8501ad4ec19be1ea0701e316ec3a4b764f7b129f62f01318bbf
HELM_IMAGE    ?= alpine/helm:4.3.1@sha256:e3f8d5c462d75470fbb1fce79ad5c20063657096d1f98c0fcea869e2600e2e5e
TRIVY_IMAGE   ?= aquasec/trivy:0.76.1@sha256:790fd66d1697395d8693d1acaa1ea702406a20f109b6fc7bac8db623eca6c06c
SHOTS_IMAGE   ?= mcr.microsoft.com/playwright/python:v1.64.1-noble@sha256:330d401ae23c905896a0c26c66c36fc971b621519e7b11b435a8328d7bf6e031
GOVULNCHECK   ?= golang.org/x/vuln/cmd/govulncheck@v1.9.0
GO_CACHE      ?= smbdeck-gomod
IMAGE         ?= smbdeck:dev
VERSION       ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

DOCKER_GO = docker run --rm --memory=1536m --cpus=2 \
	-v "$(CURDIR)":/src -w /src \
	-v $(GO_CACHE):/cache -e GOMODCACHE=/cache/mod -e GOCACHE=/cache/build \
	-e GOFLAGS=-buildvcs=false -e GOTOOLCHAIN=local

.PHONY: help test test-short vet fmt fmt-check lint vulncheck image test-integration demo demo-down screenshots helm-lint scan clean-cache tidy

help:
	@sed -n 's/^#   //p' $(MAKEFILE_LIST)

# The race detector needs cgo: gcc and musl headers are added to the Go image
# for this run only.
test:
	$(DOCKER_GO) -e CGO_ENABLED=1 $(GO_IMAGE) sh -c 'apk add --no-cache -q gcc musl-dev && go test -race -count=1 -timeout 5m ./...'

test-short:
	$(DOCKER_GO) $(GO_IMAGE) go test -count=1 -timeout 3m ./...

vet:
	$(DOCKER_GO) $(GO_IMAGE) go vet ./...

tidy:
	$(DOCKER_GO) $(GO_IMAGE) go mod tidy

fmt:
	$(DOCKER_GO) $(GO_IMAGE) gofmt -s -w .

fmt-check:
	$(DOCKER_GO) $(GO_IMAGE) sh -c 'test -z "$$(gofmt -s -l .)" || { gofmt -s -l .; exit 1; }'

lint:
	docker run --rm --memory=1536m --cpus=2 -v "$(CURDIR)":/src -w /src \
		-v $(GO_CACHE):/cache -e GOMODCACHE=/cache/mod -e GOCACHE=/cache/build \
		-e GOLANGCI_LINT_CACHE=/cache/lint -e GOFLAGS=-buildvcs=false -e GOTOOLCHAIN=local \
		$(LINT_IMAGE) golangci-lint run ./...

vulncheck:
	$(DOCKER_GO) $(GO_IMAGE) go run $(GOVULNCHECK) ./...

image:
	docker build --build-arg VERSION=$(VERSION) -t $(IMAGE) .

test-integration:
	IMAGE=$(IMAGE) GO_IMAGE=$(GO_IMAGE) GO_CACHE=$(GO_CACHE) ./test/integration/run.sh

demo:
	IMAGE=$(IMAGE) ./deploy/compose/demo/demo.sh up

demo-down:
	IMAGE=$(IMAGE) ./deploy/compose/demo/demo.sh down

screenshots:
	IMAGE=$(IMAGE) SHOTS_IMAGE=$(SHOTS_IMAGE) ./docs/screenshots/take.sh

helm-lint:
	docker run --rm --memory=512m -v "$(CURDIR)/deploy/helm":/charts -w /charts $(HELM_IMAGE) lint --strict smbdeck
	docker run --rm --memory=512m -v "$(CURDIR)/deploy/helm":/charts -w /charts $(HELM_IMAGE) template smbdeck smbdeck >/dev/null
	docker run --rm --memory=512m -v "$(CURDIR)/deploy/helm":/charts -w /charts $(HELM_IMAGE) template smbdeck smbdeck -f smbdeck/ci/full-values.yaml >/dev/null

scan:
	docker run --rm --memory=1g -v /var/run/docker.sock:/var/run/docker.sock $(TRIVY_IMAGE) \
		image --no-progress --scanners vuln --severity HIGH,CRITICAL --ignore-unfixed --exit-code 1 $(IMAGE)

clean-cache:
	docker volume rm $(GO_CACHE)
