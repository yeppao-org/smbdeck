# syntax=docker/dockerfile:1
#
# One image, three roles (see README.md):
#   web        USER 10001 (the default), no capability, read-only root file system
#   agent      root reduced to CHOWN FOWNER DAC_OVERRIDE SETUID SETGID NET_BIND_SERVICE
#   discovery  avahi as UID 86, wsdd2 as nobody, host network
#
# Base images are pinned by digest (multi-arch index). Bump them together with
# the Go version in go.mod and the Makefile.

ARG GO_IMAGE=golang:1.27.4-alpine3.24@sha256:70bd7ddea8b6cbe5d6943cde279d6b67feb10cc924fb9100d1d8757c1575b280
ARG ALPINE_IMAGE=alpine:3.24.3@sha256:b3413572228e34bd1c9245f5565e6cd127005655e8a7899aef33d8e83255c9e6

# --- smbdeck: a static binary, cross-compiled on the build platform ---------
FROM --platform=$BUILDPLATFORM ${GO_IMAGE} AS build
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -buildvcs=false -ldflags "-s -w -X main.version=${VERSION}" -o /out/smbdeck ./cmd/smbdeck

# --- wsdd2 (WS-Discovery) ----------------------------------------------------
# The upstream repository (Netgear/wsdd2) no longer exists. The source is the
# Debian archive's original tarball, content-addressed on snapshot.debian.org
# and checked against its SHA-256. GPL-3.0: see NOTICE.
FROM ${ALPINE_IMAGE} AS wsdd2
ARG WSDD2_URL=https://snapshot.debian.org/file/28506e4e22bf56ca81edfd348a5fb45d0df02ebf
ARG WSDD2_SHA256=2b1e7720435a1e067388660ec3edb321a4c91b4f9d0928ba27d0a8d89b7ef3b9
RUN apk add --no-cache build-base linux-headers \
 && wget -q -O /tmp/wsdd2.tar.xz "$WSDD2_URL" \
 && echo "$WSDD2_SHA256  /tmp/wsdd2.tar.xz" | sha256sum -c - \
 && tar -xJf /tmp/wsdd2.tar.xz -C /tmp \
 && make -C /tmp/wsdd2-1.8.7 wsdd2 \
      CFLAGS="-O2 -Wall -Wno-int-conversion -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE" \
      LDFLAGS="-pie -Wl,-z,relro,-z,now" \
 && install -D -m 0755 /tmp/wsdd2-1.8.7/wsdd2 /out/wsdd2

# --- runtime -----------------------------------------------------------------
FROM ${ALPINE_IMAGE}
ARG VERSION=dev
LABEL org.opencontainers.image.title="smbdeck" \
      org.opencontainers.image.description="A small, secure, container-first web console for Samba" \
      org.opencontainers.image.source="https://github.com/yeppao-org/smbdeck" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="${VERSION}"

# Writable locations are mounted at run time (see deploy/):
#   /state                 web (read-write) and agent (read): desired.json, audit.log
#   /status                agent (read-write) and web (read-only): status.json, tree.json
#   /run/smbdeck           agent: generated accounts, smbpasswd, smb.conf, Samba's runtime files
#   /run/smbdeck-discovery discovery: avahi's configuration and runtime directory
#   /roots/<name>          agent only: the share roots
#
# /var/log/samba points there too: samba-dcerpcd, started by smbd on demand,
# writes its own log file whatever the configuration says.
#
# /etc/passwd and /etc/group point into /run/smbdeck/etc, so the agent can add
# accounts with a read-only root file system. The image ships the base files
# there too, for the roles that do not mount /run/smbdeck. The agent starts
# from the copies in /usr/share/smbdeck.
# Packages pinned to exact versions (Renovate proposes the updates, see
# renovate.json): a rebuild never picks up a different Samba silently.
RUN apk add --no-cache \
      samba-server=4.23.8-r0 \
      samba-common-tools=4.23.8-r0 \
      avahi=0.9_rc4-r0 \
      tini=0.19.0-r3 \
 && rm -rf /etc/avahi/services/* /var/cache/apk/* \
 && addgroup -S -g 10001 smbdeck \
 && adduser -S -D -H -u 10001 -G smbdeck -s /sbin/nologin -h /nonexistent -g smbdeck smbdeck \
 && mkdir -p /usr/share/smbdeck /run/smbdeck/etc /run/smbdeck-discovery /state /status /roots \
 && cp /etc/passwd /etc/group /usr/share/smbdeck/ \
 && cp /etc/passwd /etc/group /run/smbdeck/etc/ \
 && ln -sf /run/smbdeck/etc/passwd /etc/passwd \
 && ln -sf /run/smbdeck/etc/group /etc/group \
 && ln -sf /run/smbdeck/smb.conf /etc/samba/smb.conf \
 && rm -rf /var/log/samba && ln -s /run/smbdeck/samba/log /var/log/samba \
 && rm -rf /etc/avahi/services /run/avahi-daemon \
 && ln -s /run/smbdeck-discovery/services /etc/avahi/services \
 && ln -sf /run/smbdeck-discovery/hosts /etc/avahi/hosts \
 && ln -s /run/smbdeck-discovery/avahi-daemon /run/avahi-daemon \
 && chown 10001:10001 /state && chmod 0700 /state

COPY --from=wsdd2 /out/wsdd2 /usr/sbin/wsdd2
COPY --from=build /out/smbdeck /usr/local/bin/smbdeck
COPY LICENSE NOTICE /usr/share/doc/smbdeck/

USER 10001:10001
EXPOSE 8080 445
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 CMD ["/usr/local/bin/smbdeck", "healthcheck"]
ENTRYPOINT ["/sbin/tini", "--", "/usr/local/bin/smbdeck"]
CMD ["web"]
