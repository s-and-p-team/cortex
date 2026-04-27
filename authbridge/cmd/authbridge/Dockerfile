# AuthBridge unified image — Envoy + authbridge binary in one container.
# Drop-in replacement for envoy-with-processor (Dockerfile.envoy).
#
# Uses UBI9-micro base (~24 MB) instead of UBI9-minimal (~134 MB)
# for a ~42% smaller image while remaining glibc-compatible for Envoy.
# Total image size: ~140 MB (24 MB base + 87 MB Envoy + 26 MB authbridge).
#
# Build context: ./authbridge (needs access to both authlib/ and cmd/authbridge/)

# Stage 1: Build authbridge and telemetry-processor binaries
FROM golang:1.25-alpine@sha256:5caaf1cca9dc351e13deafbc3879fd4754801acba8653fa9540cea125d01a71f AS builder

RUN apk add --no-cache git

WORKDIR /app

# Copy both modules with Docker-compatible layout
COPY authlib/ authlib/
COPY cmd/authbridge/ cmd/authbridge/
COPY cmd/telemetry-processor/ cmd/telemetry-processor/

# The go.mod has: replace authlib => ../../authlib
# In Docker the layout is /app/authlib and /app/cmd/authbridge, so the
# relative path ../../authlib resolves to /app/authlib. Correct.
ENV GOWORK=off
RUN cd cmd/authbridge && CGO_ENABLED=0 GOOS=linux go build -o /authbridge .
RUN cd cmd/telemetry-processor && CGO_ENABLED=0 GOOS=linux go build -o /telemetry-processor .

# Stage 2: Get Envoy binary
FROM docker.io/envoyproxy/envoy:v1.37.1 AS envoy-source

# Stage 3: Runtime — UBI9-micro (glibc-compatible, ~24 MB)
# UBI9-micro has no package manager and no CA certificates.
# CA certs are copied from the Alpine builder for HTTPS (JWKS, Keycloak).
FROM registry.access.redhat.com/ubi9/ubi-micro@sha256:2173487b3b72b1a7b11edc908e9bbf1726f9df46a4f78fd6d19a2bab0a701f38

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=envoy-source --chmod=755 /usr/local/bin/envoy /usr/local/bin/envoy
COPY --from=builder --chmod=755 /authbridge /usr/local/bin/authbridge
COPY --from=builder --chmod=755 /telemetry-processor /usr/local/bin/telemetry-processor
COPY --chmod=755 cmd/authbridge/entrypoint.sh /usr/local/bin/entrypoint.sh

# Envoy writes hot-restart lock files and admin socket here
RUN mkdir -p /tmp/envoy && chmod 775 /tmp/envoy

USER 1337

EXPOSE 15123 15124 9901 9090 9091

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
