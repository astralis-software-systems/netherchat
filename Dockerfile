# syntax=docker/dockerfile:1
#
# Netherchat server image. The final stage is FROM scratch: nothing but a single
# static binary — no shell, no libc, no package manager, minimal attack surface
# (ARCHITECTURE_DECISION.md §1). The server makes no outbound calls, so it needs
# no CA bundle.
#
#   docker build -t astralis/netherchat .
#   docker run -p 3000:3000 astralis/netherchat

# ---- build stage ------------------------------------------------------------
FROM golang:1.26-alpine AS build

WORKDIR /src

# Cache module downloads independently of source changes.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION=dev
# CGO disabled => a fully static binary that runs on scratch. -trimpath and
# -s -w drop local paths and debug info for a smaller, reproducible artifact.
RUN CGO_ENABLED=0 go build -trimpath \
    -ldflags="-s -w -X github.com/salehkreiner/netherchat/buildinfo.Version=${VERSION}" \
    -o /out/netherchat-server ./cmd/netherchat-server

# ---- runtime stage ----------------------------------------------------------
FROM scratch

COPY --from=build /out/netherchat-server /netherchat-server

# Run unprivileged. scratch has no /etc/passwd, so use a numeric UID:GID
# (65534 = nobody on most systems).
USER 65534:65534

EXPOSE 3000

# The binary self-probes /health via its --healthcheck flag, so a scratch image
# (no curl, no shell) can still report container health.
HEALTHCHECK --interval=30s --timeout=3s --start-period=2s --retries=3 \
    CMD ["/netherchat-server", "--healthcheck"]

ENTRYPOINT ["/netherchat-server"]
CMD ["--addr", ":3000"]
