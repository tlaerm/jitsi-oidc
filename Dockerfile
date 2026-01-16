# syntax=docker/dockerfile:1

ARG GO_VERSION=1.25
FROM golang:${GO_VERSION}-alpine AS builder

WORKDIR /src

# Install build deps
RUN apk add --no-cache ca-certificates git

# Cache modules first
COPY go.mod go.sum ./
RUN go mod download

# Copy the rest
COPY . .

# Build a static-ish binary (still fine on alpine)
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  go build -trimpath -ldflags "-s -w" -o /out/jitsi-oidc ./cmd/jitsi-oidc

FROM alpine:3.21

# Runtime deps for HTTPS
RUN apk add --no-cache ca-certificates && update-ca-certificates

WORKDIR /app
COPY --from=builder /out/jitsi-oidc /app/jitsi-oidc
COPY LICENSE /app/LICENSE

EXPOSE 3001
USER 65532:65532

ENTRYPOINT ["/app/jitsi-oidc"]

