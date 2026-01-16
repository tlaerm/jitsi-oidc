# Jitsi OIDC (OpenID Connect) Auth Adapter

This project provides an OpenID Connect (OIDC) authentication adapter for Jitsi Meet, implemented in Go.
It enables Jitsi’s JWT-based authentication by redirecting users to an external OIDC provider (Keycloak, Dex, Authentik, etc.), minting a short-lived Jitsi-compatible JWT, and redirecting the user back into the requested meeting.

## Lineage / Credits

This project is based on:

- <https://github.com/rvvg/jitsi-oidc>
  which is based on
- <https://github.com/bluffy/jitsi-oidc>
  which is based on
- <https://github.com/MarcelCoding/jitsi-openid>

The codebase has since been modernized, security-hardened, and updated to Go 1.25.

## Features

- OIDC Authorization Code Flow
- Short-lived, signed Jitsi JWTs
- Stateless JWT verification on the Jitsi side
- In-memory state store (Redis optional later)
- Secure cookies (HttpOnly, SameSite, TLS-aware)
- No sensitive tokens logged
- Designed for reverse-proxy / ingress deployments (Traefik, NGINX, etc.)

## How it Works (High Level)

1. User opens a Jitsi room (`meet.example.com/myroom`)
2. Jitsi redirects unauthenticated users to:

    ```
    https://auth.meet.example.com/room/myroom
    ```

3. This service, running at `auth.meet.example.com`, does the following:
    - starts an OIDC login
    - validates the callback
    - creates a short-lived Jitsi JWT
4. User is redirected back to:

    ```
    https://meet.example.com/myroom?jwt=...
    ```

## Repository Layout

```text
textCopy code.
├── cmd/
│   └── jitsi-oidc/
│       └── main.go
├── .env.example
├── .gitignore
├── go.mod
├── go.sum
├── Dockerfile
├── README.md
└── LICENSE
```

## Environment Variables

### Required

| Variable          | Description                                            |
| ----------------- | ------------------------------------------------------ |
| `JITSI_SECRET`    | JWT signing secret (must match Jitsi `JWT_APP_SECRET`) |
| `JITSI_URL`       | Base Jitsi URL (e.g. `https://meet.example.com`)       |
| `JITSI_SUB`       | Jitsi app ID / domain (e.g. `meet.example.com`)        |
| `ISSUER_BASE_URL` | OIDC issuer URL                                        |
| `BASE_URL`        | Public URL of this service                             |
| `CLIENT_ID`       | OIDC client ID                                         |
| `SECRET`          | OIDC client secret                                     |

### Optional/Security

| Variable          | Default | Description                   |
| ----------------- | ------- | ----------------------------- |
| `JWT_TTL`         | `10m`   | Lifetime of minted Jitsi JWT  |
| `JWT_ISSUER`      | `jitsi` | JWT `iss` claim               |
| `JWT_AUDIENCE`    | `jitsi` | JWT `aud` claim               |
| `LOG_LEVEL`       | `info`  | `info` or `debug`             |
| `COOKIE_SAMESITE` | `lax`   | `lax`, `strict`, or `none`    |
| `TRUST_PROXY`     | `true`  | Trust `X-Forwarded-*` headers |
| `TRUSTED_PROXIES` | –       | CIDRs of trusted proxies      |
| `INCLUDE_NAME`    | `true`  | Include display name in JWT   |
| `INCLUDE_EMAIL`   | `false` | Include email in JWT          |

## Docker

### Build

```bash
docker build -t jitsi-oidc .
```

### Run (example)

```bash
bashCopy codedocker run --rm \\
  -p 3001:3001 \\
  --env-file .env \\
  jitsi-oidc
```

The service listens on port 3001.

### Example docker-compose.yaml

```yaml
yamlCopy codeversion: "3.8"

services:
  jitsi-oidc:
    image: jitsi-oidc:latest
    restart: always
    environment:
      JITSI_SECRET: ${JWT_APP_SECRET}
      JITSI_URL: https://meet.example.com
      JITSI_SUB: meet.example.com
      ISSUER_BASE\_URL: https://idp.example.com/realms/main
      BASE_URL: https://auth.meet.example.com
      CLIENT_ID: jitsi
      SECRET: supersecret
    ports:
      - "3001:3001"
```

When running behind Traefik or another reverse proxy, TLS should be terminated before this service.

## Jitsi Configuration

In your Jitsi deployment (docker-jitsi-meet, Helm chart, etc.):

```env
ENABLE_AUTH=1
ENABLE_GUESTS=1
AUTH_TYPE=jwt

JWT_APP_ID=meet.example.com
JWT_APP_SECRET=SECRET

JWT_ACCEPTED_ISSUERS=jitsi
JWT_ACCEPTED_AUDIENCES=jitsi

TOKEN_AUTH_URL=https://auth.meet.example.com/room/{room}
```

### Notes

- JWT_APP_SECRET must match JITSI_SECRET
- {room} is replaced by Jitsi automatically
- HTTPS is strongly recommended

## Health Check

```http
GET /healthz
```

Returns 200 OK if the service is running.

## Security Notes

- No OAuth tokens or JWTs are logged
- Cookies are HttpOnly and TLS-aware
- JWT lifetime is intentionally short
- State is stored in-memory with TTL (safe for single-instance use)
- Redis or another shared store can be added later for HA setups.

## Development

```bash
go run ./cmd/jitsi-oidc
```

Or build locally:

```bash
go build ./cmd/jitsi-oidc
```
