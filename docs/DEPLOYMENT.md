# Deploying Project-Sky (on-premise, Entra ID)

This guide covers a production, on-premise deployment with **Microsoft Entra ID**
(Azure AD) authentication and a working browser UI. For a quick local trial with
no login, see the "Local quickstart" at the bottom.

---

## 1. Prerequisites

- A Linux host you control with **Docker** + **Docker Compose v2**.
- Outbound network access on the build host (the images fetch base images and
  the `nmap` / `nuclei` / `trivy` binaries at build time).
- A **Microsoft Entra ID** tenant.
- A DNS name + TLS certificate for the host (e.g. `scanner.example.com`).

---

## 2. Register the app in Entra ID

Create **one** app registration used by both the SPA (to sign users in) and the
API (as the token audience).

1. **Entra ID → App registrations → New registration.**
   - Redirect URI: *Single-page application* → `https://scanner.example.com`
2. **Expose an API:**
   - Set the Application ID URI to `api://<api-app-id>` (accept the default).
   - Add a scope, e.g. `access_as_user`. Full scope string becomes
     `api://<api-app-id>/access_as_user`.
3. **App roles → Create app role:**
   - Display name `Admin`, value **`Admin`**, allowed member type *Users/Groups*.
   - Assign it (Enterprise applications → your app → Users and groups) to the
     users who should administer scans.
4. Note the **Directory (tenant) ID** and **Application (client) ID**.

> The API validates the access token's **audience** (`aud`) and reads roles from
> the `roles` claim. Admin-only endpoints (scan-policy creation, Defender sync,
> schedule mutation, the Hangfire dashboard) require the `Admin` role.

---

## 3. Configure `.env`

Copy `.env.example` to `.env` and fill in:

```bash
# Secrets
POSTGRES_PASSWORD=<strong-random>
ConnectionStrings__Postgres=Host=postgres;Port=5432;Database=projectsky;Username=projectsky;Password=<strong-random>
Zap__ApiKey=<strong-random>
Nvd__ApiKey=<free NVD key>            # https://nvd.nist.gov/developers/request-an-api-key

# Backend token validation
Auth__Oidc__Authority=https://login.microsoftonline.com/<tenant-id>/v2.0
Auth__Oidc__Audience=api://<api-app-id>
Auth__Oidc__AdminRole=Admin
Auth__Oidc__RoleClaim=roles

# Frontend sign-in (same app registration)
OIDC_AUTHORITY=https://login.microsoftonline.com/<tenant-id>/v2.0
OIDC_CLIENT_ID=<api-app-id>
OIDC_SCOPE=openid profile api://<api-app-id>/access_as_user

# Public + hosting
PUBLIC_ORIGIN=https://scanner.example.com
FRONTEND_PORT=8088

# Optional: Microsoft Defender ingestion
Defender__TenantId=<tenant-id>
Defender__ClientId=<defender-app-id>
Defender__ClientSecret=<secret>
```

---

## 4. Launch

```bash
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --build
docker compose ps
docker compose logs -f api worker
```

Topology in prod: **only the `frontend` container is published** (on
`FRONTEND_PORT`). It reverse-proxies `/api` and `/hubs` to the API over the
internal Docker network, so the API, Worker, Postgres, Redis, and ZAP are never
exposed. The SPA reads its OIDC settings at runtime from `/config.js` (generated
from the `OIDC_*` env at container start), so the image is environment-agnostic.

---

## 5. TLS + reverse proxy

Terminate HTTPS in front of the frontend port. Minimal Caddy example:

```
scanner.example.com {
    reverse_proxy localhost:8088
}
```

WebSockets (SignalR) pass through automatically. Make sure the Entra redirect URI
exactly matches `https://scanner.example.com`.

---

## 6. Harden the scanner's egress (important)

The in-app scope guard blocks internal targets and pins resolved IPs for
network/TLS scans, but HTTP tools (nuclei, ZAP) resolve and follow redirects
themselves. Add **egress filtering** on the `worker`/`api` containers that blocks
RFC1918, loopback, link-local/metadata (`169.254.0.0/16`), `0.0.0.0/8`, and CGNAT
(`100.64.0.0/10`) — at the firewall / network-namespace / egress-proxy layer.
This enforces scope regardless of what a tool re-resolves. See `SECURITY.md`.

Also: run behind your perimeter, keep `/hangfire` admin-only (it is), and rotate
the default `Zap__ApiKey` and Postgres password.

---

## 7. Smoke test

```bash
# Health (through the proxy)
curl -k https://scanner.example.com/health          # {"status":"ok"}

# API requires a token now — anonymous calls should 401
curl -si https://scanner.example.com/api/targets | head -1   # HTTP/1.1 401
```

Then in a browser:

1. Open `https://scanner.example.com` → you're redirected to Entra to sign in.
2. **Scan policies** → add one allowlisting an authorized target (e.g. `scanme.nmap.org`).
3. **Targets** → add that target.
4. **Scans** → launch a **Network** scan → watch live progress → view findings.
5. Export the **CSV / HTML report**; confirm `/hangfire` loads for an Admin user.
6. Verify scope: adding/scanning `127.0.0.1` or `169.254.169.254` is **rejected**.

> First CVE enrichment waits on the NVD sync (a scheduled job; faster with
> `Nvd__ApiKey`). Web scans need the ZAP container and should target an
> intentionally-vulnerable app (e.g. OWASP Juice Shop), never a third party.

---

## Local quickstart (no login)

For a local trial without Entra, the base compose runs in Development with the
no-login LocalDev mode:

```bash
cp .env.example .env
docker compose up --build
# UI: http://localhost:3000   API: http://localhost:8080
```

LocalDev authenticates every request as an admin and **refuses to start outside
the Development environment** — it's for local use only.
