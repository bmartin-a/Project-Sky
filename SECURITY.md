# Security Policy

## Authorized use only

Project-Sky is an **active** vulnerability scanner. It sends traffic to, and
probes, the targets you point it at. **Only scan systems you own or are
explicitly authorized in writing to test.** Unauthorized scanning may be
illegal in your jurisdiction and is a violation of this project's intended use.

Project-Sky enforces this stance in code, not just in docs:

- Every scan target passes through `TargetValidator` (strict grammar) and
  `TargetAuthorizer` (scope allowlist) before a single packet is sent.
- Private ranges (RFC1918), loopback, link-local, and cloud-metadata
  addresses (e.g. `169.254.169.254`) are **blocked by default** and must be
  explicitly allowlisted via a `ScanPolicy`. This prevents the scanner from
  being turned into an SSRF pivot.
- The external-tool runner (`CliRunner`) never invokes a shell and never
  builds command strings by concatenation — arguments are passed as an
  argument vector, eliminating command-injection via target/option input.

## Hardening notes for operators

- The scanner container runs as a **non-root** user with only the
  `CAP_NET_RAW` capability (required for nmap SYN/OS-detection). Do not run it
  as root.
- **Authentication.** `Auth:Mode=LocalDev` authenticates every request as an
  admin and is refused to start outside the Development environment. Production
  MUST use `Auth:Mode=Oidc` with `Auth:Oidc:Audience` set (audience validation
  is mandatory) and an admin role claim (`Auth:Oidc:AdminRole`, default
  `Admin`, read from the `Auth:Oidc:RoleClaim` claim, default `roles`).
- **Authorization.** Every endpoint requires an authenticated user; privileged
  operations — creating/loosening scan policies, triggering Defender ingestion,
  managing schedules, and the Hangfire dashboard — require the admin role.
  Scan-policy creation is admin-only specifically because it governs the SSRF
  scope guard.
- **IP pinning.** The authorizer resolves and scope-checks a target's IPs once,
  and the direct-connect scanners (nmap, TLS) connect to that exact pinned IP
  (hostname kept only for SNI) instead of re-resolving — closing the
  DNS-rebinding window for network and TLS scans.
- **Network egress (defense-in-depth).** IP pinning can't cover HTTP tools that
  resolve and follow redirects themselves (nuclei, OWASP ZAP), so a hostile
  redirect could still steer a web scan to an internal address. Run the
  scanner/worker with **egress filtering** that blocks RFC1918, loopback,
  link-local/metadata (169.254.0.0/16), `0.0.0.0/8`, and CGNAT — at the
  network/namespace/proxy layer — so scope is enforced regardless of what a
  tool re-resolves. This is the robust control; the in-app checks are the first
  line, not the last.
- Stored credentials (Defender, OIDC client secret, ZAP key) are read from
  configuration/environment. A `SecretProtector` (ASP.NET Data Protection,
  keys persisted to a mounted volume) is available for encrypting values at
  rest; for production, back the key ring with a secrets manager (OpenBao /
  HashiCorp Vault). Change all default credentials (`change-me`, the default
  Postgres password) before any non-local deployment.
- Put the API and Hangfire dashboard behind your OIDC provider; never expose
  `/hangfire` unauthenticated.

## Reporting a vulnerability

If you discover a security issue in Project-Sky itself, please **do not open a
public issue**. Instead, report it privately via GitHub Security Advisories
("Report a vulnerability" on the repository's Security tab). We aim to
acknowledge reports within 72 hours.

Please include:
- A description of the issue and its impact
- Steps to reproduce (proof-of-concept if possible)
- Affected version / commit
