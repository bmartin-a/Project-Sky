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
- Stored credentials (Defender, OIDC client secret) are protected with ASP.NET
  Data Protection whose keys are **persisted to a mounted volume / database**.
  For production, back the key ring with a secrets manager (e.g. OpenBao /
  HashiCorp Vault) — see `docs/` (planned).
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
