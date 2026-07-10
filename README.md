# Project-Sky

**Open-source, on-premise vulnerability scanner** for network devices,
infrastructure, and web applications. Self-hosted, no *required* cloud
dependency, built to be contributed to.

> ⚠️ **Authorized use only.** Project-Sky actively probes the targets you give
> it. Only scan systems you own or are explicitly authorized to test. See
> [SECURITY.md](SECURITY.md).

---

## What it does

| Capability | Engine | Status |
|---|---|---|
| Network scanning (ports, services, OS fingerprint) | `nmap` (CLI-wrapped) | ✅ done |
| CVE matching (CPE → NVD, CVSS scoring) | local NVD mirror + `CpeMatcher` | ✅ done |
| Web app testing — template checks | `nuclei` (CLI-wrapped) | ✅ done |
| Web app testing — active spider/scan (XSS, SQLi…) | OWASP ZAP (daemon) | ✅ done |
| Microsoft Defender ingestion | Defender for Endpoint API | ✅ done |
| Infrastructure — TLS / certificate checks | `SslTlsScanner` (native) | ✅ done |
| Infrastructure — container images | `trivy` (CLI-wrapped) | ✅ done |
| Reporting (CSV / JSON / printable HTML) | `ReportService` | ✅ done |
| Scheduled recurring scans | Hangfire recurring jobs | ✅ done |

## Architecture

Clean, layered .NET 10 solution with a **pluggable scanner engine** (every
scanner implements `IScanner`). Actively-scanned targets are gated by a
validation + authorization layer before any traffic leaves the box.

```
                 ┌──────────────┐   OIDC (Entra / Keycloak / local dev)
   React 19 UI ──┤ ProjectSky.Api├── SignalR (live scan progress)
                 └──────┬───────┘
                        │ enqueue (Hangfire)
                 ┌──────▼────────┐
                 │ProjectSky.Worker│  ScanExecutionJob · NvdSyncJob · DefenderJob
                 └──────┬────────┘
     ┌──────────────────┼─────────────────────┐
┌────▼─────┐  ┌─────────▼────────┐  ┌──────────▼──────────┐
│ Scanners │  │  Vulnerability   │  │   Infrastructure    │
│ nmap/... │  │  NVD · CPE match │  │  EF Core · Postgres │
│ CliRunner│  │  risk scoring    │  │  reconciliation     │
│ Target*  │  └──────────────────┘  │  Defender · secrets │
└──────────┘                        └─────────────────────┘
         all reference ► ProjectSky.Core (entities/enums/interfaces)
```

**Projects**

- `ProjectSky.Core` — domain: entities, enums, interfaces, models (no deps)
- `ProjectSky.Scanners` — `CliRunner` (hardened), `TargetValidator`,
  `TargetAuthorizer`, nmap/nuclei/zap wrappers
- `ProjectSky.Vulnerability` — NVD sync, CPE version-range matching, risk scoring
- `ProjectSky.Infrastructure` — EF Core / PostgreSQL, repositories, finding
  reconciliation, secret protection, Defender client
- `ProjectSky.Api` — REST API, OIDC auth, Hangfire dashboard, SignalR hub
- `ProjectSky.Worker` — Hangfire server running scan + scheduled jobs
- `tests/*` — xUnit tests (parsers, CPE matching, target authorization)

## Security-by-design highlights

- **No command injection.** `CliRunner` uses an argument vector and never a
  shell — untrusted target/option values can't break out.
- **Scope control.** `TargetAuthorizer` blocks RFC1918 / loopback / link-local
  / cloud-metadata by default; targets must be allowlisted via a `ScanPolicy`.
- **Reliable jobs.** Long-running scans run on **Hangfire** (retries,
  visibility timeout, recovery if a worker dies) — not a hand-rolled queue.
- **Least privilege.** Scanner container runs non-root with only `CAP_NET_RAW`.

## Getting started

### Prerequisites
- .NET 10 SDK (for local build) **or** Docker + Docker Compose (for the full stack)
- Node 20+ (for the frontend)

### Run the full stack (Docker Compose)
```bash
cp .env.example .env      # then edit secrets
docker compose up --build
```
- API:               http://localhost:8080
- Hangfire dashboard: http://localhost:8080/hangfire  (behind auth)
- Frontend:          http://localhost:3000

### Build & test locally
```bash
dotnet restore ProjectSky.slnx
dotnet build   ProjectSky.slnx
dotnet test    ProjectSky.slnx
```

### Frontend (React SPA)
```bash
cd frontend
npm install
npm run dev        # http://localhost:3000, proxies /api + /hubs to the backend
npm run build      # typecheck + production bundle
```
Stack: React 19 + TypeScript + Vite, Tailwind CSS v4, TanStack Query, React
Router, Recharts, and the SignalR client for live scan progress. Pages:
Dashboard, Scans (launch + live detail), Targets, Scan policies.

> **Note:** the .NET backend is authored in an environment without a .NET SDK,
> so package versions in `Directory.Packages.props` are the intended baseline
> and are verified by CI (`.github/workflows/ci.yml`) on every push. The
> frontend is built and typechecked directly. Build locally or in CI to compile
> and run everything.

## First scan (once running)

```bash
# 1. Allowlist a target you are authorized to scan
curl -X POST localhost:8080/api/scan-policies \
  -H 'Content-Type: application/json' \
  -d '{"name":"lab","allowedTargets":["scanme.nmap.org"]}'

# 2. Register the target
curl -X POST localhost:8080/api/targets \
  -H 'Content-Type: application/json' \
  -d '{"address":"scanme.nmap.org","type":"Hostname","criticality":"Medium"}'

# 3. Launch a network scan (202 Accepted → runs on Hangfire)
curl -X POST localhost:8080/api/scans \
  -H 'Content-Type: application/json' \
  -d '{"targetId":"<id>","type":"Network"}'

# 4. Read findings
curl localhost:8080/api/scans/<scanId>/findings
```

## Roadmap

- **Milestone 1** ✅ — Foundation + network scanning end-to-end (auth, NVD/CPE, nmap, UI)
- **Milestone 2** ✅ — Web application testing (Nuclei templates + OWASP ZAP active scan)
- **Milestone 3** ✅ — Microsoft Defender ingestion + infrastructure (TLS) scanning
- **Milestone 4** ✅ — Container image scanning (Trivy), reporting (CSV/JSON/HTML), scheduled scans

All four milestones are complete. Reports are exportable per scan at
`/api/scans/{id}/report/{csv,json,html}` (the HTML report is print-to-PDF
friendly), and recurring scans are managed on the Scans page.

## Contributing

Issues and PRs welcome. Keep PRs focused and single-concern. All contributions
are under the project's [Apache-2.0](LICENSE) license.

## License

[Apache License 2.0](LICENSE).
