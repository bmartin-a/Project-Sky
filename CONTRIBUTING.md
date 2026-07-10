# Contributing to Project-Sky

Thanks for your interest in improving Project-Sky!

## Ground rules

- **Authorized testing only.** Never add features whose primary purpose is to
  evade authorization controls or scan without consent. See [SECURITY.md](SECURITY.md).
- Keep pull requests focused and single-concern.
- Add or update tests for behaviour you change — especially parsers, the CPE
  matcher, and target validation/authorization, which are correctness- and
  security-critical.

## Development

```bash
dotnet restore ProjectSky.slnx
dotnet build   ProjectSky.slnx
dotnet test    ProjectSky.slnx
```

Or run the whole stack:

```bash
cp .env.example .env
docker compose up --build
```

### Database migrations

The schema is created from the model on first run (`EnsureCreated`) until EF
migrations are added. Once you have the .NET 10 SDK, generate the initial
migration and the app will switch to `Migrate()` automatically:

```bash
dotnet tool install --global dotnet-ef
dotnet ef migrations add InitialCreate \
  --project src/ProjectSky.Infrastructure \
  --startup-project src/ProjectSky.Api
```

## Commit style

Conventional commits are appreciated (`feat:`, `fix:`, `docs:`, `test:`, `chore:`).

## CI

Every push is built and tested by `.github/workflows/ci.yml` on a .NET 10
runner, and the Docker images are built to catch packaging regressions.
