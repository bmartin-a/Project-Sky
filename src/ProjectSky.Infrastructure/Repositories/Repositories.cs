using Microsoft.EntityFrameworkCore;
using ProjectSky.Core.Entities;
using ProjectSky.Core.Enums;
using ProjectSky.Core.Interfaces;
using ProjectSky.Infrastructure.Data;

namespace ProjectSky.Infrastructure.Repositories;

public sealed class TargetRepository(AppDbContext db) : ITargetRepository
{
    public Task<Target?> GetAsync(Guid id, CancellationToken ct) =>
        db.Targets.FirstOrDefaultAsync(t => t.Id == id, ct);

    public async Task<IReadOnlyList<Target>> ListAsync(CancellationToken ct) =>
        await db.Targets.OrderByDescending(t => t.CreatedAt).ToListAsync(ct);

    public async Task AddAsync(Target target, CancellationToken ct) =>
        await db.Targets.AddAsync(target, ct);

    public Task SaveChangesAsync(CancellationToken ct) => db.SaveChangesAsync(ct);
}

public sealed class ScanRepository(AppDbContext db) : IScanRepository
{
    public Task<Scan?> GetAsync(Guid id, CancellationToken ct) =>
        db.Scans.Include(s => s.Target).FirstOrDefaultAsync(s => s.Id == id, ct);

    public async Task<IReadOnlyList<Scan>> ListAsync(CancellationToken ct) =>
        await db.Scans.OrderByDescending(s => s.CreatedAt).ToListAsync(ct);

    public async Task AddAsync(Scan scan, CancellationToken ct) =>
        await db.Scans.AddAsync(scan, ct);

    public Task SaveChangesAsync(CancellationToken ct) => db.SaveChangesAsync(ct);
}

public sealed class FindingRepository(AppDbContext db) : IFindingRepository
{
    public async Task<IReadOnlyList<Finding>> ListByScanAsync(Guid scanId, CancellationToken ct) =>
        await db.Findings.Where(f => f.ScanId == scanId)
            .OrderByDescending(f => f.RiskScore).ToListAsync(ct);

    public async Task<IReadOnlyList<Finding>> ListOpenByTargetAsync(Guid targetId, CancellationToken ct) =>
        await db.Findings
            .Where(f => f.TargetId == targetId && f.State != FindingState.Resolved)
            .ToListAsync(ct);

    public async Task AddRangeAsync(IEnumerable<Finding> findings, CancellationToken ct) =>
        await db.Findings.AddRangeAsync(findings, ct);

    public Task SaveChangesAsync(CancellationToken ct) => db.SaveChangesAsync(ct);
}

public sealed class ScanPolicyRepository(AppDbContext db) : IScanPolicyRepository
{
    public async Task<IReadOnlyList<ScanPolicy>> ListAsync(CancellationToken ct) =>
        await db.ScanPolicies.ToListAsync(ct);

    public async Task AddAsync(ScanPolicy policy, CancellationToken ct) =>
        await db.ScanPolicies.AddAsync(policy, ct);

    public Task SaveChangesAsync(CancellationToken ct) => db.SaveChangesAsync(ct);
}

public sealed class CveRepository(AppDbContext db) : ICveRepository
{
    public Task<Cve?> GetAsync(string cveId, CancellationToken ct) =>
        db.Cves.Include(c => c.CpeMatches).FirstOrDefaultAsync(c => c.Id == cveId, ct);

    public async Task<IReadOnlyList<Cve>> FindByProductAsync(string product, CancellationToken ct)
    {
        // Match CVEs whose CPE criteria contain ":<product>:" (product token).
        var needle = $":{product.ToLowerInvariant()}:";
        return await db.Cves
            .Include(c => c.CpeMatches)
            .Where(c => c.CpeMatches.Any(m => m.Criteria.ToLower().Contains(needle)))
            .Take(200)
            .ToListAsync(ct);
    }

    public async Task UpsertAsync(Cve cve, CancellationToken ct)
    {
        var existing = await db.Cves.Include(c => c.CpeMatches)
            .FirstOrDefaultAsync(c => c.Id == cve.Id, ct);

        if (existing is null)
        {
            await db.Cves.AddAsync(cve, ct);
            return;
        }

        existing.Description = cve.Description;
        existing.CvssV3BaseScore = cve.CvssV3BaseScore;
        existing.CvssV3Vector = cve.CvssV3Vector;
        existing.Severity = cve.Severity;
        existing.EpssScore = cve.EpssScore;
        existing.HasKnownExploit = cve.HasKnownExploit;
        existing.PublishedAt = cve.PublishedAt;
        existing.LastModifiedAt = cve.LastModifiedAt;

        db.CpeMatches.RemoveRange(existing.CpeMatches);
        existing.CpeMatches = cve.CpeMatches;
    }

    public Task SaveChangesAsync(CancellationToken ct) => db.SaveChangesAsync(ct);
}
