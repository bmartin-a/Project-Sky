using ProjectSky.Core.Entities;

namespace ProjectSky.Core.Interfaces;

/// <summary>Persistence contracts. Implemented in ProjectSky.Infrastructure.</summary>
public interface ITargetRepository
{
    Task<Target?> GetAsync(Guid id, CancellationToken ct);
    Task<IReadOnlyList<Target>> ListAsync(CancellationToken ct);
    Task AddAsync(Target target, CancellationToken ct);
    Task SaveChangesAsync(CancellationToken ct);
}

public interface IScanRepository
{
    Task<Scan?> GetAsync(Guid id, CancellationToken ct);
    Task<IReadOnlyList<Scan>> ListAsync(CancellationToken ct);
    Task AddAsync(Scan scan, CancellationToken ct);
    Task SaveChangesAsync(CancellationToken ct);
}

public interface IFindingRepository
{
    Task<IReadOnlyList<Finding>> ListByScanAsync(Guid scanId, CancellationToken ct);
    Task<IReadOnlyList<Finding>> ListOpenByTargetAsync(Guid targetId, CancellationToken ct);
    Task AddRangeAsync(IEnumerable<Finding> findings, CancellationToken ct);
    Task SaveChangesAsync(CancellationToken ct);
}

public interface IScanPolicyRepository
{
    Task<IReadOnlyList<ScanPolicy>> ListAsync(CancellationToken ct);
    Task AddAsync(ScanPolicy policy, CancellationToken ct);
    Task SaveChangesAsync(CancellationToken ct);
}

public interface ICveRepository
{
    Task<Cve?> GetAsync(string cveId, CancellationToken ct);

    /// <summary>Returns candidate CVEs whose CPE criteria reference the given product.</summary>
    Task<IReadOnlyList<Cve>> FindByProductAsync(string product, CancellationToken ct);

    Task UpsertAsync(Cve cve, CancellationToken ct);
    Task SaveChangesAsync(CancellationToken ct);
}
