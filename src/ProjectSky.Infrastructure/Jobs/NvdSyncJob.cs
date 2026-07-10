using Microsoft.Extensions.Logging;
using ProjectSky.Vulnerability.Nvd;

namespace ProjectSky.Infrastructure.Jobs;

/// <summary>Hangfire-invokable wrappers around <see cref="NvdSyncService"/>.</summary>
public interface INvdSyncJob
{
    Task RunBulkAsync(CancellationToken ct);
    Task RunIncrementalAsync(CancellationToken ct);
}

public sealed class NvdSyncJob : INvdSyncJob
{
    // Overlapping window: NVD recommends re-pulling a margin around the last run
    // to avoid missing edits. 8 days comfortably covers a daily schedule.
    private static readonly TimeSpan IncrementalWindow = TimeSpan.FromDays(8);

    private readonly NvdSyncService _sync;
    private readonly ILogger<NvdSyncJob> _logger;

    public NvdSyncJob(NvdSyncService sync, ILogger<NvdSyncJob> logger)
    {
        _sync = sync;
        _logger = logger;
    }

    public async Task RunBulkAsync(CancellationToken ct)
    {
        _logger.LogInformation("Starting NVD bulk load.");
        var count = await _sync.BulkLoadAsync(ct);
        _logger.LogInformation("NVD bulk load finished: {Count} CVEs.", count);
    }

    public async Task RunIncrementalAsync(CancellationToken ct)
    {
        var since = DateTimeOffset.UtcNow - IncrementalWindow;
        var count = await _sync.IncrementalAsync(since, ct);
        _logger.LogInformation("NVD incremental sync finished: {Count} CVEs since {Since:o}.", count, since);
    }
}
