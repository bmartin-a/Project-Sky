using Microsoft.Extensions.Logging;
using ProjectSky.Infrastructure.Defender;

namespace ProjectSky.Infrastructure.Jobs;

/// <summary>Hangfire-invokable wrapper around Defender ingestion.</summary>
public interface IDefenderIngestionJob
{
    Task RunAsync(CancellationToken ct);
}

public sealed class DefenderIngestionJob : IDefenderIngestionJob
{
    private readonly DefenderIngestionService _service;
    private readonly ILogger<DefenderIngestionJob> _logger;

    public DefenderIngestionJob(DefenderIngestionService service, ILogger<DefenderIngestionJob> logger)
    {
        _service = service;
        _logger = logger;
    }

    public async Task RunAsync(CancellationToken ct)
    {
        _logger.LogInformation("Starting Defender ingestion.");
        var count = await _service.IngestAsync(ct);
        _logger.LogInformation("Defender ingestion finished: {Count} new findings.", count);
    }
}
