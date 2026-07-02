using ProjectSky.Core.Models;

namespace ProjectSky.Core.Interfaces;

/// <summary>Sink for real-time scan progress (backed by SignalR in the API).</summary>
public interface IScanProgressReporter
{
    Task ReportAsync(ScanProgress progress, CancellationToken ct);
}
