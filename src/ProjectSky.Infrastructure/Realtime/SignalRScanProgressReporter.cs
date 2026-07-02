using Microsoft.AspNetCore.SignalR;
using ProjectSky.Core.Interfaces;
using ProjectSky.Core.Models;

namespace ProjectSky.Infrastructure.Realtime;

/// <summary>
/// Publishes scan progress over SignalR. Works from the Worker as well as the
/// API because both hosts share a Redis backplane, so a message sent here from
/// the Worker reaches clients connected to the API.
/// </summary>
public sealed class SignalRScanProgressReporter : IScanProgressReporter
{
    private readonly IHubContext<ScanProgressHub> _hub;

    public SignalRScanProgressReporter(IHubContext<ScanProgressHub> hub) => _hub = hub;

    public Task ReportAsync(ScanProgress progress, CancellationToken ct) =>
        _hub.Clients
            .Group(ScanProgressHub.GroupFor(progress.ScanId))
            .SendAsync("ScanProgress", progress, ct);
}
