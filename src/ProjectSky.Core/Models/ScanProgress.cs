using ProjectSky.Core.Enums;

namespace ProjectSky.Core.Models;

/// <summary>Real-time progress event pushed to clients over SignalR.</summary>
public record ScanProgress(
    Guid ScanId,
    ScanStatus Status,
    int PercentComplete,
    string? Message,
    int FindingsSoFar);
