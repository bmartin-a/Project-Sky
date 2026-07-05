using ProjectSky.Core.Entities;
using ProjectSky.Core.Enums;
using ProjectSky.Core.Models;
using RiskScoreModel = ProjectSky.Core.Models.RiskScore;

namespace ProjectSky.Api.Contracts;

// --- Targets ---
public record CreateTargetRequest(string Address, TargetType Type, AssetCriticality Criticality, string? Name);

public record TargetResponse(Guid Id, string Address, TargetType Type, AssetCriticality Criticality, string? Name, DateTimeOffset CreatedAt)
{
    public static TargetResponse From(Target t) =>
        new(t.Id, t.Address, t.Type, t.Criticality, t.Name, t.CreatedAt);
}

// --- Scan policies ---
public record CreateScanPolicyRequest(
    string Name,
    List<string> AllowedTargets,
    bool AllowPrivateRanges = false,
    bool AllowLoopback = false,
    bool AllowLinkLocalAndMetadata = false);

public record ScanPolicyResponse(Guid Id, string Name, List<string> AllowedTargets, bool AllowPrivateRanges, bool AllowLoopback, bool AllowLinkLocalAndMetadata)
{
    public static ScanPolicyResponse From(ScanPolicy p) =>
        new(p.Id, p.Name, p.AllowedTargets, p.AllowPrivateRanges, p.AllowLoopback, p.AllowLinkLocalAndMetadata);
}

// --- Scan schedules ---
public record CreateScanScheduleRequest(Guid TargetId, ScanType Type, string Cron);

public record ScanScheduleResponse(Guid Id, Guid TargetId, ScanType Type, string Cron, bool Enabled, DateTimeOffset CreatedAt)
{
    public static ScanScheduleResponse From(ScanSchedule s) =>
        new(s.Id, s.TargetId, s.Type, s.Cron, s.Enabled, s.CreatedAt);
}

// --- Scans ---
public record CreateScanRequest(Guid TargetId, ScanType Type, ScanOptions? Options);

public record ScanResponse(Guid Id, Guid TargetId, ScanType Type, ScanStatus Status, string? ErrorMessage, DateTimeOffset CreatedAt, DateTimeOffset? CompletedAt)
{
    public static ScanResponse From(Scan s) =>
        new(s.Id, s.TargetId, s.Type, s.Status, s.ErrorMessage, s.CreatedAt, s.CompletedAt);
}

// --- Findings ---
public record FindingResponse(
    Guid Id, string Title, string? Description, Severity Severity, FindingState State,
    string Source, int? Port, string? Protocol, string? Service, string? ServiceVersion,
    string? Cpe, string? CveId, int RiskScore, string RiskBand,
    DateTimeOffset FirstSeenAt, DateTimeOffset LastSeenAt)
{
    public static FindingResponse From(Finding f) =>
        new(f.Id, f.Title, f.Description, f.Severity, f.State, f.Source, f.Port, f.Protocol,
            f.Service, f.ServiceVersion, f.Cpe, f.CveId, f.RiskScore, RiskScoreModel.BandFor(f.RiskScore),
            f.FirstSeenAt, f.LastSeenAt);
}
