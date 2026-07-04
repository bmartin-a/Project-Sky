using System.Security.Cryptography;
using System.Text;
using ProjectSky.Core.Enums;
using ProjectSky.Core.Interfaces;
using ProjectSky.Core.Models;

namespace ProjectSky.Scanners.Base;

/// <summary>Shared helpers for scanner plugins.</summary>
public abstract class ScannerBase : IScanner
{
    public abstract string Name { get; }
    public abstract ScanType Type { get; }

    public abstract Task<IReadOnlyList<Core.Entities.Finding>> ScanAsync(
        Core.Entities.Target target,
        ScanOptions options,
        IScanProgressReporter progress,
        CancellationToken ct);

    /// <summary>
    /// Stable dedup key for a finding. Reconciliation across re-scans relies on
    /// identical inputs producing an identical fingerprint.
    /// </summary>
    protected static string ComputeFingerprint(params string?[] parts)
    {
        var joined = string.Join('|', parts.Select(p => p?.Trim().ToLowerInvariant() ?? ""));
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(joined));
        return Convert.ToHexStringLower(hash);
    }

    /// <summary>Maps a textual severity (nuclei/ZAP) to our severity enum.</summary>
    protected static Severity SeverityFromName(string? name) => name?.Trim().ToLowerInvariant() switch
    {
        "critical" => Severity.Critical,
        "high" => Severity.High,
        "medium" => Severity.Medium,
        "low" => Severity.Low,
        _ => Severity.Info,
    };

    /// <summary>Maps a CVSS v3 base score to a severity band.</summary>
    protected static Severity SeverityFromCvss(double? baseScore) => baseScore switch
    {
        null => Severity.Info,
        >= 9.0 => Severity.Critical,
        >= 7.0 => Severity.High,
        >= 4.0 => Severity.Medium,
        > 0.0 => Severity.Low,
        _ => Severity.Info,
    };

    protected static async Task ReportSafeAsync(
        IScanProgressReporter progress, ScanProgress p, CancellationToken ct)
    {
        try { await progress.ReportAsync(p, ct); }
        catch { /* progress is best-effort; never fail a scan on a reporting error */ }
    }
}
