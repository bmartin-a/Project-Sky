using ProjectSky.Core.Enums;

namespace ProjectSky.Core.Entities;

/// <summary>
/// A single vulnerability/observation produced by a scanner. Findings are
/// deduplicated across scans of the same target via <see cref="Fingerprint"/>.
/// </summary>
public class Finding
{
    public Guid Id { get; set; } = Guid.NewGuid();

    /// <summary>
    /// The scan that produced/last observed this finding. Null for findings that
    /// come from an ingestion source (e.g. Microsoft Defender) rather than a scan.
    /// </summary>
    public Guid? ScanId { get; set; }
    public Scan? Scan { get; set; }

    public Guid TargetId { get; set; }
    public Target? Target { get; set; }

    /// <summary>Origin of the finding: "Scan" (active) or "Defender" (ingested).</summary>
    public string Source { get; set; } = "Scan";

    public required string Title { get; set; }
    public string? Description { get; set; }

    public Severity Severity { get; set; } = Severity.Info;
    public FindingState State { get; set; } = FindingState.New;

    // Network context (nullable for non-network findings).
    public int? Port { get; set; }
    public string? Protocol { get; set; }
    public string? Service { get; set; }
    public string? ServiceProduct { get; set; }
    public string? ServiceVersion { get; set; }

    /// <summary>CPE 2.3 string inferred for the detected service, if any.</summary>
    public string? Cpe { get; set; }

    /// <summary>Matched CVE identifier (e.g. CVE-2021-44228), if any.</summary>
    public string? CveId { get; set; }
    public Cve? Cve { get; set; }

    /// <summary>Computed 0–1000 risk score; see <c>RiskScoreService</c>.</summary>
    public int RiskScore { get; set; }

    /// <summary>Raw evidence (banner, matched response, nmap script output).</summary>
    public string? Evidence { get; set; }

    /// <summary>
    /// Stable content hash used to reconcile findings across scans of the same
    /// target (target + port + service + cve). Produced by the scanner.
    /// </summary>
    public required string Fingerprint { get; set; }

    public DateTimeOffset FirstSeenAt { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset LastSeenAt { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset? ResolvedAt { get; set; }
}
