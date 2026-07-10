using ProjectSky.Core.Enums;

namespace ProjectSky.Core.Entities;

/// <summary>A single scan run against a target.</summary>
public class Scan
{
    public Guid Id { get; set; } = Guid.NewGuid();

    public Guid TargetId { get; set; }
    public Target? Target { get; set; }

    public ScanType Type { get; set; }
    public ScanStatus Status { get; set; } = ScanStatus.Queued;

    /// <summary>Serialized <c>ScanOptions</c> (ports, templates, depth, etc.).</summary>
    public string? OptionsJson { get; set; }

    /// <summary>OIDC subject of the user who launched the scan (audit trail).</summary>
    public string? CreatedBySubject { get; set; }

    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset? StartedAt { get; set; }
    public DateTimeOffset? CompletedAt { get; set; }

    /// <summary>Populated when <see cref="Status"/> is Failed or Rejected.</summary>
    public string? ErrorMessage { get; set; }

    public ICollection<Finding> Findings { get; set; } = new List<Finding>();
}
