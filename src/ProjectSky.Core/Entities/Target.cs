using ProjectSky.Core.Enums;

namespace ProjectSky.Core.Entities;

/// <summary>A system authorized to be scanned: a host, IP, CIDR range, or URL.</summary>
public class Target
{
    public Guid Id { get; set; } = Guid.NewGuid();

    /// <summary>The raw address/URL. Validated by <c>TargetValidator</c> before use.</summary>
    public required string Address { get; set; }

    public TargetType Type { get; set; }

    public AssetCriticality Criticality { get; set; } = AssetCriticality.Medium;

    /// <summary>Optional human-friendly label.</summary>
    public string? Name { get; set; }

    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset UpdatedAt { get; set; } = DateTimeOffset.UtcNow;

    public ICollection<Scan> Scans { get; set; } = new List<Scan>();
    public ICollection<Finding> Findings { get; set; } = new List<Finding>();
}
