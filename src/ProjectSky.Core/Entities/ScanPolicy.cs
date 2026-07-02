namespace ProjectSky.Core.Entities;

/// <summary>
/// Defines what may be scanned. Enforced by <c>TargetAuthorizer</c> before any
/// scan traffic is sent. This is the primary guardrail against the scanner
/// being pointed at unauthorized or internal-only infrastructure.
/// </summary>
public class ScanPolicy
{
    public Guid Id { get; set; } = Guid.NewGuid();

    public required string Name { get; set; }

    /// <summary>
    /// Explicit allowlist entries: hostnames, IPs, or CIDR ranges. A target is
    /// only scannable if it matches at least one entry.
    /// </summary>
    public List<string> AllowedTargets { get; set; } = new();

    /// <summary>Allow RFC1918 private ranges. Off by default.</summary>
    public bool AllowPrivateRanges { get; set; }

    /// <summary>Allow loopback addresses. Off by default.</summary>
    public bool AllowLoopback { get; set; }

    /// <summary>
    /// Allow link-local / cloud-metadata addresses (169.254.0.0/16, fd00:ec2::/*).
    /// Off by default — enabling this removes SSRF-pivot protection.
    /// </summary>
    public bool AllowLinkLocalAndMetadata { get; set; }

    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
}
