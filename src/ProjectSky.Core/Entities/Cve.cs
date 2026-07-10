using ProjectSky.Core.Enums;

namespace ProjectSky.Core.Entities;

/// <summary>A CVE record mirrored from the NVD.</summary>
public class Cve
{
    /// <summary>Natural key, e.g. "CVE-2021-44228".</summary>
    public required string Id { get; set; }

    public string? Description { get; set; }

    public double? CvssV3BaseScore { get; set; }
    public string? CvssV3Vector { get; set; }
    public Severity Severity { get; set; } = Severity.Info;

    /// <summary>EPSS exploit-probability score (0–1), if known.</summary>
    public double? EpssScore { get; set; }

    /// <summary>True when a public/known exploit exists (NVD refs, CISA KEV).</summary>
    public bool HasKnownExploit { get; set; }

    public DateTimeOffset? PublishedAt { get; set; }
    public DateTimeOffset? LastModifiedAt { get; set; }

    /// <summary>CPE applicability rows used to match detected software to this CVE.</summary>
    public ICollection<CpeMatch> CpeMatches { get; set; } = new List<CpeMatch>();
}

/// <summary>
/// A single CPE applicability statement for a CVE, including optional version
/// range bounds. Matching logic lives in <c>CpeMatcher</c>.
/// </summary>
public class CpeMatch
{
    public Guid Id { get; set; } = Guid.NewGuid();

    public required string CveId { get; set; }
    public Cve? Cve { get; set; }

    /// <summary>CPE 2.3 criteria string, e.g. "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*".</summary>
    public required string Criteria { get; set; }

    public bool Vulnerable { get; set; } = true;

    public string? VersionStartIncluding { get; set; }
    public string? VersionStartExcluding { get; set; }
    public string? VersionEndIncluding { get; set; }
    public string? VersionEndExcluding { get; set; }
}
