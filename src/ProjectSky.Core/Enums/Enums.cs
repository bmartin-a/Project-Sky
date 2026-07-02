namespace ProjectSky.Core.Enums;

/// <summary>The category of scan, which determines the scanner plugin(s) used.</summary>
public enum ScanType
{
    Network = 0,
    Web = 1,
    Defender = 2,
    Infrastructure = 3,
}

/// <summary>Lifecycle state of a scan run.</summary>
public enum ScanStatus
{
    Queued = 0,
    Running = 1,
    Completed = 2,
    Failed = 3,
    Cancelled = 4,
    Rejected = 5,
}

/// <summary>Severity of a finding, aligned to common CVSS bands.</summary>
public enum Severity
{
    Info = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

/// <summary>
/// Lifecycle of a finding across repeated scans of the same target, produced by
/// the reconciliation service so re-scans don't create duplicate rows.
/// </summary>
public enum FindingState
{
    New = 0,
    Existing = 1,
    Resolved = 2,
}

/// <summary>Kind of scan target; drives which validation grammar is applied.</summary>
public enum TargetType
{
    Hostname = 0,
    IpAddress = 1,
    CidrRange = 2,
    Url = 3,
}

/// <summary>Business criticality of an asset, used as a risk-score multiplier.</summary>
public enum AssetCriticality
{
    Low = 0,
    Medium = 1,
    High = 2,
    Critical = 3,
}
