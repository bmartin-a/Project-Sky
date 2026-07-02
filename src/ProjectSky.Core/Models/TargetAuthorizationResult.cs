namespace ProjectSky.Core.Models;

/// <summary>Outcome of authorizing a target for scanning.</summary>
public readonly record struct TargetAuthorizationResult(bool IsAllowed, string? Reason)
{
    public static TargetAuthorizationResult Allowed() => new(true, null);
    public static TargetAuthorizationResult Denied(string reason) => new(false, reason);
}
