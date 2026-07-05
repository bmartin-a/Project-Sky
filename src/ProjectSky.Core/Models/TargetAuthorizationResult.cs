using System.Net;

namespace ProjectSky.Core.Models;

/// <summary>
/// Outcome of authorizing a target for scanning. When allowed, <see cref="ResolvedIps"/>
/// carries the IPs the authorizer resolved and scope-checked, so the scan can
/// connect to one of those exact addresses instead of re-resolving the hostname
/// (which would reopen a DNS-rebinding window).
/// </summary>
public readonly record struct TargetAuthorizationResult(
    bool IsAllowed,
    string? Reason,
    IReadOnlyList<IPAddress>? ResolvedIps = null)
{
    public static TargetAuthorizationResult Allowed(IReadOnlyList<IPAddress>? resolvedIps = null) =>
        new(true, null, resolvedIps);

    public static TargetAuthorizationResult Denied(string reason) => new(false, reason);
}
