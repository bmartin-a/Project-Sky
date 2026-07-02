using ProjectSky.Core.Entities;
using ProjectSky.Core.Models;

namespace ProjectSky.Core.Interfaces;

/// <summary>
/// Decides whether a target may be scanned, enforcing scan-policy scope and the
/// default blocks on private/loopback/link-local/metadata addresses.
/// </summary>
public interface ITargetAuthorizer
{
    Task<TargetAuthorizationResult> AuthorizeAsync(Target target, CancellationToken ct);
}
