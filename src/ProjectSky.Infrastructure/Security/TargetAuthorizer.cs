using System.Net;
using System.Net.Sockets;
using ProjectSky.Core.Entities;
using ProjectSky.Core.Enums;
using ProjectSky.Core.Interfaces;
using ProjectSky.Core.Models;
using ProjectSky.Scanners.Base;

namespace ProjectSky.Infrastructure.Security;

/// <summary>
/// Enforces scan scope. A target is only authorized when (1) its address is
/// well-formed, (2) it matches an explicit allowlist entry in some
/// <see cref="ScanPolicy"/>, and (3) every IP it resolves to is permitted by
/// that policy. Private/loopback/link-local/metadata addresses are blocked
/// unless the matching policy opts in — this is what stops the scanner being
/// aimed at internal hosts or used as an SSRF pivot (including via a hostname
/// that resolves to an internal IP).
/// </summary>
public sealed class TargetAuthorizer : ITargetAuthorizer
{
    private static readonly TimeSpan DnsTimeout = TimeSpan.FromSeconds(5);
    private readonly IScanPolicyRepository _policies;

    public TargetAuthorizer(IScanPolicyRepository policies) => _policies = policies;

    public async Task<TargetAuthorizationResult> AuthorizeAsync(Target target, CancellationToken ct)
    {
        var validation = TargetValidator.Validate(target.Address, target.Type);
        if (!validation.IsValid || validation.Normalized is null)
            return TargetAuthorizationResult.Denied(validation.Error ?? "Invalid target.");
        var address = validation.Normalized;

        var policies = await _policies.ListAsync(ct);
        if (policies.Count == 0)
            return TargetAuthorizationResult.Denied(
                "No scan policy is defined; scanning is disabled by default.");

        var host = HostOf(target.Type, address);

        var matched = policies.FirstOrDefault(p =>
            p.AllowedTargets.Any(entry => AllowlistMatches(entry, host, address)));
        if (matched is null)
            return TargetAuthorizationResult.Denied(
                $"Target '{host}' is not in any scan policy allowlist.");

        // Container images are pulled from a registry, not probed over the network,
        // so IP-scope checks don't apply — the allowlist governs which images.
        if (target.Type == TargetType.ContainerImage)
            return TargetAuthorizationResult.Allowed();

        var ips = await ResolveAsync(host, target.Type, address, ct);
        if (ips.Count == 0)
            return TargetAuthorizationResult.Denied($"Could not resolve '{host}' to an IP address.");

        foreach (var ip in ips)
        {
            if (IpScope.IsLoopback(ip) && !matched.AllowLoopback)
                return TargetAuthorizationResult.Denied($"Loopback address {ip} is blocked by policy.");
            if (IpScope.IsPrivate(ip) && !matched.AllowPrivateRanges)
                return TargetAuthorizationResult.Denied($"Private address {ip} is blocked by policy.");
            if (IpScope.IsLinkLocalOrMetadata(ip) && !matched.AllowLinkLocalAndMetadata)
                return TargetAuthorizationResult.Denied($"Link-local/metadata address {ip} is blocked by policy.");
        }

        return TargetAuthorizationResult.Allowed();
    }

    private static string HostOf(TargetType type, string address) => type switch
    {
        TargetType.Url => new Uri(address).Host,
        TargetType.CidrRange => address.Split('/')[0],
        _ => address,
    };

    private static bool AllowlistMatches(string entry, string host, string address)
    {
        entry = entry.Trim();
        if (entry.Length == 0) return false;
        if (string.Equals(entry, host, StringComparison.OrdinalIgnoreCase)) return true;
        if (string.Equals(entry, address, StringComparison.OrdinalIgnoreCase)) return true;

        // A CIDR allowlist entry matches a target IP within its range.
        if (entry.Contains('/') && IPAddress.TryParse(host, out var ip))
            return IpScope.CidrContains(entry, ip);

        return false;
    }

    private static async Task<IReadOnlyList<IPAddress>> ResolveAsync(
        string host, TargetType type, string address, CancellationToken ct)
    {
        switch (type)
        {
            case TargetType.IpAddress when IPAddress.TryParse(address, out var ip):
                return [ip];
            case TargetType.CidrRange when IPAddress.TryParse(host, out var netIp):
                return [netIp];
            default:
                if (IPAddress.TryParse(host, out var literal))
                    return [literal];
                try
                {
                    using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                    cts.CancelAfter(DnsTimeout);
                    var resolved = await Dns.GetHostAddressesAsync(host, cts.Token);
                    return resolved
                        .Where(a => a.AddressFamily is AddressFamily.InterNetwork or AddressFamily.InterNetworkV6)
                        .ToList();
                }
                catch
                {
                    return [];
                }
        }
    }
}
