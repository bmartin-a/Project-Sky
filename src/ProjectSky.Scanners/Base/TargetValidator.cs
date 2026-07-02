using System.Net;
using System.Net.Sockets;
using System.Text.RegularExpressions;
using ProjectSky.Core.Enums;

namespace ProjectSky.Scanners.Base;

/// <summary>Outcome of validating a raw target address.</summary>
public readonly record struct TargetValidationResult(bool IsValid, string? Normalized, string? Error)
{
    public static TargetValidationResult Ok(string normalized) => new(true, normalized, null);
    public static TargetValidationResult Fail(string error) => new(false, null, error);
}

/// <summary>
/// Validates target addresses against a strict grammar for their type. This is
/// the first line of defence: anything that isn't an exact hostname / IP / CIDR
/// / URL is rejected before it can ever reach a CLI argument. Combined with
/// <c>CliRunner</c>'s argument-vector execution, this closes command injection.
/// </summary>
public static partial class TargetValidator
{
    // RFC 1123 hostname: labels of alphanumerics/hyphen, no leading/trailing hyphen.
    [GeneratedRegex(@"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$")]
    private static partial Regex HostnameRegex();

    public static TargetValidationResult Validate(string address, TargetType type) => type switch
    {
        TargetType.Hostname => ValidateHostname(address),
        TargetType.IpAddress => ValidateIp(address),
        TargetType.CidrRange => ValidateCidr(address),
        TargetType.Url => ValidateUrl(address),
        _ => TargetValidationResult.Fail($"Unknown target type '{type}'."),
    };

    public static TargetValidationResult ValidateHostname(string address)
    {
        address = address.Trim();
        if (string.IsNullOrEmpty(address))
            return TargetValidationResult.Fail("Hostname is empty.");
        if (!HostnameRegex().IsMatch(address))
            return TargetValidationResult.Fail("Not a valid RFC 1123 hostname.");
        return TargetValidationResult.Ok(address.ToLowerInvariant());
    }

    public static TargetValidationResult ValidateIp(string address)
    {
        address = address.Trim();
        if (!IPAddress.TryParse(address, out var ip))
            return TargetValidationResult.Fail("Not a valid IP address.");
        // Reject forms IPAddress.TryParse accepts loosely (e.g. integer-only).
        if (ip.AddressFamily is not (AddressFamily.InterNetwork or AddressFamily.InterNetworkV6))
            return TargetValidationResult.Fail("Unsupported address family.");
        return TargetValidationResult.Ok(ip.ToString());
    }

    public static TargetValidationResult ValidateCidr(string address)
    {
        address = address.Trim();
        var parts = address.Split('/');
        if (parts.Length != 2)
            return TargetValidationResult.Fail("CIDR must be in the form <address>/<prefix>.");
        if (!IPAddress.TryParse(parts[0], out var ip))
            return TargetValidationResult.Fail("CIDR network address is invalid.");
        if (!int.TryParse(parts[1], out var prefix))
            return TargetValidationResult.Fail("CIDR prefix is not a number.");

        var maxPrefix = ip.AddressFamily == AddressFamily.InterNetwork ? 32 : 128;
        if (prefix < 0 || prefix > maxPrefix)
            return TargetValidationResult.Fail($"CIDR prefix must be between 0 and {maxPrefix}.");

        return TargetValidationResult.Ok($"{ip}/{prefix}");
    }

    public static TargetValidationResult ValidateUrl(string address)
    {
        address = address.Trim();
        if (!Uri.TryCreate(address, UriKind.Absolute, out var uri))
            return TargetValidationResult.Fail("Not an absolute URL.");
        if (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps)
            return TargetValidationResult.Fail("Only http and https URLs are allowed.");
        if (string.IsNullOrEmpty(uri.Host))
            return TargetValidationResult.Fail("URL has no host.");
        return TargetValidationResult.Ok(uri.ToString());
    }
}
