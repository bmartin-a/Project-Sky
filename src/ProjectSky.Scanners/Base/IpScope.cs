using System.Net;
using System.Net.Sockets;

namespace ProjectSky.Scanners.Base;

/// <summary>
/// Classifies IP addresses into scope categories used by <c>TargetAuthorizer</c>.
/// Blocking these by default is what prevents the scanner from being pointed at
/// internal infrastructure or used as an SSRF pivot.
/// </summary>
public static class IpScope
{
    public static bool IsLoopback(IPAddress ip) => IPAddress.IsLoopback(ip);

    /// <summary>RFC 1918 (IPv4) and RFC 4193 unique-local (IPv6 fc00::/7).</summary>
    public static bool IsPrivate(IPAddress ip)
    {
        if (ip.AddressFamily == AddressFamily.InterNetwork)
        {
            var b = ip.GetAddressBytes();
            return b[0] == 10
                || (b[0] == 172 && b[1] >= 16 && b[1] <= 31)
                || (b[0] == 192 && b[1] == 168);
        }
        if (ip.AddressFamily == AddressFamily.InterNetworkV6)
        {
            if (ip.IsIPv4MappedToIPv6) return IsPrivate(ip.MapToIPv4());
            var b = ip.GetAddressBytes();
            return (b[0] & 0xFE) == 0xFC; // fc00::/7
        }
        return false;
    }

    /// <summary>Link-local ranges plus cloud-metadata addresses.</summary>
    public static bool IsLinkLocalOrMetadata(IPAddress ip)
    {
        if (ip.AddressFamily == AddressFamily.InterNetwork)
        {
            var b = ip.GetAddressBytes();
            return b[0] == 169 && b[1] == 254; // 169.254.0.0/16 (incl. 169.254.169.254)
        }
        if (ip.AddressFamily == AddressFamily.InterNetworkV6)
        {
            if (ip.IsIPv4MappedToIPv6) return IsLinkLocalOrMetadata(ip.MapToIPv4());
            return ip.IsIPv6LinkLocal;
        }
        return false;
    }

    /// <summary>True when the address is in any category blocked by default.</summary>
    public static bool IsRestrictedByDefault(IPAddress ip) =>
        IsLoopback(ip) || IsPrivate(ip) || IsLinkLocalOrMetadata(ip);

    /// <summary>Returns true if <paramref name="ip"/> falls within the given CIDR block.</summary>
    public static bool CidrContains(string cidr, IPAddress ip)
    {
        var parts = cidr.Split('/');
        if (parts.Length != 2
            || !IPAddress.TryParse(parts[0], out var network)
            || !int.TryParse(parts[1], out var prefix))
            return false;

        if (network.AddressFamily != ip.AddressFamily) return false;

        var netBytes = network.GetAddressBytes();
        var ipBytes = ip.GetAddressBytes();
        if (netBytes.Length != ipBytes.Length) return false;

        var maxPrefix = netBytes.Length * 8;
        if (prefix < 0 || prefix > maxPrefix) return false;

        var fullBytes = prefix / 8;
        for (var i = 0; i < fullBytes; i++)
            if (netBytes[i] != ipBytes[i]) return false;

        var remainingBits = prefix % 8;
        if (remainingBits == 0) return true;

        var mask = (byte)(0xFF << (8 - remainingBits));
        return (netBytes[fullBytes] & mask) == (ipBytes[fullBytes] & mask);
    }
}
