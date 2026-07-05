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
    // Reserved/special IPv4 ranges that must never be scanned regardless of
    // policy (unspecified, CGNAT, TEST-NET, benchmarking, multicast, future-use).
    private static readonly string[] ReservedV4 =
    [
        "0.0.0.0/8",        // "this host" — connect(0.0.0.0) reaches localhost on Linux
        "100.64.0.0/10",    // CGNAT
        "192.0.0.0/24",     // IETF protocol assignments
        "192.0.2.0/24",     // TEST-NET-1
        "198.18.0.0/15",    // benchmarking
        "198.51.100.0/24",  // TEST-NET-2
        "203.0.113.0/24",   // TEST-NET-3
        "224.0.0.0/4",      // multicast
        "240.0.0.0/4",      // reserved / future use (incl. 255.255.255.255)
    ];

    public static bool IsLoopback(IPAddress ip) => IPAddress.IsLoopback(Canonical(ip));

    /// <summary>RFC 1918 (IPv4) and RFC 4193 unique-local (IPv6 fc00::/7).</summary>
    public static bool IsPrivate(IPAddress ip)
    {
        ip = Canonical(ip);
        if (ip.AddressFamily == AddressFamily.InterNetwork)
        {
            var b = ip.GetAddressBytes();
            return b[0] == 10
                || (b[0] == 172 && b[1] >= 16 && b[1] <= 31)
                || (b[0] == 192 && b[1] == 168);
        }
        if (ip.AddressFamily == AddressFamily.InterNetworkV6)
        {
            var b = ip.GetAddressBytes();
            return (b[0] & 0xFE) == 0xFC; // fc00::/7
        }
        return false;
    }

    /// <summary>Link-local ranges plus cloud-metadata addresses.</summary>
    public static bool IsLinkLocalOrMetadata(IPAddress ip)
    {
        ip = Canonical(ip);
        if (ip.AddressFamily == AddressFamily.InterNetwork)
        {
            var b = ip.GetAddressBytes();
            return b[0] == 169 && b[1] == 254; // 169.254.0.0/16 (incl. 169.254.169.254)
        }
        if (ip.AddressFamily == AddressFamily.InterNetworkV6)
            return ip.IsIPv6LinkLocal;
        return false;
    }

    /// <summary>
    /// Reserved/special-purpose ranges that are blocked unconditionally (there is
    /// no policy flag to allow them).
    /// </summary>
    public static bool IsReserved(IPAddress ip)
    {
        ip = Canonical(ip);
        if (ip.AddressFamily == AddressFamily.InterNetwork)
            return ReservedV4.Any(cidr => CidrContains(cidr, ip));
        if (ip.AddressFamily == AddressFamily.InterNetworkV6)
        {
            if (ip.Equals(IPAddress.IPv6Any)) return true;      // ::
            if (ip.IsIPv6Multicast) return true;                // ff00::/8
            if (CidrContains("64:ff9b::/96", ip)) return true;  // NAT64 (embeds an IPv4)
            return false;
        }
        return true; // unknown family — refuse
    }

    /// <summary>True when the address is in any category blocked by default.</summary>
    public static bool IsRestrictedByDefault(IPAddress ip) =>
        IsLoopback(ip) || IsPrivate(ip) || IsLinkLocalOrMetadata(ip) || IsReserved(ip);

    /// <summary>Normalizes IPv4-mapped IPv6 (::ffff:a.b.c.d) to its IPv4 form.</summary>
    private static IPAddress Canonical(IPAddress ip) =>
        ip.AddressFamily == AddressFamily.InterNetworkV6 && ip.IsIPv4MappedToIPv6
            ? ip.MapToIPv4()
            : ip;

    /// <summary>Returns true if <paramref name="ip"/> falls within the given CIDR block.</summary>
    public static bool CidrContains(string cidr, IPAddress ip)
    {
        var parts = cidr.Split('/');
        if (parts.Length != 2
            || !IPAddress.TryParse(parts[0], out var network)
            || !int.TryParse(parts[1], out var prefix))
            return false;

        ip = Canonical(ip);
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
