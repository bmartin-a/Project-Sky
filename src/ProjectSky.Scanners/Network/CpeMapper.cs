using System.Text.RegularExpressions;

namespace ProjectSky.Scanners.Network;

/// <summary>
/// Builds a best-effort CPE 2.3 string from an nmap-detected service product and
/// version. This is intentionally conservative: it produces a well-formed CPE
/// whose product/version can then be matched against NVD CPE criteria by
/// <c>CpeMatcher</c>. Vendor is left as a wildcard because nmap rarely reports it.
/// </summary>
public static partial class CpeMapper
{
    [GeneratedRegex(@"[^a-z0-9._\-]")]
    private static partial Regex UnsafeChars();

    /// <summary>
    /// Returns a CPE 2.3 URI like
    /// <c>cpe:2.3:a:*:openssh:8.2p1:*:*:*:*:*:*:*</c>, or null if there isn't
    /// enough information to form one.
    /// </summary>
    public static string? ToCpe(string? product, string? version)
    {
        var p = Normalize(product);
        if (string.IsNullOrEmpty(p))
            return null;

        var v = Normalize(version);
        var versionField = string.IsNullOrEmpty(v) ? "*" : v;

        return $"cpe:2.3:a:*:{p}:{versionField}:*:*:*:*:*:*:*";
    }

    /// <summary>Extracts the product token from a CPE 2.3 string (index 4), or null.</summary>
    public static string? ProductOf(string cpe)
    {
        var parts = cpe.Split(':');
        return parts.Length > 4 ? parts[4] : null;
    }

    private static string Normalize(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return string.Empty;
        var lower = value.Trim().ToLowerInvariant().Replace(' ', '_');
        return UnsafeChars().Replace(lower, "");
    }
}
