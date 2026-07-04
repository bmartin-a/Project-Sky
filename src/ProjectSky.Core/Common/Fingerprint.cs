using System.Security.Cryptography;
using System.Text;

namespace ProjectSky.Core.Common;

/// <summary>
/// Deterministic content hashing for finding deduplication. The same inputs
/// always produce the same fingerprint, so re-observing a finding (by a scan or
/// by ingestion) reconciles to the existing row instead of duplicating.
/// </summary>
public static class Fingerprint
{
    public static string Compute(params string?[] parts)
    {
        var joined = string.Join('|', parts.Select(p => p?.Trim().ToLowerInvariant() ?? ""));
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(joined));
        return Convert.ToHexStringLower(hash);
    }
}
