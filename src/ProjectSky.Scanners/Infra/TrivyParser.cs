using System.Text.Json;

namespace ProjectSky.Scanners.Infra;

/// <summary>One vulnerability from Trivy's JSON output.</summary>
public sealed record TrivyVuln(
    string VulnerabilityId,
    string? PkgName,
    string? InstalledVersion,
    string? Severity,
    string? Title,
    string? Description,
    string? PrimaryUrl);

/// <summary>
/// Parses Trivy's <c>--format json</c> image-scan output into neutral records.
/// Defensive against missing fields; unknown structure yields an empty list.
/// </summary>
public static class TrivyParser
{
    public static IReadOnlyList<TrivyVuln> Parse(string stdout)
    {
        var vulns = new List<TrivyVuln>();
        if (string.IsNullOrWhiteSpace(stdout)) return vulns;

        JsonDocument doc;
        try { doc = JsonDocument.Parse(stdout); }
        catch (JsonException) { return vulns; }

        using (doc)
        {
            if (!doc.RootElement.TryGetProperty("Results", out var results) ||
                results.ValueKind != JsonValueKind.Array)
                return vulns;

            foreach (var result in results.EnumerateArray())
            {
                if (!result.TryGetProperty("Vulnerabilities", out var vs) ||
                    vs.ValueKind != JsonValueKind.Array)
                    continue;

                foreach (var v in vs.EnumerateArray())
                {
                    var id = Str(v, "VulnerabilityID");
                    if (id is null) continue;
                    vulns.Add(new TrivyVuln(
                        id,
                        Str(v, "PkgName"),
                        Str(v, "InstalledVersion"),
                        Str(v, "Severity"),
                        Str(v, "Title"),
                        Str(v, "Description"),
                        Str(v, "PrimaryURL")));
                }
            }
        }

        return vulns;
    }

    private static string? Str(JsonElement el, string prop) =>
        el.TryGetProperty(prop, out var v) && v.ValueKind == JsonValueKind.String
            ? v.GetString()
            : null;
}
