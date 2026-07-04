using System.Text.Json;

namespace ProjectSky.Scanners.Web;

/// <summary>One parsed result line from nuclei's JSONL output.</summary>
public sealed record NucleiResult(
    string TemplateId,
    string? Name,
    string? Severity,
    string? Description,
    string? MatchedAt,
    string? CveId);

/// <summary>
/// Parses nuclei's JSONL output (<c>-jsonl</c>): one JSON object per line. Lines
/// that aren't valid JSON (banners, blank lines) are skipped defensively.
/// </summary>
public static class NucleiResultParser
{
    public static IReadOnlyList<NucleiResult> Parse(string stdout)
    {
        var results = new List<NucleiResult>();
        if (string.IsNullOrWhiteSpace(stdout)) return results;

        foreach (var line in stdout.Split('\n'))
        {
            var trimmed = line.Trim();
            if (trimmed.Length == 0 || trimmed[0] != '{') continue;

            JsonDocument doc;
            try { doc = JsonDocument.Parse(trimmed); }
            catch (JsonException) { continue; }

            using (doc)
            {
                var root = doc.RootElement;
                var templateId =
                    GetString(root, "template-id") ?? GetString(root, "templateID");
                if (templateId is null) continue;

                string? name = null, severity = null, description = null, cveId = null;
                if (root.TryGetProperty("info", out var info) &&
                    info.ValueKind == JsonValueKind.Object)
                {
                    name = GetString(info, "name");
                    severity = GetString(info, "severity");
                    description = GetString(info, "description");
                    cveId = FirstCve(info);
                }

                results.Add(new NucleiResult(
                    templateId,
                    name,
                    severity,
                    description,
                    GetString(root, "matched-at") ?? GetString(root, "host"),
                    cveId));
            }
        }

        return results;
    }

    private static string? FirstCve(JsonElement info)
    {
        if (!info.TryGetProperty("classification", out var cls) ||
            cls.ValueKind != JsonValueKind.Object)
            return null;
        if (!cls.TryGetProperty("cve-id", out var cve)) return null;
        if (cve.ValueKind == JsonValueKind.Array && cve.GetArrayLength() > 0)
            return cve[0].GetString();
        if (cve.ValueKind == JsonValueKind.String) return cve.GetString();
        return null;
    }

    private static string? GetString(JsonElement el, string prop) =>
        el.TryGetProperty(prop, out var v) && v.ValueKind == JsonValueKind.String
            ? v.GetString()
            : null;
}
