using System.Text.Json;

namespace ProjectSky.Infrastructure.Defender;

/// <summary>A machine (device) from Defender's inventory.</summary>
public sealed record DefenderMachine(
    string Id,
    string? DnsName,
    string? IpAddress,
    string? OsPlatform,
    string? ExposureLevel);

/// <summary>A machine↔vulnerability row from Defender.</summary>
public sealed record DefenderVuln(
    string MachineId,
    string CveId,
    string? ProductName,
    string? ProductVendor,
    string? ProductVersion,
    string? Severity,
    double? CvssV3);

/// <summary>
/// Pure parsing of Microsoft Defender API responses into neutral records,
/// decoupled from HTTP and EF so it can be unit tested against sample payloads.
/// </summary>
public static class DefenderMapper
{
    public static IReadOnlyList<DefenderMachine> ParseMachines(JsonElement root)
    {
        var machines = new List<DefenderMachine>();
        foreach (var m in Values(root))
        {
            var id = Str(m, "id");
            if (id is null) continue;
            machines.Add(new DefenderMachine(
                id,
                Str(m, "computerDnsName"),
                Str(m, "lastIpAddress"),
                Str(m, "osPlatform"),
                Str(m, "exposureLevel")));
        }
        return machines;
    }

    public static IReadOnlyList<DefenderVuln> ParseVulnerabilities(JsonElement root)
    {
        var vulns = new List<DefenderVuln>();
        foreach (var v in Values(root))
        {
            var machineId = Str(v, "machineId");
            var cveId = Str(v, "cveId");
            if (machineId is null || cveId is null) continue;
            vulns.Add(new DefenderVuln(
                machineId,
                cveId,
                Str(v, "productName"),
                Str(v, "productVendor"),
                Str(v, "productVersion"),
                Str(v, "severity"),
                Num(v, "cvssV3")));
        }
        return vulns;
    }

    private static IEnumerable<JsonElement> Values(JsonElement root)
    {
        if (root.ValueKind == JsonValueKind.Array)
            return root.EnumerateArray();
        if (root.TryGetProperty("value", out var value) && value.ValueKind == JsonValueKind.Array)
            return value.EnumerateArray();
        return [];
    }

    private static string? Str(JsonElement el, string prop) =>
        el.TryGetProperty(prop, out var v) && v.ValueKind == JsonValueKind.String
            ? v.GetString()
            : null;

    private static double? Num(JsonElement el, string prop) =>
        el.TryGetProperty(prop, out var v) &&
        v.ValueKind == JsonValueKind.Number && v.TryGetDouble(out var d)
            ? d
            : null;
}
