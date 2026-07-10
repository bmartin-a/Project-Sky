using System.Net.Http.Json;
using System.Text.Json;

namespace ProjectSky.Scanners.Web;

/// <summary>A ZAP alert (finding) from the core/alerts view.</summary>
public sealed record ZapAlert(
    string Name,
    string Risk,
    string? Description,
    string? Url,
    string? Param,
    string? Solution,
    string? CweId,
    string? PluginId);

/// <summary>
/// Thin client over the OWASP ZAP daemon REST API. Exposes just what the
/// scanner needs: spider, active scan, their progress, and alert retrieval.
/// Uses IHttpClientFactory so it is safe to hold as a singleton.
/// </summary>
public sealed class ZapClient
{
    private readonly IHttpClientFactory _factory;
    private readonly ZapOptions _options;

    public ZapClient(IHttpClientFactory factory, ZapOptions options)
    {
        _factory = factory;
        _options = options;
    }

    public async Task<bool> IsReachableAsync(CancellationToken ct)
    {
        try
        {
            var v = await GetAsync("/JSON/core/view/version/", null, ct);
            return v.TryGetProperty("version", out _);
        }
        catch
        {
            return false;
        }
    }

    public async Task<string> StartSpiderAsync(string url, CancellationToken ct)
    {
        var el = await GetAsync("/JSON/spider/action/scan/",
            new() { ["url"] = url, ["recurse"] = "true" }, ct);
        return el.GetProperty("scan").GetString() ?? "0";
    }

    public Task<int> SpiderStatusAsync(string scanId, CancellationToken ct) =>
        StatusAsync("/JSON/spider/view/status/", scanId, ct);

    public async Task<string> StartActiveScanAsync(string url, CancellationToken ct)
    {
        var el = await GetAsync("/JSON/ascan/action/scan/",
            new() { ["url"] = url, ["recurse"] = "true", ["inScopeOnly"] = "false" }, ct);
        return el.GetProperty("scan").GetString() ?? "0";
    }

    public Task<int> ActiveScanStatusAsync(string scanId, CancellationToken ct) =>
        StatusAsync("/JSON/ascan/view/status/", scanId, ct);

    public async Task<IReadOnlyList<ZapAlert>> AlertsAsync(string baseUrl, CancellationToken ct)
    {
        var el = await GetAsync("/JSON/core/view/alerts/",
            new() { ["baseurl"] = baseUrl }, ct);

        var alerts = new List<ZapAlert>();
        if (el.TryGetProperty("alerts", out var arr) && arr.ValueKind == JsonValueKind.Array)
        {
            foreach (var a in arr.EnumerateArray())
            {
                alerts.Add(new ZapAlert(
                    Name: Str(a, "alert") ?? Str(a, "name") ?? "ZAP alert",
                    Risk: Str(a, "risk") ?? "Informational",
                    Description: Str(a, "description"),
                    Url: Str(a, "url"),
                    Param: Str(a, "param"),
                    Solution: Str(a, "solution"),
                    CweId: Str(a, "cweid"),
                    PluginId: Str(a, "pluginId")));
            }
        }
        return alerts;
    }

    private async Task<int> StatusAsync(string path, string scanId, CancellationToken ct)
    {
        var el = await GetAsync(path, new() { ["scanId"] = scanId }, ct);
        return el.TryGetProperty("status", out var s) && int.TryParse(s.GetString(), out var pct)
            ? pct
            : 0;
    }

    private async Task<JsonElement> GetAsync(
        string path, Dictionary<string, string>? query, CancellationToken ct)
    {
        var q = new List<string> { $"apikey={Uri.EscapeDataString(_options.ApiKey)}" };
        if (query is not null)
            foreach (var (k, v) in query)
                q.Add($"{k}={Uri.EscapeDataString(v)}");

        var url = $"{_options.BaseUrl.TrimEnd('/')}{path}?{string.Join('&', q)}";
        var http = _factory.CreateClient("zap");
        using var resp = await http.GetAsync(url, ct);
        resp.EnsureSuccessStatusCode();
        var doc = await resp.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: ct);
        return doc;
    }

    private static string? Str(JsonElement el, string prop) =>
        el.TryGetProperty(prop, out var v) && v.ValueKind == JsonValueKind.String
            ? v.GetString()
            : null;
}
