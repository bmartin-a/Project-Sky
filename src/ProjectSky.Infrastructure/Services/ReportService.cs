using System.Text;
using ProjectSky.Core.Entities;
using ProjectSky.Core.Models;

namespace ProjectSky.Infrastructure.Services;

/// <summary>
/// Renders scan findings to exportable formats. CSV and HTML are produced here;
/// JSON export is served directly from the DTOs. The HTML report is
/// self-contained and print-to-PDF friendly.
/// </summary>
public sealed class ReportService
{
    private static readonly string[] Header =
    [
        "Id", "Title", "Severity", "State", "Source", "Port", "Protocol",
        "Service", "ServiceVersion", "CVE", "RiskScore", "RiskBand",
        "FirstSeen", "LastSeen",
    ];

    public string BuildCsv(IEnumerable<Finding> findings)
    {
        var sb = new StringBuilder();
        sb.AppendLine(string.Join(',', Header));

        foreach (var f in findings)
        {
            sb.AppendLine(string.Join(',',
                Csv(f.Id.ToString()),
                Csv(f.Title),
                Csv(f.Severity.ToString()),
                Csv(f.State.ToString()),
                Csv(f.Source),
                Csv(f.Port?.ToString()),
                Csv(f.Protocol),
                Csv(f.Service),
                Csv(f.ServiceVersion),
                Csv(f.CveId),
                Csv(f.RiskScore.ToString()),
                Csv(RiskScore.BandFor(f.RiskScore)),
                Csv(f.FirstSeenAt.ToString("o")),
                Csv(f.LastSeenAt.ToString("o"))));
        }

        return sb.ToString();
    }

    public string BuildHtml(Scan scan, Target? target, IReadOnlyList<Finding> findings)
    {
        var rows = new StringBuilder();
        foreach (var f in findings.OrderByDescending(x => x.RiskScore))
        {
            rows.Append("<tr>")
                .Append($"<td>{SeverityCell(f.Severity.ToString())}</td>")
                .Append($"<td>{Html(f.Title)}</td>")
                .Append($"<td>{Html(f.Service)}{(f.Port is { } p ? $" :{p}" : "")}</td>")
                .Append($"<td>{Cve(f.CveId)}</td>")
                .Append($"<td>{f.RiskScore} · {Html(RiskScore.BandFor(f.RiskScore))}</td>")
                .Append($"<td>{Html(f.State.ToString())}</td>")
                .Append("</tr>");
        }

        var counts = findings
            .GroupBy(f => f.Severity)
            .ToDictionary(g => g.Key.ToString(), g => g.Count());
        var summary = string.Join(" · ",
            counts.OrderByDescending(kv => kv.Key).Select(kv => $"{kv.Key}: {kv.Value}"));

        return $$"""
            <!doctype html>
            <html lang="en"><head><meta charset="utf-8">
            <title>Project-Sky report — {{Html(target?.Address)}}</title>
            <style>
              body { font-family: system-ui, sans-serif; margin: 2rem; color: #111; }
              h1 { font-size: 1.4rem; } .meta { color: #555; font-size: .9rem; margin-bottom: 1rem; }
              table { border-collapse: collapse; width: 100%; font-size: .9rem; }
              th, td { text-align: left; padding: .5rem .6rem; border-bottom: 1px solid #ddd; }
              th { background: #f5f5f5; }
              .sev { font-weight: 600; padding: .1rem .4rem; border-radius: .25rem; color: #fff; }
              .Critical { background: #dc2626; } .High { background: #ea580c; }
              .Medium { background: #d97706; } .Low { background: #2563eb; } .Info { background: #6b7280; }
            </style></head><body>
              <h1>Project-Sky scan report</h1>
              <div class="meta">
                Target: <strong>{{Html(target?.Address ?? "—")}}</strong> ·
                Type: {{scan.Type}} · Status: {{scan.Status}} ·
                Completed: {{scan.CompletedAt?.ToString("u") ?? "—"}}<br>
                {{findings.Count}} finding(s) — {{Html(summary)}}
              </div>
              <table>
                <thead><tr><th>Severity</th><th>Finding</th><th>Service</th>
                <th>CVE</th><th>Risk</th><th>State</th></tr></thead>
                <tbody>{{rows}}</tbody>
              </table>
            </body></html>
            """;
    }

    private static string Csv(string? value)
    {
        value ??= "";

        // Neutralize spreadsheet formula injection: a leading =, +, -, @, or a
        // control char makes Excel/LibreOffice evaluate the cell. Prefix with a
        // single quote so it's treated as text.
        if (value.Length > 0 && value[0] is '=' or '+' or '-' or '@' or '\t' or '\r')
            value = "'" + value;

        if (value.Contains(',') || value.Contains('"') || value.Contains('\n') || value.Contains('\r'))
            return "\"" + value.Replace("\"", "\"\"") + "\"";
        return value;
    }

    private static string Html(string? value) => System.Net.WebUtility.HtmlEncode(value ?? "");

    private static string SeverityCell(string severity) =>
        $"<span class=\"sev {Html(severity)}\">{Html(severity)}</span>";

    private static string Cve(string? cveId) =>
        cveId is null
            ? "—"
            : $"<a href=\"https://nvd.nist.gov/vuln/detail/{Html(cveId)}\">{Html(cveId)}</a>";
}
