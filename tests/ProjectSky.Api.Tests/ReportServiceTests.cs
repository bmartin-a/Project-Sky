using ProjectSky.Core.Entities;
using ProjectSky.Core.Enums;
using ProjectSky.Infrastructure.Services;
using Xunit;

namespace ProjectSky.Api.Tests;

public class ReportServiceTests
{
    private readonly ReportService _svc = new();

    private static Finding Finding(string title, Severity sev = Severity.High) => new()
    {
        Title = title,
        Severity = sev,
        Fingerprint = "fp",
        Source = "Scan",
        RiskScore = 800,
    };

    [Fact]
    public void Csv_has_header_and_row_per_finding()
    {
        var csv = _svc.BuildCsv([Finding("Open port 80"), Finding("Weak TLS")]);
        var lines = csv.Trim().Split('\n');

        Assert.StartsWith("Id,Title,Severity", lines[0]);
        Assert.Equal(3, lines.Length); // header + 2 rows
    }

    [Fact]
    public void Csv_escapes_fields_containing_commas()
    {
        var csv = _svc.BuildCsv([Finding("Open port, insecure")]);
        Assert.Contains("\"Open port, insecure\"", csv);
    }

    [Fact]
    public void Html_report_includes_target_and_findings()
    {
        var target = new Target { Address = "example.com", Type = TargetType.Hostname };
        var scan = new Scan { TargetId = target.Id, Type = ScanType.Web, Status = ScanStatus.Completed };
        var html = _svc.BuildHtml(scan, target, [Finding("Reflected XSS")]);

        Assert.Contains("example.com", html);
        Assert.Contains("Reflected XSS", html);
        Assert.Contains("<table", html);
    }
}
