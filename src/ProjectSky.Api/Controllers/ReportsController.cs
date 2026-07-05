using System.Text;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using ProjectSky.Api.Contracts;
using ProjectSky.Core.Interfaces;
using ProjectSky.Infrastructure.Services;

namespace ProjectSky.Api.Controllers;

[ApiController]
[Route("api/scans/{scanId:guid}/report")]
[Authorize]
public sealed class ReportsController : ControllerBase
{
    private readonly IScanRepository _scans;
    private readonly IFindingRepository _findings;
    private readonly ITargetRepository _targets;
    private readonly ReportService _reports;

    public ReportsController(
        IScanRepository scans,
        IFindingRepository findings,
        ITargetRepository targets,
        ReportService reports)
    {
        _scans = scans;
        _findings = findings;
        _targets = targets;
        _reports = reports;
    }

    [HttpGet("json")]
    public async Task<ActionResult<IReadOnlyList<FindingResponse>>> Json(Guid scanId, CancellationToken ct)
    {
        if (await _scans.GetAsync(scanId, ct) is null) return NotFound();
        var findings = await _findings.ListByScanAsync(scanId, ct);
        return findings.Select(FindingResponse.From).ToList();
    }

    [HttpGet("csv")]
    public async Task<IActionResult> Csv(Guid scanId, CancellationToken ct)
    {
        if (await _scans.GetAsync(scanId, ct) is null) return NotFound();
        var findings = await _findings.ListByScanAsync(scanId, ct);
        var csv = _reports.BuildCsv(findings);
        return File(Encoding.UTF8.GetBytes(csv), "text/csv", $"scan-{scanId}.csv");
    }

    [HttpGet("html")]
    public async Task<IActionResult> Html(Guid scanId, CancellationToken ct)
    {
        var scan = await _scans.GetAsync(scanId, ct);
        if (scan is null) return NotFound();
        var target = await _targets.GetAsync(scan.TargetId, ct);
        var findings = await _findings.ListByScanAsync(scanId, ct);
        return Content(_reports.BuildHtml(scan, target, findings), "text/html");
    }
}
