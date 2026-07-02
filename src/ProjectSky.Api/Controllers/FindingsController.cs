using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using ProjectSky.Api.Contracts;
using ProjectSky.Core.Interfaces;

namespace ProjectSky.Api.Controllers;

[ApiController]
[Authorize]
public sealed class FindingsController : ControllerBase
{
    private readonly IFindingRepository _findings;

    public FindingsController(IFindingRepository findings) => _findings = findings;

    [HttpGet("api/scans/{scanId:guid}/findings")]
    public async Task<IReadOnlyList<FindingResponse>> ByScan(Guid scanId, CancellationToken ct) =>
        (await _findings.ListByScanAsync(scanId, ct)).Select(FindingResponse.From).ToList();

    [HttpGet("api/targets/{targetId:guid}/findings")]
    public async Task<IReadOnlyList<FindingResponse>> OpenByTarget(Guid targetId, CancellationToken ct) =>
        (await _findings.ListOpenByTargetAsync(targetId, ct)).Select(FindingResponse.From).ToList();
}
