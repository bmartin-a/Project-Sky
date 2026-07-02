using System.Security.Claims;
using System.Text.Json;
using Hangfire;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using ProjectSky.Api.Contracts;
using ProjectSky.Core.Entities;
using ProjectSky.Core.Interfaces;
using ProjectSky.Infrastructure.Jobs;

namespace ProjectSky.Api.Controllers;

[ApiController]
[Route("api/scans")]
[Authorize]
public sealed class ScansController : ControllerBase
{
    private readonly IScanRepository _scans;
    private readonly ITargetRepository _targets;
    private readonly ITargetAuthorizer _authorizer;
    private readonly IBackgroundJobClient _jobs;

    public ScansController(
        IScanRepository scans,
        ITargetRepository targets,
        ITargetAuthorizer authorizer,
        IBackgroundJobClient jobs)
    {
        _scans = scans;
        _targets = targets;
        _authorizer = authorizer;
        _jobs = jobs;
    }

    [HttpGet]
    public async Task<IReadOnlyList<ScanResponse>> List(CancellationToken ct) =>
        (await _scans.ListAsync(ct)).Select(ScanResponse.From).ToList();

    [HttpGet("{id:guid}")]
    public async Task<ActionResult<ScanResponse>> Get(Guid id, CancellationToken ct)
    {
        var scan = await _scans.GetAsync(id, ct);
        return scan is null ? NotFound() : ScanResponse.From(scan);
    }

    [HttpPost]
    public async Task<ActionResult<ScanResponse>> Create(CreateScanRequest request, CancellationToken ct)
    {
        var target = await _targets.GetAsync(request.TargetId, ct);
        if (target is null)
            return NotFound(new { error = "Target not found." });

        // Fail fast: reject out-of-scope targets before queuing anything. The
        // job re-checks authorization at execution time as well.
        var auth = await _authorizer.AuthorizeAsync(target, ct);
        if (!auth.IsAllowed)
            return BadRequest(new { error = auth.Reason });

        var scan = new Scan
        {
            TargetId = target.Id,
            Type = request.Type,
            OptionsJson = request.Options is null ? null : JsonSerializer.Serialize(request.Options),
            CreatedBySubject = User.FindFirstValue(ClaimTypes.NameIdentifier) ?? User.FindFirstValue("sub"),
        };

        await _scans.AddAsync(scan, ct);
        await _scans.SaveChangesAsync(ct);

        _jobs.Enqueue<IScanExecutionJob>(j => j.RunAsync(scan.Id, CancellationToken.None));

        return AcceptedAtAction(nameof(Get), new { id = scan.Id }, ScanResponse.From(scan));
    }
}
