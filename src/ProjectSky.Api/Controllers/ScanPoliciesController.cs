using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using ProjectSky.Api.Contracts;
using ProjectSky.Core.Entities;
using ProjectSky.Core.Interfaces;

namespace ProjectSky.Api.Controllers;

[ApiController]
[Route("api/scan-policies")]
[Authorize]
public sealed class ScanPoliciesController : ControllerBase
{
    private readonly IScanPolicyRepository _repo;

    public ScanPoliciesController(IScanPolicyRepository repo) => _repo = repo;

    [HttpGet]
    public async Task<IReadOnlyList<ScanPolicyResponse>> List(CancellationToken ct) =>
        (await _repo.ListAsync(ct)).Select(ScanPolicyResponse.From).ToList();

    [HttpPost]
    public async Task<ActionResult<ScanPolicyResponse>> Create(CreateScanPolicyRequest request, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(request.Name))
            return BadRequest(new { error = "Policy name is required." });
        if (request.AllowedTargets is null || request.AllowedTargets.Count == 0)
            return BadRequest(new { error = "A policy must list at least one allowed target." });

        var policy = new ScanPolicy
        {
            Name = request.Name,
            AllowedTargets = request.AllowedTargets,
            AllowPrivateRanges = request.AllowPrivateRanges,
            AllowLoopback = request.AllowLoopback,
            AllowLinkLocalAndMetadata = request.AllowLinkLocalAndMetadata,
        };

        await _repo.AddAsync(policy, ct);
        await _repo.SaveChangesAsync(ct);

        return CreatedAtAction(nameof(List), null, ScanPolicyResponse.From(policy));
    }
}
