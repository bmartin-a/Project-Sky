using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using ProjectSky.Api.Contracts;
using ProjectSky.Core.Entities;
using ProjectSky.Core.Interfaces;
using ProjectSky.Scanners.Base;

namespace ProjectSky.Api.Controllers;

[ApiController]
[Route("api/targets")]
[Authorize]
public sealed class TargetsController : ControllerBase
{
    private readonly ITargetRepository _repo;

    public TargetsController(ITargetRepository repo) => _repo = repo;

    [HttpGet]
    public async Task<IReadOnlyList<TargetResponse>> List(CancellationToken ct) =>
        (await _repo.ListAsync(ct)).Select(TargetResponse.From).ToList();

    [HttpGet("{id:guid}")]
    public async Task<ActionResult<TargetResponse>> Get(Guid id, CancellationToken ct)
    {
        var target = await _repo.GetAsync(id, ct);
        return target is null ? NotFound() : TargetResponse.From(target);
    }

    [HttpPost]
    public async Task<ActionResult<TargetResponse>> Create(CreateTargetRequest request, CancellationToken ct)
    {
        // Reject malformed addresses up front (defence in depth; the authorizer
        // and scanner also validate).
        var validation = TargetValidator.Validate(request.Address, request.Type);
        if (!validation.IsValid)
            return BadRequest(new { error = validation.Error });

        var target = new Target
        {
            Address = validation.Normalized!,
            Type = request.Type,
            Criticality = request.Criticality,
            Name = request.Name,
        };

        await _repo.AddAsync(target, ct);
        await _repo.SaveChangesAsync(ct);

        return CreatedAtAction(nameof(Get), new { id = target.Id }, TargetResponse.From(target));
    }
}
