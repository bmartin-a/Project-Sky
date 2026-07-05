using Hangfire;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using ProjectSky.Api.Auth;
using ProjectSky.Infrastructure.Defender;
using ProjectSky.Infrastructure.Jobs;

namespace ProjectSky.Api.Controllers;

[ApiController]
[Route("api/integrations")]
[Authorize]
public sealed class IntegrationsController : ControllerBase
{
    private readonly DefenderOptions _defender;
    private readonly IBackgroundJobClient _jobs;

    public IntegrationsController(DefenderOptions defender, IBackgroundJobClient jobs)
    {
        _defender = defender;
        _jobs = jobs;
    }

    [HttpGet]
    public object Get() => new { defenderConfigured = _defender.IsConfigured };

    /// <summary>Triggers a Defender ingestion run on demand (also runs on a schedule).</summary>
    [HttpPost("defender/sync")]
    [Authorize(Policy = AuthSetup.AdminPolicy)]
    public IActionResult SyncDefender()
    {
        if (!_defender.IsConfigured)
            return BadRequest(new { error = "Defender ingestion is not configured." });

        _jobs.Enqueue<IDefenderIngestionJob>(j => j.RunAsync(CancellationToken.None));
        return Accepted(new { status = "queued" });
    }
}
