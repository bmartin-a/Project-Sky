using Hangfire;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using ProjectSky.Api.Auth;
using ProjectSky.Api.Contracts;
using ProjectSky.Core.Entities;
using ProjectSky.Core.Interfaces;
using ProjectSky.Infrastructure.Jobs;

namespace ProjectSky.Api.Controllers;

[ApiController]
[Route("api/schedules")]
[Authorize]
public sealed class SchedulesController : ControllerBase
{
    private readonly IScanScheduleRepository _schedules;
    private readonly ITargetRepository _targets;
    private readonly IRecurringJobManager _recurring;

    public SchedulesController(
        IScanScheduleRepository schedules,
        ITargetRepository targets,
        IRecurringJobManager recurring)
    {
        _schedules = schedules;
        _targets = targets;
        _recurring = recurring;
    }

    [HttpGet]
    public async Task<IReadOnlyList<ScanScheduleResponse>> List(CancellationToken ct) =>
        (await _schedules.ListAsync(ct)).Select(ScanScheduleResponse.From).ToList();

    [HttpPost]
    [Authorize(Policy = AuthSetup.AdminPolicy)]
    public async Task<ActionResult<ScanScheduleResponse>> Create(
        CreateScanScheduleRequest request, CancellationToken ct)
    {
        if (await _targets.GetAsync(request.TargetId, ct) is null)
            return NotFound(new { error = "Target not found." });
        if (!IsValidCron(request.Cron))
            return BadRequest(new { error = "Invalid cron expression (expected 5 or 6 fields)." });

        var schedule = new ScanSchedule
        {
            TargetId = request.TargetId,
            Type = request.Type,
            Cron = request.Cron.Trim(),
        };
        await _schedules.AddAsync(schedule, ct);
        await _schedules.SaveChangesAsync(ct);

        _recurring.AddOrUpdate<IScheduledScanJob>(
            schedule.RecurringJobId,
            j => j.RunAsync(schedule.Id, CancellationToken.None),
            schedule.Cron);

        return CreatedAtAction(nameof(List), null, ScanScheduleResponse.From(schedule));
    }

    [HttpDelete("{id:guid}")]
    [Authorize(Policy = AuthSetup.AdminPolicy)]
    public async Task<IActionResult> Delete(Guid id, CancellationToken ct)
    {
        var schedule = await _schedules.GetAsync(id, ct);
        if (schedule is null) return NotFound();

        _recurring.RemoveIfExists(schedule.RecurringJobId);
        _schedules.Remove(schedule);
        await _schedules.SaveChangesAsync(ct);
        return NoContent();
    }

    /// <summary>Lightweight cron sanity check: 5 or 6 whitespace-separated fields.</summary>
    private static bool IsValidCron(string? cron)
    {
        if (string.IsNullOrWhiteSpace(cron)) return false;
        var fields = cron.Trim().Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (fields.Length is not (5 or 6)) return false;
        return fields.All(f => f.All(c => char.IsDigit(c) || c is '*' or '/' or ',' or '-'));
    }
}
