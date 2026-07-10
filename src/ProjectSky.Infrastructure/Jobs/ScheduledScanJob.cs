using Microsoft.Extensions.Logging;
using ProjectSky.Core.Entities;
using ProjectSky.Core.Enums;
using ProjectSky.Core.Interfaces;

namespace ProjectSky.Infrastructure.Jobs;

/// <summary>Invoked by a Hangfire recurring job to launch a scheduled scan.</summary>
public interface IScheduledScanJob
{
    Task RunAsync(Guid scheduleId, CancellationToken ct);
}

public sealed class ScheduledScanJob : IScheduledScanJob
{
    private readonly IScanScheduleRepository _schedules;
    private readonly IScanRepository _scans;
    private readonly IScanExecutionJob _execution;
    private readonly ILogger<ScheduledScanJob> _logger;

    public ScheduledScanJob(
        IScanScheduleRepository schedules,
        IScanRepository scans,
        IScanExecutionJob execution,
        ILogger<ScheduledScanJob> logger)
    {
        _schedules = schedules;
        _scans = scans;
        _execution = execution;
        _logger = logger;
    }

    public async Task RunAsync(Guid scheduleId, CancellationToken ct)
    {
        var schedule = await _schedules.GetAsync(scheduleId, ct);
        if (schedule is null || !schedule.Enabled)
        {
            _logger.LogInformation("Schedule {ScheduleId} missing or disabled; skipping.", scheduleId);
            return;
        }

        var scan = new Scan
        {
            TargetId = schedule.TargetId,
            Type = schedule.Type,
            Status = ScanStatus.Queued,
            CreatedBySubject = "schedule",
        };
        await _scans.AddAsync(scan, ct);
        await _scans.SaveChangesAsync(ct);

        _logger.LogInformation("Scheduled scan {ScanId} starting from schedule {ScheduleId}.",
            scan.Id, scheduleId);

        // Run the scan inline within this recurring job (the Hangfire server hosts it).
        await _execution.RunAsync(scan.Id, ct);
    }
}
