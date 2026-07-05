using Hangfire;
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
    private readonly IBackgroundJobClient _jobs;
    private readonly ILogger<ScheduledScanJob> _logger;

    public ScheduledScanJob(
        IScanScheduleRepository schedules,
        IScanRepository scans,
        IBackgroundJobClient jobs,
        ILogger<ScheduledScanJob> logger)
    {
        _schedules = schedules;
        _scans = scans;
        _jobs = jobs;
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

        _jobs.Enqueue<IScanExecutionJob>(j => j.RunAsync(scan.Id, CancellationToken.None));
        _logger.LogInformation("Scheduled scan {ScanId} queued from schedule {ScheduleId}.",
            scan.Id, scheduleId);
    }
}
