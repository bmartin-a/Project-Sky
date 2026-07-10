using ProjectSky.Core.Enums;

namespace ProjectSky.Core.Entities;

/// <summary>A recurring scan definition, executed by a Hangfire recurring job.</summary>
public class ScanSchedule
{
    public Guid Id { get; set; } = Guid.NewGuid();

    public Guid TargetId { get; set; }
    public Target? Target { get; set; }

    public ScanType Type { get; set; }

    /// <summary>Cron expression (Hangfire/Cronos syntax), e.g. "0 2 * * *".</summary>
    public required string Cron { get; set; }

    public bool Enabled { get; set; } = true;

    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;

    /// <summary>Stable Hangfire recurring-job id derived from the schedule id.</summary>
    public string RecurringJobId => $"scan-schedule:{Id}";
}
