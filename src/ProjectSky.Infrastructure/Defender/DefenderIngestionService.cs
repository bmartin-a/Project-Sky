using System.Net;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using ProjectSky.Core.Common;
using ProjectSky.Core.Entities;
using ProjectSky.Core.Enums;
using ProjectSky.Infrastructure.Data;
using ProjectSky.Vulnerability.Scoring;

namespace ProjectSky.Infrastructure.Defender;

/// <summary>
/// Pulls machines and their vulnerabilities from Microsoft Defender and persists
/// them as targets + findings (Source = "Defender"). Findings are upserted by
/// fingerprint so repeated ingestion updates rather than duplicates. Each
/// Defender machine becomes a target so its exposure shows up in the dashboard
/// alongside actively-scanned assets.
/// </summary>
public sealed class DefenderIngestionService
{
    private readonly DefenderApiClient _client;
    private readonly AppDbContext _db;
    private readonly RiskScoreService _risk;
    private readonly ILogger<DefenderIngestionService> _logger;

    public DefenderIngestionService(
        DefenderApiClient client,
        AppDbContext db,
        RiskScoreService risk,
        ILogger<DefenderIngestionService> logger)
    {
        _client = client;
        _db = db;
        _risk = risk;
        _logger = logger;
    }

    public async Task<int> IngestAsync(CancellationToken ct)
    {
        var machines = await _client.GetMachinesAsync(ct);
        var vulns = await _client.GetVulnerabilitiesAsync(ct);
        var vulnsByMachine = vulns.GroupBy(v => v.MachineId)
            .ToDictionary(g => g.Key, g => g.ToList());

        _logger.LogInformation("Defender: {Machines} machines, {Vulns} vulnerability rows.",
            machines.Count, vulns.Count);

        var now = DateTimeOffset.UtcNow;
        var newFindings = 0;

        foreach (var machine in machines)
        {
            var target = await UpsertTargetAsync(machine, ct);
            if (!vulnsByMachine.TryGetValue(machine.Id, out var machineVulns)) continue;

            var existing = await _db.Findings
                .Where(f => f.TargetId == target.Id && f.Source == "Defender")
                .ToListAsync(ct);
            var byFingerprint = existing
                .GroupBy(f => f.Fingerprint)
                .ToDictionary(g => g.Key, g => g.First());

            foreach (var v in machineVulns)
            {
                var fp = Fingerprint.Compute(machine.Id, v.CveId, v.ProductName);
                var severity = SeverityFromName(v.Severity);
                var cvss = v.CvssV3 ?? CvssFromSeverity(severity);
                var risk = _risk.Compute(cvss, false, null, target.Criticality).Value;

                if (byFingerprint.TryGetValue(fp, out var f))
                {
                    f.Severity = severity;
                    f.RiskScore = risk;
                    f.CveId = v.CveId;
                    f.ServiceProduct = v.ProductName;
                    f.ServiceVersion = v.ProductVersion;
                    f.State = FindingState.Existing;
                    f.LastSeenAt = now;
                    f.ResolvedAt = null;
                }
                else
                {
                    _db.Findings.Add(new Finding
                    {
                        TargetId = target.Id,
                        Source = "Defender",
                        Title = $"{v.CveId} in {v.ProductName ?? "software"}",
                        Severity = severity,
                        RiskScore = risk,
                        CveId = v.CveId,
                        ServiceProduct = v.ProductName,
                        ServiceVersion = v.ProductVersion,
                        FirstSeenAt = now,
                        LastSeenAt = now,
                        Fingerprint = fp,
                    });
                    newFindings++;
                }
            }

            await _db.SaveChangesAsync(ct);
        }

        _logger.LogInformation("Defender ingestion complete: {New} new findings.", newFindings);
        return newFindings;
    }

    private async Task<Target> UpsertTargetAsync(DefenderMachine machine, CancellationToken ct)
    {
        var address = machine.DnsName ?? machine.IpAddress ?? machine.Id;
        var target = await _db.Targets.FirstOrDefaultAsync(t => t.Address == address, ct);
        if (target is not null) return target;

        target = new Target
        {
            Address = address,
            Type = IPAddress.TryParse(address, out _) ? TargetType.IpAddress : TargetType.Hostname,
            Criticality = CriticalityFromExposure(machine.ExposureLevel),
            Name = machine.DnsName,
        };
        _db.Targets.Add(target);
        await _db.SaveChangesAsync(ct);
        return target;
    }

    private static AssetCriticality CriticalityFromExposure(string? level) =>
        level?.Trim().ToLowerInvariant() switch
        {
            "high" => AssetCriticality.High,
            "low" => AssetCriticality.Low,
            _ => AssetCriticality.Medium,
        };

    private static Severity SeverityFromName(string? name) => name?.Trim().ToLowerInvariant() switch
    {
        "critical" => Severity.Critical,
        "high" => Severity.High,
        "medium" => Severity.Medium,
        "low" => Severity.Low,
        _ => Severity.Info,
    };

    private static double CvssFromSeverity(Severity severity) => severity switch
    {
        Severity.Critical => 9.5,
        Severity.High => 8.0,
        Severity.Medium => 5.5,
        Severity.Low => 3.0,
        _ => 0.5,
    };
}
