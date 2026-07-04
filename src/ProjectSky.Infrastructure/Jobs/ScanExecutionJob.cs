using System.Text.Json;
using Microsoft.Extensions.Logging;
using ProjectSky.Core.Enums;
using ProjectSky.Core.Interfaces;
using ProjectSky.Core.Models;
using ProjectSky.Infrastructure.Services;

namespace ProjectSky.Infrastructure.Jobs;

/// <summary>Entry point Hangfire invokes to run a queued scan.</summary>
public interface IScanExecutionJob
{
    Task RunAsync(Guid scanId, CancellationToken ct);
}

/// <summary>
/// Executes a queued scan end-to-end: authorize → scan → enrich with CVEs →
/// reconcile against prior findings → persist. All work happens in the Hangfire
/// job scope, so every injected repository shares one DbContext and the
/// reconciliation's in-place updates persist alongside the new findings.
/// </summary>
public sealed class ScanExecutionJob : IScanExecutionJob
{
    private readonly IScanRepository _scans;
    private readonly IFindingRepository _findings;
    private readonly ITargetAuthorizer _authorizer;
    private readonly IEnumerable<IScanner> _scanners;
    private readonly CveEnrichmentService _enrichment;
    private readonly FindingReconciliationService _reconciliation;
    private readonly IScanProgressReporter _progress;
    private readonly ILogger<ScanExecutionJob> _logger;

    public ScanExecutionJob(
        IScanRepository scans,
        IFindingRepository findings,
        ITargetAuthorizer authorizer,
        IEnumerable<IScanner> scanners,
        CveEnrichmentService enrichment,
        FindingReconciliationService reconciliation,
        IScanProgressReporter progress,
        ILogger<ScanExecutionJob> logger)
    {
        _scans = scans;
        _findings = findings;
        _authorizer = authorizer;
        _scanners = scanners;
        _enrichment = enrichment;
        _reconciliation = reconciliation;
        _progress = progress;
        _logger = logger;
    }

    public async Task RunAsync(Guid scanId, CancellationToken ct)
    {
        var scan = await _scans.GetAsync(scanId, ct);
        if (scan is null)
        {
            _logger.LogWarning("Scan {ScanId} not found; nothing to run.", scanId);
            return;
        }
        if (scan.Target is null)
        {
            await FailAsync(scan, "Scan has no target.", ct);
            return;
        }

        scan.Status = ScanStatus.Running;
        scan.StartedAt = DateTimeOffset.UtcNow;
        await _scans.SaveChangesAsync(ct);

        try
        {
            // 1. Authorization gate — never scan without an explicit allow.
            var auth = await _authorizer.AuthorizeAsync(scan.Target, ct);
            if (!auth.IsAllowed)
            {
                scan.Status = ScanStatus.Rejected;
                scan.ErrorMessage = auth.Reason;
                scan.CompletedAt = DateTimeOffset.UtcNow;
                await _scans.SaveChangesAsync(ct);
                await Report(scan, ScanStatus.Rejected, 100, auth.Reason, 0, ct);
                return;
            }

            // 2. Resolve every scanner registered for this scan type (e.g. Web runs
            //    both nuclei and ZAP).
            var scanners = _scanners.Where(s => s.Type == scan.Type).ToList();
            if (scanners.Count == 0)
            {
                await FailAsync(scan, $"No scanner registered for type '{scan.Type}'.", ct);
                return;
            }

            var options = DeserializeOptions(scan.OptionsJson);

            // 3. Run each scanner. An individual scanner failing (e.g. ZAP daemon
            //    down) is non-fatal as long as at least one produced results.
            var found = new List<Core.Entities.Finding>();
            var errors = new List<string>();
            foreach (var scanner in scanners)
            {
                try
                {
                    found.AddRange(await scanner.ScanAsync(scan.Target, options, _progress, ct));
                }
                catch (OperationCanceledException)
                {
                    throw;
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Scanner {Scanner} failed for scan {ScanId}.",
                        scanner.Name, scan.Id);
                    errors.Add($"{scanner.Name}: {ex.Message}");
                }
            }

            if (found.Count == 0 && errors.Count == scanners.Count)
            {
                await FailAsync(scan, string.Join("; ", errors), ct);
                return;
            }

            // 4. Enrich with CVE matches + risk scores.
            await _enrichment.EnrichAsync(found, scan.Target.Criticality, ct);

            // 5. Reconcile against currently-open findings for this target.
            var existingOpen = await _findings.ListOpenByTargetAsync(scan.TargetId, ct);
            var result = _reconciliation.Reconcile(existingOpen, found, scan.Id);
            await _findings.AddRangeAsync(result.ToInsert, ct);
            await _findings.SaveChangesAsync(ct);

            // 6. Complete. Partial scanner failures are surfaced as a warning but
            //    don't fail the scan.
            scan.Status = ScanStatus.Completed;
            scan.CompletedAt = DateTimeOffset.UtcNow;
            scan.ErrorMessage = errors.Count > 0 ? $"Partial: {string.Join("; ", errors)}" : null;
            await _scans.SaveChangesAsync(ct);

            var summary = $"{result.ToInsert.Count} new, {result.Resolved.Count} resolved";
            if (errors.Count > 0) summary += $" ({errors.Count} scanner(s) skipped)";
            await Report(scan, ScanStatus.Completed, 100, summary, found.Count, ct);

            _logger.LogInformation(
                "Scan {ScanId} completed: {New} new, {Resolved} resolved.",
                scan.Id, result.ToInsert.Count, result.Resolved.Count);
        }
        catch (OperationCanceledException)
        {
            scan.Status = ScanStatus.Cancelled;
            scan.CompletedAt = DateTimeOffset.UtcNow;
            await _scans.SaveChangesAsync(CancellationToken.None);
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Scan {ScanId} failed.", scan.Id);
            await FailAsync(scan, ex.Message, CancellationToken.None);
        }
    }

    private async Task FailAsync(Core.Entities.Scan scan, string message, CancellationToken ct)
    {
        scan.Status = ScanStatus.Failed;
        scan.ErrorMessage = message;
        scan.CompletedAt = DateTimeOffset.UtcNow;
        await _scans.SaveChangesAsync(ct);
        await Report(scan, ScanStatus.Failed, 100, message, 0, ct);
    }

    private Task Report(Core.Entities.Scan scan, ScanStatus status, int pct, string? msg, int findings, CancellationToken ct)
    {
        try
        {
            return _progress.ReportAsync(new ScanProgress(scan.Id, status, pct, msg, findings), ct);
        }
        catch
        {
            return Task.CompletedTask; // progress is best-effort
        }
    }

    private static ScanOptions DeserializeOptions(string? json)
    {
        if (string.IsNullOrWhiteSpace(json)) return new ScanOptions();
        try { return JsonSerializer.Deserialize<ScanOptions>(json) ?? new ScanOptions(); }
        catch { return new ScanOptions(); }
    }
}
