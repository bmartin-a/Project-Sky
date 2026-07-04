using ProjectSky.Core.Entities;
using ProjectSky.Core.Enums;
using ProjectSky.Core.Interfaces;
using ProjectSky.Core.Models;
using ProjectSky.Scanners.Base;

namespace ProjectSky.Scanners.Web;

/// <summary>
/// Active web scanner backed by the OWASP ZAP daemon: it spiders the target then
/// runs an active scan (XSS, SQLi, etc.) and maps the resulting alerts to
/// findings. If ZAP is unreachable it throws a clear error; the orchestrator
/// treats an individual scanner failure as non-fatal so nuclei results still
/// come through.
/// </summary>
public sealed class ZapScanner : ScannerBase
{
    private readonly ZapClient _zap;
    private readonly ZapOptions _options;

    public ZapScanner(ZapClient zap, ZapOptions options)
    {
        _zap = zap;
        _options = options;
    }

    public override string Name => "owasp-zap";
    public override ScanType Type => ScanType.Web;

    public override async Task<IReadOnlyList<Finding>> ScanAsync(
        Target target,
        ScanOptions options,
        IScanProgressReporter progress,
        CancellationToken ct)
    {
        var validation = TargetValidator.Validate(target.Address, target.Type);
        if (!validation.IsValid || validation.Normalized is null)
            throw new InvalidOperationException($"Refusing to scan invalid target: {validation.Error}");
        var url = validation.Normalized;

        if (!await _zap.IsReachableAsync(ct))
            throw new InvalidOperationException(
                $"OWASP ZAP daemon not reachable at {_options.BaseUrl}.");

        var timeout = TimeSpan.FromSeconds(options.TimeoutSeconds ?? _options.DefaultTimeoutFallback);
        var deadline = DateTimeOffset.UtcNow + timeout;

        // 1. Spider.
        await ReportSafeAsync(progress,
            new ScanProgress(target.Id, ScanStatus.Running, 15, "ZAP: spidering", 0), ct);
        var spiderId = await _zap.StartSpiderAsync(url, ct);
        await PollAsync(
            () => _zap.SpiderStatusAsync(spiderId, ct),
            target.Id, progress, "ZAP: spidering", 15, 45, deadline, ct);

        // 2. Active scan.
        await ReportSafeAsync(progress,
            new ScanProgress(target.Id, ScanStatus.Running, 45, "ZAP: active scan", 0), ct);
        var ascanId = await _zap.StartActiveScanAsync(url, ct);
        await PollAsync(
            () => _zap.ActiveScanStatusAsync(ascanId, ct),
            target.Id, progress, "ZAP: active scan", 45, 90, deadline, ct);

        // 3. Collect alerts.
        var alerts = await _zap.AlertsAsync(url, ct);
        var findings = alerts.Select(a => MapFinding(target, a)).ToList();

        await ReportSafeAsync(progress,
            new ScanProgress(target.Id, ScanStatus.Running, 95, "ZAP complete", findings.Count), ct);

        return findings;
    }

    private async Task PollAsync(
        Func<Task<int>> statusFn,
        Guid targetId,
        IScanProgressReporter progress,
        string phase,
        int fromPct,
        int toPct,
        DateTimeOffset deadline,
        CancellationToken ct)
    {
        while (true)
        {
            var status = await statusFn();
            if (status >= 100) break;
            if (DateTimeOffset.UtcNow >= deadline) break; // time budget exhausted → take partial results

            var pct = fromPct + (int)((toPct - fromPct) * (status / 100.0));
            await ReportSafeAsync(progress,
                new ScanProgress(targetId, ScanStatus.Running, pct, $"{phase} ({status}%)", 0), ct);

            await Task.Delay(_options.PollIntervalMs, ct);
        }
    }

    private Finding MapFinding(Target target, ZapAlert a)
    {
        var evidence = string.Join("\n",
            new[]
            {
                a.Url is null ? null : $"URL: {a.Url}",
                a.Param is null ? null : $"Param: {a.Param}",
                a.CweId is null ? null : $"CWE-{a.CweId}",
                a.Solution is null ? null : $"Solution: {a.Solution}",
            }.Where(s => s is not null));

        return new Finding
        {
            TargetId = target.Id,
            Title = a.Name,
            Description = a.Description,
            Severity = SeverityFromName(a.Risk),
            Service = "http",
            Evidence = evidence.Length == 0 ? null : evidence,
            Fingerprint = ComputeFingerprint(
                target.Address, "zap", a.PluginId ?? a.Name, a.Url, a.Param),
        };
    }
}
