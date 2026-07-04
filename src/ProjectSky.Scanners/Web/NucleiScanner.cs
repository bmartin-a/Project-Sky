using ProjectSky.Core.Entities;
using ProjectSky.Core.Enums;
using ProjectSky.Core.Interfaces;
using ProjectSky.Core.Models;
using ProjectSky.Scanners.Base;

namespace ProjectSky.Scanners.Web;

/// <summary>
/// Web scanner backed by nuclei's template engine. Runs nuclei against a URL
/// target with JSONL output and maps each match to a finding. Templates ship in
/// the image (see docker/Dockerfile.backend); update checks are disabled so a
/// scan never blocks on network access at runtime.
/// </summary>
public sealed class NucleiScanner : ScannerBase
{
    private readonly CliRunner _cli;
    private readonly ScannerOptions _options;

    public NucleiScanner(CliRunner cli, ScannerOptions options)
    {
        _cli = cli;
        _options = options;
    }

    public override string Name => "nuclei";
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

        await ReportSafeAsync(progress,
            new ScanProgress(target.Id, ScanStatus.Running, 10, "Starting nuclei", 0), ct);

        var args = BuildArgs(url, options);
        var timeout = TimeSpan.FromSeconds(options.TimeoutSeconds ?? _options.DefaultScanTimeoutSeconds);

        var result = await _cli.RunAsync(_options.NucleiPath, args, timeout, ct);
        if (result.TimedOut)
            throw new TimeoutException("nuclei scan exceeded its time budget.");

        var parsed = NucleiResultParser.Parse(result.StandardOutput);
        var findings = parsed.Select(r => MapFinding(target, r)).ToList();

        await ReportSafeAsync(progress,
            new ScanProgress(target.Id, ScanStatus.Running, 60, "nuclei complete", findings.Count), ct);

        return findings;
    }

    private static List<string> BuildArgs(string url, ScanOptions options)
    {
        var args = new List<string>
        {
            "-u", url,
            "-jsonl",
            "-silent",
            "-disable-update-check",
            "-no-color",
        };

        // Tag filter (e.g. cve, misconfig). Each value is validated to a safe token.
        var tags = options.NucleiTags
            .Where(t => t.All(c => char.IsLetterOrDigit(c) || c is '-' or '_'))
            .ToList();
        if (tags.Count > 0)
        {
            args.Add("-tags");
            args.Add(string.Join(',', tags));
        }

        return args;
    }

    private Finding MapFinding(Target target, NucleiResult r)
    {
        return new Finding
        {
            TargetId = target.Id,
            Title = r.Name ?? r.TemplateId,
            Description = r.Description,
            Severity = SeverityFromName(r.Severity),
            Service = "http",
            CveId = r.CveId,
            Evidence = r.MatchedAt is null ? null : $"Matched at: {r.MatchedAt}",
            Fingerprint = ComputeFingerprint(
                target.Address, "nuclei", r.TemplateId, r.MatchedAt),
        };
    }
}
