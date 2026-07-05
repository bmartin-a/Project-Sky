using ProjectSky.Core.Entities;
using ProjectSky.Core.Enums;
using ProjectSky.Core.Interfaces;
using ProjectSky.Core.Models;
using ProjectSky.Scanners.Base;

namespace ProjectSky.Scanners.Infra;

/// <summary>
/// Scans a container image for known vulnerabilities using Trivy. Only runs for
/// <see cref="TargetType.ContainerImage"/> targets; for anything else it returns
/// no findings so it can coexist with the TLS scanner under the same
/// Infrastructure scan type.
/// </summary>
public sealed class TrivyScanner : ScannerBase
{
    private readonly CliRunner _cli;
    private readonly ScannerOptions _options;

    public TrivyScanner(CliRunner cli, ScannerOptions options)
    {
        _cli = cli;
        _options = options;
    }

    public override string Name => "trivy";
    public override ScanType Type => ScanType.Infrastructure;

    public override async Task<IReadOnlyList<Finding>> ScanAsync(
        Target target,
        ScanOptions options,
        IScanProgressReporter progress,
        CancellationToken ct)
    {
        if (target.Type != TargetType.ContainerImage)
            return [];

        var validation = TargetValidator.Validate(target.Address, target.Type);
        if (!validation.IsValid || validation.Normalized is null)
            throw new InvalidOperationException($"Refusing to scan invalid image: {validation.Error}");
        var image = validation.Normalized;

        await ReportSafeAsync(progress,
            new ScanProgress(target.Id, ScanStatus.Running, 15, $"Trivy scanning {image}", 0), ct);

        var args = new List<string>
        {
            "image",
            "--quiet",
            "--format", "json",
            "--scanners", "vuln",
            image, // validated; passed as its own argument
        };
        var timeout = TimeSpan.FromSeconds(options.TimeoutSeconds ?? _options.DefaultScanTimeoutSeconds);

        var result = await _cli.RunAsync(_options.TrivyPath, args, timeout, ct);
        if (result.TimedOut)
            throw new TimeoutException("Trivy scan exceeded its time budget.");

        var vulns = TrivyParser.Parse(result.StandardOutput);
        var findings = vulns.Select(v => MapFinding(target, v)).ToList();

        await ReportSafeAsync(progress,
            new ScanProgress(target.Id, ScanStatus.Running, 90, "Trivy complete", findings.Count), ct);

        return findings;
    }

    private Finding MapFinding(Target target, TrivyVuln v) => new()
    {
        TargetId = target.Id,
        Title = v.Title ?? $"{v.VulnerabilityId} in {v.PkgName ?? "package"}",
        Description = v.Description,
        Severity = SeverityFromName(v.Severity),
        Service = "container",
        ServiceProduct = v.PkgName,
        ServiceVersion = v.InstalledVersion,
        CveId = v.VulnerabilityId.StartsWith("CVE-", StringComparison.OrdinalIgnoreCase)
            ? v.VulnerabilityId
            : null,
        Evidence = v.PrimaryUrl,
        Fingerprint = ComputeFingerprint(
            target.Address, "trivy", v.VulnerabilityId, v.PkgName, v.InstalledVersion),
    };
}
