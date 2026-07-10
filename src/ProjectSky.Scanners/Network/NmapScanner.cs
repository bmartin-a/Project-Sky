using ProjectSky.Core.Entities;
using ProjectSky.Core.Enums;
using ProjectSky.Core.Interfaces;
using ProjectSky.Core.Models;
using ProjectSky.Scanners.Base;

namespace ProjectSky.Scanners.Network;

/// <summary>
/// Network scanner backed by nmap. Builds an argument vector (never a command
/// string), runs nmap with XML output, and maps open ports / service banners /
/// NSE script output into findings. CVE enrichment happens downstream via the
/// vulnerability module.
/// </summary>
public sealed class NmapScanner : ScannerBase
{
    private readonly CliRunner _cli;
    private readonly ScannerOptions _options;

    public NmapScanner(CliRunner cli, ScannerOptions options)
    {
        _cli = cli;
        _options = options;
    }

    public override string Name => "nmap";
    public override ScanType Type => ScanType.Network;

    public override async Task<IReadOnlyList<Finding>> ScanAsync(
        Target target,
        ScanOptions options,
        string? pinnedIp,
        IScanProgressReporter progress,
        CancellationToken ct)
    {
        // Defence in depth: re-validate the address here even though the API and
        // authorizer already did. The scanner never trusts its caller.
        var validation = TargetValidator.Validate(target.Address, target.Type);
        if (!validation.IsValid || validation.Normalized is null)
            throw new InvalidOperationException($"Refusing to scan invalid target: {validation.Error}");

        // Prefer the authorizer's pinned IP so nmap scans the exact address that
        // was scope-checked, rather than re-resolving the hostname (DNS rebinding).
        var address = pinnedIp is not null && System.Net.IPAddress.TryParse(pinnedIp, out _)
            ? pinnedIp
            : validation.Normalized;

        await ReportSafeAsync(progress,
            new ScanProgress(target.Id, ScanStatus.Running, 5, "Starting nmap", 0), ct);

        var args = BuildArgs(address, options);
        var timeout = TimeSpan.FromSeconds(options.TimeoutSeconds ?? _options.DefaultScanTimeoutSeconds);

        var result = await _cli.RunAsync(_options.NmapPath, args, timeout, ct);

        if (result.TimedOut)
            throw new TimeoutException("nmap scan exceeded its time budget.");

        // nmap exits non-zero on some partial conditions but still emits XML; we
        // parse whatever we got rather than hard-failing on exit code alone.
        var run = NmapXmlParser.Parse(result.StandardOutput);

        await ReportSafeAsync(progress,
            new ScanProgress(target.Id, ScanStatus.Running, 80, "Parsing results", 0), ct);

        var findings = MapFindings(target, run);

        await ReportSafeAsync(progress,
            new ScanProgress(target.Id, ScanStatus.Running, 95, "nmap complete", findings.Count), ct);

        return findings;
    }

    private List<string> BuildArgs(string address, ScanOptions options)
    {
        var args = new List<string> { "-oX", "-", "-Pn" };

        if (options.ServiceDetection) args.Add("-sV");
        if (options.OsDetection) args.Add("-O");

        if (!string.IsNullOrWhiteSpace(options.Ports))
        {
            // Validate BEFORE adding to the argument vector.
            if (!IsValidPortSpec(options.Ports))
                throw new InvalidOperationException("Invalid port specification.");
            args.Add("-p");
            args.Add(options.Ports);
        }

        if (options.RunVulnScripts)
        {
            args.Add("--script");
            args.Add("default,safe");
        }

        args.Add(address); // address is validated/normalized; still passed as its own arg
        return args;
    }

    /// <summary>Port spec grammar: digits, commas, and hyphen ranges only, no leading hyphen.</summary>
    private static bool IsValidPortSpec(string spec) =>
        spec.Length > 0 && spec[0] != '-' &&
        spec.All(c => char.IsDigit(c) || c is ',' or '-');

    private static List<Finding> MapFindings(Target target, NmapRun run)
    {
        var findings = new List<Finding>();

        foreach (var host in run.Hosts)
        {
            foreach (var port in host.Ports.Where(p => p.State == "open"))
            {
                var svc = port.Service;
                var cpe = svc?.Cpe ?? CpeMapper.ToCpe(svc?.Product, svc?.Version);
                var serviceLabel = svc?.Name ?? "unknown";
                var productVersion = string.Join(' ',
                    new[] { svc?.Product, svc?.Version }.Where(s => !string.IsNullOrWhiteSpace(s)));

                var title = string.IsNullOrWhiteSpace(productVersion)
                    ? $"Open {port.Protocol}/{port.Port} ({serviceLabel})"
                    : $"Open {port.Protocol}/{port.Port} — {productVersion}";

                findings.Add(new Finding
                {
                    TargetId = target.Id,
                    Title = title,
                    Description = svc?.ExtraInfo,
                    Severity = Severity.Info,
                    Port = port.Port,
                    Protocol = port.Protocol,
                    Service = serviceLabel,
                    ServiceProduct = svc?.Product,
                    ServiceVersion = svc?.Version,
                    Cpe = cpe,
                    Evidence = FormatScripts(port.Scripts),
                    Fingerprint = ComputeFingerprint(
                        target.Address, port.Protocol, port.Port.ToString(), serviceLabel, cpe),
                });
            }
        }

        return findings;
    }

    private static string? FormatScripts(IReadOnlyList<NmapScript> scripts) =>
        scripts.Count == 0
            ? null
            : string.Join("\n\n", scripts.Select(s => $"[{s.Id}]\n{s.Output}"));
}
