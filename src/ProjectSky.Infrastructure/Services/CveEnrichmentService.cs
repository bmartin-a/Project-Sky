using ProjectSky.Core.Entities;
using ProjectSky.Core.Enums;
using ProjectSky.Core.Interfaces;
using ProjectSky.Scanners.Network;
using ProjectSky.Vulnerability.Cpe;
using ProjectSky.Vulnerability.Scoring;

namespace ProjectSky.Infrastructure.Services;

/// <summary>
/// Enriches scanner findings with CVE data: for each finding that carries a
/// product/version, it finds the highest-severity matching CVE (via
/// <see cref="CpeMatcher"/>) and applies its severity and a computed risk score.
///
/// NOTE: this attaches the single worst matching CVE per service. Emitting one
/// finding per matching CVE is a planned enhancement (tracked for Milestone 1
/// polish); the fingerprint scheme already leaves room for it.
/// </summary>
public sealed class CveEnrichmentService
{
    private readonly ICveRepository _cves;
    private readonly RiskScoreService _risk;

    public CveEnrichmentService(ICveRepository cves, RiskScoreService risk)
    {
        _cves = cves;
        _risk = risk;
    }

    public async Task EnrichAsync(
        IReadOnlyList<Finding> findings,
        AssetCriticality criticality,
        CancellationToken ct)
    {
        foreach (var finding in findings)
        {
            var product = ResolveProduct(finding);
            if (product is null)
            {
                finding.RiskScore = _risk.Compute(null, false, null, criticality).Value;
                continue;
            }

            var candidates = await _cves.FindByProductAsync(product, ct);
            var best = SelectWorstMatch(candidates, product, finding.ServiceVersion);

            if (best is null)
            {
                finding.RiskScore = _risk.Compute(null, false, null, criticality).Value;
                continue;
            }

            finding.CveId = best.Id;
            finding.Severity = best.Severity;
            finding.Description = string.IsNullOrWhiteSpace(finding.Description)
                ? best.Description
                : finding.Description;
            finding.RiskScore = _risk
                .Compute(best.CvssV3BaseScore, best.HasKnownExploit, best.EpssScore, criticality)
                .Value;
        }
    }

    private static Cve? SelectWorstMatch(IReadOnlyList<Cve> candidates, string product, string? version)
    {
        Cve? best = null;
        foreach (var cve in candidates)
        {
            var applies = cve.CpeMatches.Any(m => CpeMatcher.Matches(product, version, m));
            if (!applies) continue;
            if (best is null || (cve.CvssV3BaseScore ?? 0) > (best.CvssV3BaseScore ?? 0))
                best = cve;
        }
        return best;
    }

    private static string? ResolveProduct(Finding finding)
    {
        if (finding.Cpe is { } cpe && CpeMapper.ProductOf(cpe) is { Length: > 0 } p && p != "*")
            return p;
        if (!string.IsNullOrWhiteSpace(finding.ServiceProduct))
            return finding.ServiceProduct.Trim().ToLowerInvariant().Replace(' ', '_');
        return null;
    }
}
