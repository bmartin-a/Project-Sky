using ProjectSky.Core.Entities;
using ProjectSky.Core.Enums;

namespace ProjectSky.Infrastructure.Services;

/// <summary>Findings to add versus existing findings to mark resolved.</summary>
public sealed record ReconciliationResult(
    IReadOnlyList<Finding> ToInsert,
    IReadOnlyList<Finding> Resolved);

/// <summary>
/// Reconciles a fresh scan's findings against the target's currently-open
/// findings so repeated scans don't pile up duplicates:
///  - a fresh finding matching an open one (same fingerprint) updates that row
///    in place (LastSeen, latest scan, refreshed detail) and is marked Existing;
///  - a fresh finding with no match is inserted as New;
///  - an open finding not seen this scan is marked Resolved.
/// Existing findings are mutated in place (they are tracked by the caller's
/// DbContext); only genuinely new findings are returned in <c>ToInsert</c>.
/// </summary>
public sealed class FindingReconciliationService
{
    public ReconciliationResult Reconcile(
        IReadOnlyList<Finding> existingOpen,
        IReadOnlyList<Finding> fresh,
        Guid? scanId)
    {
        var now = DateTimeOffset.UtcNow;
        var byFingerprint = existingOpen
            .GroupBy(f => f.Fingerprint)
            .ToDictionary(g => g.Key, g => g.First());

        var toInsert = new List<Finding>();
        var seen = new HashSet<string>();

        foreach (var f in fresh)
        {
            if (byFingerprint.TryGetValue(f.Fingerprint, out var existing))
            {
                existing.State = FindingState.Existing;
                existing.LastSeenAt = now;
                existing.ScanId = scanId;
                existing.Severity = f.Severity;
                existing.RiskScore = f.RiskScore;
                existing.CveId = f.CveId;
                existing.Evidence = f.Evidence;
                existing.ResolvedAt = null;
                seen.Add(f.Fingerprint);
            }
            else
            {
                f.State = FindingState.New;
                f.ScanId = scanId;
                f.FirstSeenAt = now;
                f.LastSeenAt = now;
                toInsert.Add(f);
            }
        }

        var resolved = new List<Finding>();
        foreach (var (fingerprint, existing) in byFingerprint)
        {
            if (seen.Contains(fingerprint)) continue;
            existing.State = FindingState.Resolved;
            existing.ResolvedAt = now;
            resolved.Add(existing);
        }

        return new ReconciliationResult(toInsert, resolved);
    }
}
