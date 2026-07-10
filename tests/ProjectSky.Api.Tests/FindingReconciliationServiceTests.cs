using ProjectSky.Core.Entities;
using ProjectSky.Core.Enums;
using ProjectSky.Infrastructure.Services;
using Xunit;

namespace ProjectSky.Api.Tests;

public class FindingReconciliationServiceTests
{
    private readonly FindingReconciliationService _svc = new();

    private static Finding Open(string fingerprint) => new()
    {
        Title = "existing",
        Fingerprint = fingerprint,
        State = FindingState.New,
        TargetId = Guid.NewGuid(),
    };

    private static Finding Fresh(string fingerprint) => new()
    {
        Title = "fresh",
        Fingerprint = fingerprint,
    };

    [Fact]
    public void New_fingerprint_is_inserted_as_new()
    {
        var scanId = Guid.NewGuid();
        var result = _svc.Reconcile([], [Fresh("A")], scanId);

        var inserted = Assert.Single(result.ToInsert);
        Assert.Equal(FindingState.New, inserted.State);
        Assert.Equal(scanId, inserted.ScanId);
        Assert.Empty(result.Resolved);
    }

    [Fact]
    public void Matching_fingerprint_updates_existing_not_inserts()
    {
        var existing = Open("A");
        var result = _svc.Reconcile([existing], [Fresh("A")], Guid.NewGuid());

        Assert.Empty(result.ToInsert);
        Assert.Empty(result.Resolved);
        Assert.Equal(FindingState.Existing, existing.State);
    }

    [Fact]
    public void Disappeared_finding_is_resolved()
    {
        var existing = Open("A");
        var result = _svc.Reconcile([existing], [], Guid.NewGuid());

        var resolved = Assert.Single(result.Resolved);
        Assert.Equal(FindingState.Resolved, resolved.State);
        Assert.NotNull(resolved.ResolvedAt);
    }

    [Fact]
    public void Mixed_set_partitions_correctly()
    {
        var a = Open("A"); // stays -> Existing
        var b = Open("B"); // disappears -> Resolved
        var result = _svc.Reconcile([a, b], [Fresh("A"), Fresh("C")], Guid.NewGuid());

        Assert.Equal("C", Assert.Single(result.ToInsert).Fingerprint);
        Assert.Equal("B", Assert.Single(result.Resolved).Fingerprint);
        Assert.Equal(FindingState.Existing, a.State);
    }
}
