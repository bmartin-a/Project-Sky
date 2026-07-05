using ProjectSky.Core.Entities;
using ProjectSky.Core.Enums;
using ProjectSky.Core.Models;

namespace ProjectSky.Core.Interfaces;

/// <summary>
/// A pluggable scanner. Each implementation handles one <see cref="ScanType"/>
/// and returns findings. The scan orchestrator resolves scanners by their
/// <see cref="Type"/>.
/// </summary>
public interface IScanner
{
    string Name { get; }

    ScanType Type { get; }

    /// <summary>
    /// Executes the scan. Implementations must honour <paramref name="ct"/> for
    /// timeout/cancellation and report incremental progress.
    /// </summary>
    /// <param name="pinnedIp">
    /// The authorizer's already-resolved, scope-checked IP for the target, or
    /// null. Scanners that open a direct connection SHOULD connect to this exact
    /// address (using the target's hostname only for SNI/Host) rather than
    /// re-resolving, which would reopen a DNS-rebinding window.
    /// </param>
    Task<IReadOnlyList<Finding>> ScanAsync(
        Target target,
        ScanOptions options,
        string? pinnedIp,
        IScanProgressReporter progress,
        CancellationToken ct);
}
