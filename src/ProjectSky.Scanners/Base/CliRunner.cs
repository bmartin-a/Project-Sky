using System.Diagnostics;
using System.Text;

namespace ProjectSky.Scanners.Base;

/// <summary>Result of running an external CLI tool.</summary>
public sealed record CliResult(int ExitCode, string StandardOutput, string StandardError, bool TimedOut)
{
    public bool Succeeded => !TimedOut && ExitCode == 0;
}

/// <summary>
/// Hardened wrapper around external scanner binaries (nmap, nuclei, ...).
///
/// SECURITY INVARIANTS — do not weaken:
///  1. Arguments are ALWAYS passed via <see cref="ProcessStartInfo.ArgumentList"/>
///     (an argument vector). We never build a command string and never use a
///     shell (<c>UseShellExecute = false</c>). This makes command injection via
///     a hostile target/option value impossible.
///  2. Every run is bounded by a timeout; on timeout or cancellation the whole
///     process tree is killed.
///  3. Captured stdout/stderr are capped to avoid unbounded memory growth from a
///     runaway tool.
/// </summary>
public sealed class CliRunner
{
    private const int MaxOutputBytes = 32 * 1024 * 1024; // 32 MiB cap per stream.

    /// <summary>
    /// Runs <paramref name="fileName"/> with the given argument vector. Callers
    /// must pass each argument as a separate list element — never a single
    /// pre-joined string.
    /// </summary>
    public async Task<CliResult> RunAsync(
        string fileName,
        IReadOnlyList<string> arguments,
        TimeSpan timeout,
        CancellationToken ct)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(fileName);
        ArgumentNullException.ThrowIfNull(arguments);

        var psi = new ProcessStartInfo
        {
            FileName = fileName,
            UseShellExecute = false,          // never go through a shell
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        };
        foreach (var arg in arguments)
            psi.ArgumentList.Add(arg);        // argument vector — no concatenation

        using var process = new Process { StartInfo = psi };

        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeoutCts.CancelAfter(timeout);
        var token = timeoutCts.Token;

        try
        {
            process.Start();
        }
        catch (Exception ex)
        {
            return new CliResult(-1, string.Empty, $"Failed to start '{fileName}': {ex.Message}", false);
        }

        var stdoutTask = ReadCappedAsync(process.StandardOutput, token);
        var stderrTask = ReadCappedAsync(process.StandardError, token);

        var timedOut = false;
        try
        {
            await process.WaitForExitAsync(token);
        }
        catch (OperationCanceledException)
        {
            timedOut = ct.IsCancellationRequested == false; // distinguish timeout vs caller-cancel
            TryKill(process);
        }

        var stdout = await SafeAwait(stdoutTask);
        var stderr = await SafeAwait(stderrTask);
        var exitCode = TryGetExitCode(process);

        return new CliResult(exitCode, stdout, stderr, timedOut);
    }

    private static async Task<string> ReadCappedAsync(StreamReader reader, CancellationToken ct)
    {
        var sb = new StringBuilder();
        var buffer = new char[8192];
        var total = 0;
        try
        {
            int read;
            while ((read = await reader.ReadAsync(buffer, ct)) > 0)
            {
                if (total >= MaxOutputBytes) continue; // drain but stop appending
                sb.Append(buffer, 0, read);
                total += read;
            }
        }
        catch (OperationCanceledException)
        {
            // Return whatever was captured before cancellation.
        }
        return sb.ToString();
    }

    private static async Task<string> SafeAwait(Task<string> task)
    {
        try { return await task; }
        catch { return string.Empty; }
    }

    private static void TryKill(Process process)
    {
        try
        {
            if (!process.HasExited)
                process.Kill(entireProcessTree: true);
        }
        catch { /* best-effort */ }
    }

    private static int TryGetExitCode(Process process)
    {
        try { return process.HasExited ? process.ExitCode : -1; }
        catch { return -1; }
    }
}
