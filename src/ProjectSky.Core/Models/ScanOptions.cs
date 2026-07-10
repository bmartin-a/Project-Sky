namespace ProjectSky.Core.Models;

/// <summary>
/// Per-scan tuning, serialized onto <c>Scan.OptionsJson</c>. All fields have
/// safe defaults so a scan can be launched with an empty options object.
/// </summary>
public class ScanOptions
{
    // --- Network (nmap) ---
    /// <summary>Port spec passed to nmap, e.g. "1-1024" or "22,80,443". Null = nmap default.</summary>
    public string? Ports { get; set; }

    public bool ServiceDetection { get; set; } = true;
    public bool OsDetection { get; set; } = true;

    /// <summary>Run nmap's default "vuln"/"safe" NSE scripts.</summary>
    public bool RunVulnScripts { get; set; } = true;

    // --- Web (nuclei / zap) ---
    /// <summary>Nuclei template tags/severity filter, e.g. ["cve","misconfig"].</summary>
    public List<string> NucleiTags { get; set; } = new();

    /// <summary>Enable OWASP ZAP active spider + scan (Milestone 2).</summary>
    public bool ZapActiveScan { get; set; }

    public int MaxCrawlDepth { get; set; } = 5;

    // --- Shared ---
    /// <summary>Hard timeout for the scan. Null falls back to the configured default.</summary>
    public int? TimeoutSeconds { get; set; }
}
