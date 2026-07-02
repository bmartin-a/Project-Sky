namespace ProjectSky.Scanners.Base;

/// <summary>Configuration for scanner tooling, bound from the "Scanner" config section.</summary>
public sealed class ScannerOptions
{
    public const string SectionName = "Scanner";

    public string NmapPath { get; set; } = "/usr/bin/nmap";
    public string NucleiPath { get; set; } = "/usr/local/bin/nuclei";
    public int DefaultScanTimeoutSeconds { get; set; } = 1800;
}
