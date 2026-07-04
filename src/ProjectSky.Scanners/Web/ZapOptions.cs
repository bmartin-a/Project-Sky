namespace ProjectSky.Scanners.Web;

/// <summary>Configuration for the OWASP ZAP daemon, bound from the "Zap" section.</summary>
public sealed class ZapOptions
{
    public const string SectionName = "Zap";

    public string BaseUrl { get; set; } = "http://zap:8080";
    public string ApiKey { get; set; } = "change-me";

    /// <summary>How often to poll spider/active-scan progress.</summary>
    public int PollIntervalMs { get; set; } = 3000;

    /// <summary>Timeout used when the scan request doesn't specify one (seconds).</summary>
    public int DefaultTimeoutFallback { get; set; } = 1800;
}
