namespace ProjectSky.Infrastructure.Defender;

/// <summary>
/// Configuration for Microsoft Defender for Endpoint ingestion, bound from the
/// "Defender" section. Ingestion is disabled unless all credentials are set.
/// </summary>
public sealed class DefenderOptions
{
    public const string SectionName = "Defender";

    public string TenantId { get; set; } = "";
    public string ClientId { get; set; } = "";
    public string ClientSecret { get; set; } = "";

    public string Authority { get; set; } = "https://login.microsoftonline.com";
    public string ApiBaseUrl { get; set; } = "https://api.securitycenter.microsoft.com";
    public string Scope { get; set; } = "https://api.securitycenter.microsoft.com/.default";

    /// <summary>Machine inventory endpoint (relative to <see cref="ApiBaseUrl"/>).</summary>
    public string MachinesPath { get; set; } = "/api/machines";

    /// <summary>Bulk machine↔vulnerability endpoint.</summary>
    public string VulnerabilitiesPath { get; set; } = "/api/vulnerabilities/machinesVulnerabilities";

    /// <summary>Cron for scheduled ingestion (default every 6 hours).</summary>
    public string SyncCron { get; set; } = "0 */6 * * *";

    public bool IsConfigured =>
        !string.IsNullOrWhiteSpace(TenantId) &&
        !string.IsNullOrWhiteSpace(ClientId) &&
        !string.IsNullOrWhiteSpace(ClientSecret);
}
