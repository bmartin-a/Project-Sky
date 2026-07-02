namespace ProjectSky.Core.Models;

/// <summary>Result of risk scoring: a 0–1000 value plus its band label.</summary>
public readonly record struct RiskScore(int Value, string Band)
{
    public static string BandFor(int value) => value switch
    {
        >= 900 => "Critical",
        >= 750 => "High",
        >= 500 => "Medium",
        _ => "Low",
    };

    public static RiskScore Of(int value) => new(value, BandFor(value));
}
