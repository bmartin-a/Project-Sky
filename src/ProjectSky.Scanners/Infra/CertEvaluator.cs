using ProjectSky.Core.Enums;

namespace ProjectSky.Scanners.Infra;

/// <summary>Neutral view of a TLS certificate + negotiated connection.</summary>
public sealed record CertInfo(
    string Subject,
    string Issuer,
    DateTimeOffset NotBefore,
    DateTimeOffset NotAfter,
    string? ProtocolName,
    bool NameMatches);

/// <summary>A single issue found while evaluating a certificate/connection.</summary>
public sealed record CertIssue(Severity Severity, string Title, string? Description);

/// <summary>
/// Pure TLS certificate/connection evaluation, decoupled from the network so it
/// can be unit tested. The <see cref="SslTlsScanner"/> supplies a
/// <see cref="CertInfo"/> captured from a live handshake.
/// </summary>
public static class CertEvaluator
{
    public static readonly TimeSpan ExpiryWarningWindow = TimeSpan.FromDays(30);

    private static readonly HashSet<string> WeakProtocols =
        new(StringComparer.OrdinalIgnoreCase) { "Ssl2", "Ssl3", "Tls", "Tls11" };

    public static IReadOnlyList<CertIssue> Evaluate(CertInfo cert, DateTimeOffset now)
    {
        var issues = new List<CertIssue>();

        if (now > cert.NotAfter)
        {
            issues.Add(new CertIssue(Severity.High, "TLS certificate expired",
                $"Expired on {cert.NotAfter:yyyy-MM-dd}."));
        }
        else if (cert.NotAfter - now < ExpiryWarningWindow)
        {
            var days = (int)(cert.NotAfter - now).TotalDays;
            issues.Add(new CertIssue(Severity.Medium, "TLS certificate expiring soon",
                $"Expires in {days} day(s), on {cert.NotAfter:yyyy-MM-dd}."));
        }

        if (now < cert.NotBefore)
        {
            issues.Add(new CertIssue(Severity.Medium, "TLS certificate not yet valid",
                $"Not valid before {cert.NotBefore:yyyy-MM-dd}."));
        }

        if (string.Equals(cert.Subject, cert.Issuer, StringComparison.OrdinalIgnoreCase))
        {
            issues.Add(new CertIssue(Severity.Medium, "Self-signed TLS certificate",
                $"Subject and issuer are identical ({cert.Subject})."));
        }

        if (!cert.NameMatches)
        {
            issues.Add(new CertIssue(Severity.Medium, "TLS certificate name mismatch",
                "The certificate does not match the requested host."));
        }

        if (cert.ProtocolName is not null && WeakProtocols.Contains(cert.ProtocolName))
        {
            issues.Add(new CertIssue(Severity.High, "Weak TLS protocol",
                $"Negotiated {cert.ProtocolName}; TLS 1.2 or higher is recommended."));
        }

        // Always emit an informational baseline so a clean host still reports.
        issues.Add(new CertIssue(Severity.Info, "TLS endpoint",
            $"Subject {cert.Subject}; issuer {cert.Issuer}; expires {cert.NotAfter:yyyy-MM-dd}" +
            (cert.ProtocolName is null ? "" : $"; protocol {cert.ProtocolName}") + "."));

        return issues;
    }
}
