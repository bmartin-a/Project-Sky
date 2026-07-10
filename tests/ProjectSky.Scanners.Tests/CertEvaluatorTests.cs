using ProjectSky.Core.Enums;
using ProjectSky.Scanners.Infra;
using Xunit;

namespace ProjectSky.Scanners.Tests;

public class CertEvaluatorTests
{
    private static readonly DateTimeOffset Now = new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);

    private static CertInfo Cert(
        string subject = "CN=example.com",
        string issuer = "CN=DigiCert",
        int notBeforeDays = -30,
        int notAfterDays = 365,
        string protocol = "Tls12",
        bool nameMatches = true) =>
        new(subject, issuer, Now.AddDays(notBeforeDays), Now.AddDays(notAfterDays), protocol, nameMatches);

    private static bool Has(IEnumerable<CertIssue> issues, Severity sev, string titlePart) =>
        issues.Any(i => i.Severity == sev && i.Title.Contains(titlePart, StringComparison.OrdinalIgnoreCase));

    [Fact]
    public void Healthy_certificate_yields_only_info_baseline()
    {
        var issues = CertEvaluator.Evaluate(Cert(), Now);
        Assert.Single(issues);
        Assert.Equal(Severity.Info, issues[0].Severity);
    }

    [Fact]
    public void Expired_certificate_is_high()
    {
        var issues = CertEvaluator.Evaluate(Cert(notAfterDays: -1), Now);
        Assert.True(Has(issues, Severity.High, "expired"));
    }

    [Fact]
    public void Expiring_soon_is_medium()
    {
        var issues = CertEvaluator.Evaluate(Cert(notAfterDays: 10), Now);
        Assert.True(Has(issues, Severity.Medium, "expiring soon"));
    }

    [Fact]
    public void Self_signed_is_medium()
    {
        var issues = CertEvaluator.Evaluate(Cert(subject: "CN=self", issuer: "CN=self"), Now);
        Assert.True(Has(issues, Severity.Medium, "self-signed"));
    }

    [Fact]
    public void Weak_protocol_is_high()
    {
        var issues = CertEvaluator.Evaluate(Cert(protocol: "Tls11"), Now);
        Assert.True(Has(issues, Severity.High, "weak tls"));
    }

    [Fact]
    public void Name_mismatch_is_medium()
    {
        var issues = CertEvaluator.Evaluate(Cert(nameMatches: false), Now);
        Assert.True(Has(issues, Severity.Medium, "name mismatch"));
    }
}
