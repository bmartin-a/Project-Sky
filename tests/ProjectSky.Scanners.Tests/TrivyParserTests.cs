using ProjectSky.Scanners.Infra;
using Xunit;

namespace ProjectSky.Scanners.Tests;

public class TrivyParserTests
{
    private const string Sample = """
        {
          "Results": [
            {
              "Target": "alpine:3.18",
              "Vulnerabilities": [
                {"VulnerabilityID":"CVE-2023-1234","PkgName":"openssl","InstalledVersion":"1.1.1","Severity":"HIGH","Title":"OpenSSL flaw","PrimaryURL":"https://nvd.nist.gov/vuln/detail/CVE-2023-1234"},
                {"VulnerabilityID":"CVE-2023-5678","PkgName":"busybox","InstalledVersion":"1.36","Severity":"MEDIUM"}
              ]
            },
            { "Target": "no-vulns", "Vulnerabilities": null }
          ]
        }
        """;

    [Fact]
    public void Parses_vulnerabilities_across_results()
    {
        var vulns = TrivyParser.Parse(Sample);
        Assert.Equal(2, vulns.Count);
    }

    [Fact]
    public void Captures_fields()
    {
        var v = TrivyParser.Parse(Sample)[0];
        Assert.Equal("CVE-2023-1234", v.VulnerabilityId);
        Assert.Equal("openssl", v.PkgName);
        Assert.Equal("1.1.1", v.InstalledVersion);
        Assert.Equal("HIGH", v.Severity);
    }

    [Fact]
    public void Empty_or_garbage_yields_none()
    {
        Assert.Empty(TrivyParser.Parse(""));
        Assert.Empty(TrivyParser.Parse("not json"));
        Assert.Empty(TrivyParser.Parse("{}"));
    }
}
