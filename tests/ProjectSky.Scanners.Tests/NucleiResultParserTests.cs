using ProjectSky.Scanners.Web;
using Xunit;

namespace ProjectSky.Scanners.Tests;

public class NucleiResultParserTests
{
    private const string SampleJsonl = """
        {"template-id":"CVE-2021-44228","info":{"name":"Apache Log4j RCE","severity":"critical","description":"Log4Shell","classification":{"cve-id":["CVE-2021-44228"]}},"matched-at":"https://example.com/","host":"example.com","type":"http"}
        not-a-json-banner-line
        {"template-id":"tech-detect","info":{"name":"Nginx","severity":"info"},"matched-at":"https://example.com","type":"http"}
        """;

    [Fact]
    public void Parses_valid_lines_and_skips_garbage()
    {
        var results = NucleiResultParser.Parse(SampleJsonl);
        Assert.Equal(2, results.Count);
    }

    [Fact]
    public void Extracts_template_severity_and_cve()
    {
        var results = NucleiResultParser.Parse(SampleJsonl);
        var log4j = results[0];

        Assert.Equal("CVE-2021-44228", log4j.TemplateId);
        Assert.Equal("Apache Log4j RCE", log4j.Name);
        Assert.Equal("critical", log4j.Severity);
        Assert.Equal("CVE-2021-44228", log4j.CveId);
        Assert.Equal("https://example.com/", log4j.MatchedAt);
    }

    [Fact]
    public void Result_without_classification_has_no_cve()
    {
        var results = NucleiResultParser.Parse(SampleJsonl);
        Assert.Null(results[1].CveId);
        Assert.Equal("tech-detect", results[1].TemplateId);
    }

    [Fact]
    public void Empty_input_yields_no_results()
    {
        Assert.Empty(NucleiResultParser.Parse(""));
        Assert.Empty(NucleiResultParser.Parse("   \n  \n"));
    }
}
