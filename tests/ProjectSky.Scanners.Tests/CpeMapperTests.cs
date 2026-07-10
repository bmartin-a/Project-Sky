using ProjectSky.Scanners.Network;
using Xunit;

namespace ProjectSky.Scanners.Tests;

public class CpeMapperTests
{
    [Fact]
    public void Builds_cpe_from_product_and_version()
    {
        var cpe = CpeMapper.ToCpe("OpenSSH", "8.2p1");
        Assert.Equal("cpe:2.3:a:*:openssh:8.2p1:*:*:*:*:*:*:*", cpe);
    }

    [Fact]
    public void Normalizes_spaces_and_case()
    {
        var cpe = CpeMapper.ToCpe("Apache httpd", "2.4.41");
        Assert.Equal("cpe:2.3:a:*:apache_httpd:2.4.41:*:*:*:*:*:*:*", cpe);
    }

    [Fact]
    public void Missing_version_becomes_wildcard()
    {
        var cpe = CpeMapper.ToCpe("nginx", null);
        Assert.Equal("cpe:2.3:a:*:nginx:*:*:*:*:*:*:*:*", cpe);
    }

    [Fact]
    public void Null_product_yields_null()
    {
        Assert.Null(CpeMapper.ToCpe(null, "1.0"));
        Assert.Null(CpeMapper.ToCpe("", "1.0"));
    }

    [Fact]
    public void Extracts_product_token()
    {
        Assert.Equal("openssh", CpeMapper.ProductOf("cpe:2.3:a:*:openssh:8.2p1:*:*:*:*:*:*:*"));
    }
}
