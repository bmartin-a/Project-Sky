using System.Net;
using ProjectSky.Scanners.Base;
using Xunit;

namespace ProjectSky.Scanners.Tests;

public class IpScopeTests
{
    [Theory]
    [InlineData("10.0.0.1")]
    [InlineData("172.16.5.4")]
    [InlineData("192.168.1.1")]
    [InlineData("fc00::1")]
    public void Detects_private(string ip) =>
        Assert.True(IpScope.IsPrivate(IPAddress.Parse(ip)));

    [Theory]
    [InlineData("8.8.8.8")]
    [InlineData("1.1.1.1")]
    public void Public_addresses_are_not_private(string ip) =>
        Assert.False(IpScope.IsPrivate(IPAddress.Parse(ip)));

    [Theory]
    [InlineData("169.254.169.254")] // cloud metadata
    [InlineData("169.254.0.1")]
    public void Detects_link_local_and_metadata(string ip) =>
        Assert.True(IpScope.IsLinkLocalOrMetadata(IPAddress.Parse(ip)));

    [Fact]
    public void Loopback_is_detected() =>
        Assert.True(IpScope.IsLoopback(IPAddress.Parse("127.0.0.1")));

    [Fact]
    public void Metadata_ip_is_restricted_by_default() =>
        Assert.True(IpScope.IsRestrictedByDefault(IPAddress.Parse("169.254.169.254")));

    [Fact]
    public void Public_ip_is_not_restricted() =>
        Assert.False(IpScope.IsRestrictedByDefault(IPAddress.Parse("93.184.216.34")));

    [Theory]
    [InlineData("192.168.0.0/16", "192.168.5.10", true)]
    [InlineData("10.0.0.0/8", "10.255.1.1", true)]
    [InlineData("10.0.0.0/8", "11.0.0.1", false)]
    [InlineData("192.168.1.0/24", "192.168.2.1", false)]
    public void Cidr_containment(string cidr, string ip, bool expected) =>
        Assert.Equal(expected, IpScope.CidrContains(cidr, IPAddress.Parse(ip)));
}
