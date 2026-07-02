using ProjectSky.Core.Enums;
using ProjectSky.Scanners.Base;
using Xunit;

namespace ProjectSky.Scanners.Tests;

public class TargetValidatorTests
{
    [Theory]
    [InlineData("scanme.nmap.org")]
    [InlineData("example.com")]
    [InlineData("sub.domain.example.co.uk")]
    public void Accepts_valid_hostnames(string host) =>
        Assert.True(TargetValidator.Validate(host, TargetType.Hostname).IsValid);

    [Theory]
    [InlineData("scanme.nmap.org; rm -rf /")]  // command injection attempt
    [InlineData("host name")]                   // space
    [InlineData("-leading-hyphen.com")]
    [InlineData("bad_host$.com")]
    [InlineData("a|b.com")]
    public void Rejects_injection_and_malformed_hostnames(string host) =>
        Assert.False(TargetValidator.Validate(host, TargetType.Hostname).IsValid);

    [Theory]
    [InlineData("192.168.1.1")]
    [InlineData("8.8.8.8")]
    [InlineData("2001:db8::1")]
    public void Accepts_valid_ips(string ip) =>
        Assert.True(TargetValidator.Validate(ip, TargetType.IpAddress).IsValid);

    [Theory]
    [InlineData("999.1.1.1")]
    [InlineData("1.2.3")]
    [InlineData("not-an-ip")]
    public void Rejects_invalid_ips(string ip) =>
        Assert.False(TargetValidator.Validate(ip, TargetType.IpAddress).IsValid);

    [Theory]
    [InlineData("10.0.0.0/8")]
    [InlineData("192.168.0.0/16")]
    [InlineData("2001:db8::/32")]
    public void Accepts_valid_cidr(string cidr) =>
        Assert.True(TargetValidator.Validate(cidr, TargetType.CidrRange).IsValid);

    [Theory]
    [InlineData("10.0.0.0/33")]
    [InlineData("10.0.0.0")]
    [InlineData("10.0.0.0/abc")]
    public void Rejects_invalid_cidr(string cidr) =>
        Assert.False(TargetValidator.Validate(cidr, TargetType.CidrRange).IsValid);

    [Theory]
    [InlineData("https://example.com")]
    [InlineData("http://example.com:8080/path")]
    public void Accepts_http_urls(string url) =>
        Assert.True(TargetValidator.Validate(url, TargetType.Url).IsValid);

    [Theory]
    [InlineData("ftp://example.com")]
    [InlineData("file:///etc/passwd")]
    [InlineData("javascript:alert(1)")]
    [InlineData("not a url")]
    public void Rejects_non_http_urls(string url) =>
        Assert.False(TargetValidator.Validate(url, TargetType.Url).IsValid);
}
