using ProjectSky.Scanners.Network;
using Xunit;

namespace ProjectSky.Scanners.Tests;

public class NmapXmlParserTests
{
    private const string SampleXml = """
        <?xml version="1.0"?>
        <nmaprun>
          <host>
            <address addr="45.33.32.156" addrtype="ipv4"/>
            <hostnames><hostname name="scanme.nmap.org"/></hostnames>
            <ports>
              <port protocol="tcp" portid="22">
                <state state="open"/>
                <service name="ssh" product="OpenSSH" version="8.2p1" extrainfo="Ubuntu">
                  <cpe>cpe:/a:openbsd:openssh:8.2p1</cpe>
                </service>
                <script id="ssh-hostkey" output="2048 aa:bb"/>
              </port>
              <port protocol="tcp" portid="80">
                <state state="open"/>
                <service name="http" product="Apache httpd" version="2.4.41"/>
              </port>
              <port protocol="tcp" portid="443">
                <state state="closed"/>
                <service name="https"/>
              </port>
            </ports>
            <os><osmatch name="Linux 5.x" accuracy="95"/></os>
          </host>
        </nmaprun>
        """;

    [Fact]
    public void Parses_host_and_open_ports()
    {
        var run = NmapXmlParser.Parse(SampleXml);

        var host = Assert.Single(run.Hosts);
        Assert.Equal("45.33.32.156", host.Address);
        Assert.Equal("scanme.nmap.org", host.Hostname);
        Assert.Equal("Linux 5.x", host.OsGuess);
        Assert.Equal(3, host.Ports.Count);
    }

    [Fact]
    public void Captures_service_details_and_scripts()
    {
        var run = NmapXmlParser.Parse(SampleXml);
        var ssh = run.Hosts[0].Ports.Single(p => p.Port == 22);

        Assert.Equal("open", ssh.State);
        Assert.Equal("ssh", ssh.Service!.Name);
        Assert.Equal("OpenSSH", ssh.Service.Product);
        Assert.Equal("8.2p1", ssh.Service.Version);
        Assert.Equal("cpe:/a:openbsd:openssh:8.2p1", ssh.Service.Cpe);
        Assert.Single(ssh.Scripts);
    }

    [Fact]
    public void Empty_or_garbage_input_yields_no_hosts()
    {
        Assert.Empty(NmapXmlParser.Parse("").Hosts);
        Assert.Empty(NmapXmlParser.Parse("not xml <<<").Hosts);
    }
}
