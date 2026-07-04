using System.Text.Json;
using ProjectSky.Infrastructure.Defender;
using Xunit;

namespace ProjectSky.Api.Tests;

public class DefenderMapperTests
{
    private static JsonElement Parse(string json) => JsonDocument.Parse(json).RootElement;

    [Fact]
    public void Parses_machines_from_odata_value()
    {
        var json = """
            {"value":[
              {"id":"m1","computerDnsName":"host1.corp","lastIpAddress":"10.0.0.5","osPlatform":"Windows11","exposureLevel":"High"},
              {"id":"m2","computerDnsName":"host2.corp","lastIpAddress":"10.0.0.6","exposureLevel":"Low"}
            ]}
            """;
        var machines = DefenderMapper.ParseMachines(Parse(json));

        Assert.Equal(2, machines.Count);
        Assert.Equal("host1.corp", machines[0].DnsName);
        Assert.Equal("High", machines[0].ExposureLevel);
    }

    [Fact]
    public void Parses_vulnerabilities_and_skips_rows_missing_keys()
    {
        var json = """
            {"value":[
              {"machineId":"m1","cveId":"CVE-2021-44228","productName":"log4j","productVersion":"2.14.1","severity":"Critical","cvssV3":10.0},
              {"machineId":"m1","productName":"noCve"},
              {"cveId":"CVE-2020-0001"}
            ]}
            """;
        var vulns = DefenderMapper.ParseVulnerabilities(Parse(json));

        Assert.Single(vulns);
        Assert.Equal("CVE-2021-44228", vulns[0].CveId);
        Assert.Equal("m1", vulns[0].MachineId);
        Assert.Equal(10.0, vulns[0].CvssV3);
    }

    [Fact]
    public void Accepts_bare_array_payloads()
    {
        var machines = DefenderMapper.ParseMachines(Parse("""[{"id":"m1"}]"""));
        Assert.Single(machines);
    }
}
