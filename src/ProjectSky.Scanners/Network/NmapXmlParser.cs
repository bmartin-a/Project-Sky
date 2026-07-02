using System.Xml.Linq;

namespace ProjectSky.Scanners.Network;

/// <summary>
/// Parses nmap's XML output (<c>-oX -</c>) into a <see cref="NmapRun"/>.
/// Written to be null-tolerant: nmap omits elements/attributes freely depending
/// on scan flags, so every lookup is defensive.
/// </summary>
public static class NmapXmlParser
{
    public static NmapRun Parse(string xml)
    {
        if (string.IsNullOrWhiteSpace(xml))
            return new NmapRun([]);

        XDocument doc;
        try
        {
            doc = XDocument.Parse(xml);
        }
        catch (System.Xml.XmlException)
        {
            return new NmapRun([]);
        }

        var hosts = new List<NmapHost>();
        foreach (var hostEl in doc.Descendants("host"))
        {
            var address = hostEl.Elements("address")
                .FirstOrDefault(a => (string?)a.Attribute("addrtype") is "ipv4" or "ipv6")
                ?.Attribute("addr")?.Value
                ?? hostEl.Element("address")?.Attribute("addr")?.Value;

            var hostname = hostEl.Element("hostnames")?.Elements("hostname")
                .FirstOrDefault()?.Attribute("name")?.Value;

            var osGuess = hostEl.Element("os")?.Elements("osmatch")
                .OrderByDescending(m => ParseInt(m.Attribute("accuracy")?.Value))
                .FirstOrDefault()?.Attribute("name")?.Value;

            var ports = new List<NmapPort>();
            foreach (var portEl in hostEl.Element("ports")?.Elements("port") ?? Enumerable.Empty<XElement>())
            {
                var portId = ParseInt(portEl.Attribute("portid")?.Value);
                if (portId is null) continue;

                var protocol = portEl.Attribute("protocol")?.Value ?? "tcp";
                var state = portEl.Element("state")?.Attribute("state")?.Value ?? "unknown";

                var svcEl = portEl.Element("service");
                NmapService? service = svcEl is null ? null : new NmapService(
                    Name: svcEl.Attribute("name")?.Value,
                    Product: svcEl.Attribute("product")?.Value,
                    Version: svcEl.Attribute("version")?.Value,
                    ExtraInfo: svcEl.Attribute("extrainfo")?.Value,
                    Cpe: svcEl.Element("cpe")?.Value);

                var scripts = portEl.Elements("script")
                    .Select(s => new NmapScript(
                        s.Attribute("id")?.Value ?? "unknown",
                        s.Attribute("output")?.Value ?? string.Empty))
                    .ToList();

                ports.Add(new NmapPort(portId.Value, protocol, state, service, scripts));
            }

            hosts.Add(new NmapHost(address, hostname, osGuess, ports));
        }

        return new NmapRun(hosts);
    }

    private static int? ParseInt(string? value) =>
        int.TryParse(value, out var n) ? n : null;
}
