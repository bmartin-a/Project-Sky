namespace ProjectSky.Scanners.Network;

/// <summary>Neutral representation of parsed nmap XML (decoupled from entities).</summary>
public sealed record NmapService(
    string? Name,
    string? Product,
    string? Version,
    string? ExtraInfo,
    string? Cpe);

public sealed record NmapScript(string Id, string Output);

public sealed record NmapPort(
    int Port,
    string Protocol,
    string State,
    NmapService? Service,
    IReadOnlyList<NmapScript> Scripts);

public sealed record NmapHost(
    string? Address,
    string? Hostname,
    string? OsGuess,
    IReadOnlyList<NmapPort> Ports);

public sealed record NmapRun(IReadOnlyList<NmapHost> Hosts);
