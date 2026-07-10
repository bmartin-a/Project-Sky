using System.Net.Http.Headers;
using System.Text.Json;

namespace ProjectSky.Infrastructure.Defender;

/// <summary>
/// Client for the Microsoft Defender for Endpoint API. Handles the Azure AD
/// client-credentials token flow (with in-memory caching) and paginated reads of
/// machines and machine↔vulnerability rows, returning neutral records produced
/// by <see cref="DefenderMapper"/>. Safe to hold as a singleton.
/// </summary>
public sealed class DefenderApiClient
{
    private readonly IHttpClientFactory _factory;
    private readonly DefenderOptions _options;
    private readonly SemaphoreSlim _tokenLock = new(1, 1);

    private string? _cachedToken;
    private DateTimeOffset _tokenExpiry = DateTimeOffset.MinValue;

    public DefenderApiClient(IHttpClientFactory factory, DefenderOptions options)
    {
        _factory = factory;
        _options = options;
    }

    public async Task<IReadOnlyList<DefenderMachine>> GetMachinesAsync(CancellationToken ct)
    {
        var machines = new List<DefenderMachine>();
        await foreach (var page in ReadPagesAsync(_options.ApiBaseUrl + _options.MachinesPath, ct))
            machines.AddRange(DefenderMapper.ParseMachines(page));
        return machines;
    }

    public async Task<IReadOnlyList<DefenderVuln>> GetVulnerabilitiesAsync(CancellationToken ct)
    {
        var vulns = new List<DefenderVuln>();
        await foreach (var page in ReadPagesAsync(_options.ApiBaseUrl + _options.VulnerabilitiesPath, ct))
            vulns.AddRange(DefenderMapper.ParseVulnerabilities(page));
        return vulns;
    }

    private async IAsyncEnumerable<JsonElement> ReadPagesAsync(
        string url, [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken ct)
    {
        var token = await GetTokenAsync(ct);
        var http = _factory.CreateClient("defender");
        http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

        string? next = url;
        while (next is not null)
        {
            using var resp = await http.GetAsync(next, ct);
            resp.EnsureSuccessStatusCode();
            using var doc = await JsonDocument.ParseAsync(
                await resp.Content.ReadAsStreamAsync(ct), cancellationToken: ct);

            yield return doc.RootElement.Clone();

            next = doc.RootElement.TryGetProperty("@odata.nextLink", out var link)
                   && link.ValueKind == JsonValueKind.String
                ? link.GetString()
                : null;
        }
    }

    private async Task<string> GetTokenAsync(CancellationToken ct)
    {
        if (_cachedToken is not null && DateTimeOffset.UtcNow < _tokenExpiry)
            return _cachedToken;

        await _tokenLock.WaitAsync(ct);
        try
        {
            if (_cachedToken is not null && DateTimeOffset.UtcNow < _tokenExpiry)
                return _cachedToken;

            var http = _factory.CreateClient("defender");
            var tokenUrl = $"{_options.Authority.TrimEnd('/')}/{_options.TenantId}/oauth2/v2.0/token";
            using var body = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "client_credentials",
                ["client_id"] = _options.ClientId,
                ["client_secret"] = _options.ClientSecret,
                ["scope"] = _options.Scope,
            });

            using var resp = await http.PostAsync(tokenUrl, body, ct);
            resp.EnsureSuccessStatusCode();
            using var doc = await JsonDocument.ParseAsync(
                await resp.Content.ReadAsStreamAsync(ct), cancellationToken: ct);

            var token = doc.RootElement.GetProperty("access_token").GetString()
                ?? throw new InvalidOperationException("Defender token response had no access_token.");
            var expiresIn = doc.RootElement.TryGetProperty("expires_in", out var e) && e.TryGetInt32(out var s)
                ? s
                : 3600;

            _cachedToken = token;
            _tokenExpiry = DateTimeOffset.UtcNow.AddSeconds(expiresIn - 60); // refresh a minute early
            return token;
        }
        finally
        {
            _tokenLock.Release();
        }
    }
}
