using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using ProjectSky.Core.Entities;
using ProjectSky.Core.Enums;
using ProjectSky.Core.Interfaces;
using ProjectSky.Core.Models;
using ProjectSky.Scanners.Base;

namespace ProjectSky.Scanners.Infra;

/// <summary>
/// Infrastructure scanner that inspects a host's TLS endpoint: it performs a
/// handshake, captures the served certificate and negotiated protocol, and maps
/// issues (expiry, self-signed, name mismatch, weak protocol) to findings.
/// Evaluation logic lives in the pure <see cref="CertEvaluator"/>.
/// </summary>
public sealed class SslTlsScanner : ScannerBase
{
    private static readonly TimeSpan ConnectTimeout = TimeSpan.FromSeconds(15);

    public override string Name => "ssl-tls";
    public override ScanType Type => ScanType.Infrastructure;

    public override async Task<IReadOnlyList<Finding>> ScanAsync(
        Target target,
        ScanOptions options,
        string? pinnedIp,
        IScanProgressReporter progress,
        CancellationToken ct)
    {
        var validation = TargetValidator.Validate(target.Address, target.Type);
        if (!validation.IsValid || validation.Normalized is null)
            throw new InvalidOperationException($"Refusing to scan invalid target: {validation.Error}");

        // Container images are handled by the Trivy scanner, not TLS.
        if (target.Type == TargetType.ContainerImage)
            return [];

        if (target.Type == TargetType.CidrRange)
            return [InfoFinding(target, "TLS scan skipped",
                "TLS scanning is not supported for CIDR ranges.", "cidr")];

        var (host, port) = ResolveEndpoint(target.Type, validation.Normalized);

        // Connect to the authorizer's pinned IP (no re-resolution / rebinding);
        // keep the hostname for SNI + name-match evaluation.
        var connectTo = pinnedIp is not null && System.Net.IPAddress.TryParse(pinnedIp, out _)
            ? pinnedIp
            : host;

        await ReportSafeAsync(progress,
            new ScanProgress(target.Id, ScanStatus.Running, 20, $"Connecting to {host}:{port}", 0), ct);

        CertInfo? cert;
        try
        {
            cert = await HandshakeAsync(connectTo, host, port, ct);
        }
        catch (Exception ex) when (ex is SocketException or IOException or AuthenticationException)
        {
            return [InfoFinding(target, $"No TLS service on {host}:{port}", ex.Message, $"{host}:{port}")];
        }

        var issues = CertEvaluator.Evaluate(cert, DateTimeOffset.UtcNow);
        var findings = issues.Select(i => MapFinding(target, host, port, i)).ToList();

        await ReportSafeAsync(progress,
            new ScanProgress(target.Id, ScanStatus.Running, 90, "TLS check complete", findings.Count), ct);

        return findings;
    }

    private static (string Host, int Port) ResolveEndpoint(TargetType type, string address)
    {
        if (type == TargetType.Url)
        {
            var uri = new Uri(address);
            var port = uri.Port > 0 ? uri.Port : 443;
            return (uri.Host, uri.Scheme == Uri.UriSchemeHttps || uri.IsDefaultPort ? port : 443);
        }
        return (address, 443);
    }

    private static async Task<CertInfo> HandshakeAsync(
        string connectTo, string sniHost, int port, CancellationToken ct)
    {
        using var tcp = new TcpClient();
        using var connectCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        connectCts.CancelAfter(ConnectTimeout);
        await tcp.ConnectAsync(connectTo, port, connectCts.Token);

        var nameMatches = true;
        using var ssl = new SslStream(tcp.GetStream(), false, (_, _, _, errors) =>
        {
            // Accept the cert so we can inspect it; record name-mismatch for evaluation.
            nameMatches = !errors.HasFlag(SslPolicyErrors.RemoteCertificateNameMismatch);
            return true;
        });

        await ssl.AuthenticateAsClientAsync(
            new SslClientAuthenticationOptions { TargetHost = sniHost }, connectCts.Token);

        if (ssl.RemoteCertificate is null)
            throw new AuthenticationException("Server presented no certificate.");

        using var cert = new X509Certificate2(ssl.RemoteCertificate);
        return new CertInfo(
            Subject: cert.Subject,
            Issuer: cert.Issuer,
            NotBefore: cert.NotBefore.ToUniversalTime(),
            NotAfter: cert.NotAfter.ToUniversalTime(),
            ProtocolName: ssl.SslProtocol.ToString(),
            NameMatches: nameMatches);
    }

    private Finding MapFinding(Target target, string host, int port, CertIssue issue) => new()
    {
        TargetId = target.Id,
        Title = issue.Title,
        Description = issue.Description,
        Severity = issue.Severity,
        Port = port,
        Protocol = "tcp",
        Service = "tls",
        Fingerprint = ComputeFingerprint(target.Address, "tls", host, port.ToString(), issue.Title),
    };

    private Finding InfoFinding(Target target, string title, string? description, string discriminator) => new()
    {
        TargetId = target.Id,
        Title = title,
        Description = description,
        Severity = Severity.Info,
        Service = "tls",
        Fingerprint = ComputeFingerprint(target.Address, "tls", discriminator, title),
    };
}
