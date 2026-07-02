using Microsoft.AspNetCore.DataProtection;

namespace ProjectSky.Infrastructure.Security;

/// <summary>
/// Encrypts/decrypts stored secrets (Defender client secret, etc.) using ASP.NET
/// Data Protection. The key ring must be persisted (mounted volume or DB) so
/// protected values survive restarts — see Program.cs wiring and SECURITY.md.
/// </summary>
public sealed class SecretProtector
{
    private const string Purpose = "ProjectSky.StoredSecrets.v1";
    private readonly IDataProtector _protector;

    public SecretProtector(IDataProtectionProvider provider) =>
        _protector = provider.CreateProtector(Purpose);

    public string Protect(string plaintext) => _protector.Protect(plaintext);

    public string Unprotect(string ciphertext) => _protector.Unprotect(ciphertext);
}
