namespace ProjectSky.Core.Entities;

/// <summary>A user, provisioned from OIDC claims on first sign-in.</summary>
public class User
{
    public Guid Id { get; set; } = Guid.NewGuid();

    /// <summary>OIDC subject ("sub" claim). Unique per provider.</summary>
    public required string Subject { get; set; }

    public string? Email { get; set; }
    public string? DisplayName { get; set; }

    /// <summary>Coarse role: "Admin", "Operator", or "Viewer".</summary>
    public string Role { get; set; } = "Viewer";

    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset? LastLoginAt { get; set; }
}
