using System.Security.Claims;
using System.Text.Encodings.Web;
using Hangfire.Dashboard;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Options;

namespace ProjectSky.Api.Auth;

/// <summary>
/// Configures authentication. Two modes, selected by <c>Auth:Mode</c>:
///  - "Oidc": validates JWT bearer tokens from any OpenID Connect provider
///    (Azure Entra ID, Keycloak, Authentik, ...). No provider is hard-coded.
///  - "LocalDev": authenticates every request as a local admin. For development
///    only — never enable in production.
/// </summary>
public static class AuthSetup
{
    public const string LocalDevScheme = "LocalDev";

    public static IServiceCollection AddProjectSkyAuth(this IServiceCollection services, IConfiguration config)
    {
        var mode = config["Auth:Mode"] ?? "LocalDev";

        if (string.Equals(mode, "Oidc", StringComparison.OrdinalIgnoreCase))
        {
            services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
                .AddJwtBearer(options =>
                {
                    options.Authority = config["Auth:Oidc:Authority"];
                    options.Audience = config["Auth:Oidc:Audience"];
                    options.TokenValidationParameters.ValidateAudience =
                        !string.IsNullOrWhiteSpace(config["Auth:Oidc:Audience"]);
                });
        }
        else
        {
            services.AddAuthentication(LocalDevScheme)
                .AddScheme<AuthenticationSchemeOptions, LocalDevAuthHandler>(LocalDevScheme, _ => { });
        }

        services.AddAuthorization();
        return services;
    }
}

/// <summary>Development-only handler that authenticates every request as an admin.</summary>
public sealed class LocalDevAuthHandler : AuthenticationHandler<AuthenticationSchemeOptions>
{
    public LocalDevAuthHandler(
        IOptionsMonitor<AuthenticationSchemeOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder)
        : base(options, logger, encoder) { }

    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var claims = new[]
        {
            new Claim(ClaimTypes.NameIdentifier, "local-dev"),
            new Claim("sub", "local-dev"),
            new Claim(ClaimTypes.Name, "Local Dev"),
            new Claim(ClaimTypes.Role, "Admin"),
        };
        var identity = new ClaimsIdentity(claims, Scheme.Name);
        var ticket = new AuthenticationTicket(new ClaimsPrincipal(identity), Scheme.Name);
        return Task.FromResult(AuthenticateResult.Success(ticket));
    }
}

/// <summary>Restricts the Hangfire dashboard to authenticated users.</summary>
public sealed class HangfireDashboardAuthFilter : IDashboardAuthorizationFilter
{
    public bool Authorize(DashboardContext context)
    {
        var httpContext = context.GetHttpContext();
        return httpContext.User.Identity?.IsAuthenticated == true;
    }
}
