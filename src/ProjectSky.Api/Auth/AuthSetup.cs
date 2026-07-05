using System.Security.Claims;
using System.Text.Encodings.Web;
using Hangfire.Dashboard;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Options;

namespace ProjectSky.Api.Auth;

/// <summary>
/// Configures authentication + authorization. Two modes, selected by
/// <c>Auth:Mode</c> (no default — an unset/unknown value fails startup):
///  - "Oidc": validates JWT bearer tokens from any OpenID Connect provider.
///  - "LocalDev": authenticates every request as a local admin. Permitted ONLY
///    in the Development environment; refuses to start otherwise.
///
/// A fallback policy requires an authenticated user on every endpoint, and an
/// "Admin" policy gates privileged operations (scan-policy creation, Defender
/// sync, schedule mutation, the Hangfire dashboard).
/// </summary>
public static class AuthSetup
{
    public const string LocalDevScheme = "LocalDev";
    public const string AdminPolicy = "Admin";

    public static IServiceCollection AddProjectSkyAuth(
        this IServiceCollection services, IConfiguration config, IHostEnvironment env)
    {
        var mode = config["Auth:Mode"];
        var adminRole = config["Auth:Oidc:AdminRole"] ?? "Admin";

        if (string.Equals(mode, "Oidc", StringComparison.OrdinalIgnoreCase))
        {
            var audience = config["Auth:Oidc:Audience"];
            if (string.IsNullOrWhiteSpace(audience))
                throw new InvalidOperationException(
                    "Auth:Oidc:Audience must be set in Oidc mode (audience validation is mandatory).");

            services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
                .AddJwtBearer(options =>
                {
                    options.Authority = config["Auth:Oidc:Authority"];
                    options.Audience = audience;
                    options.TokenValidationParameters.ValidateAudience = true;
                    options.TokenValidationParameters.RoleClaimType =
                        config["Auth:Oidc:RoleClaim"] ?? "roles";

                    // Allow SignalR/WebSocket clients to pass the token via query string.
                    options.Events = new JwtBearerEvents
                    {
                        OnMessageReceived = ctx =>
                        {
                            var accessToken = ctx.Request.Query["access_token"];
                            if (!string.IsNullOrEmpty(accessToken) &&
                                ctx.HttpContext.Request.Path.StartsWithSegments("/hubs"))
                                ctx.Token = accessToken;
                            return Task.CompletedTask;
                        },
                    };
                });
        }
        else if (string.Equals(mode, "LocalDev", StringComparison.OrdinalIgnoreCase))
        {
            if (!env.IsDevelopment())
                throw new InvalidOperationException(
                    "Auth:Mode=LocalDev is only permitted in the Development environment. " +
                    "Set Auth:Mode=Oidc for any non-development deployment.");

            services.AddAuthentication(LocalDevScheme)
                .AddScheme<AuthenticationSchemeOptions, LocalDevAuthHandler>(LocalDevScheme, _ => { });
        }
        else
        {
            throw new InvalidOperationException(
                "Auth:Mode must be set to 'Oidc' or 'LocalDev'.");
        }

        services.AddAuthorization(options =>
        {
            options.FallbackPolicy = new AuthorizationPolicyBuilder()
                .RequireAuthenticatedUser()
                .Build();
            options.AddPolicy(AdminPolicy, p => p.RequireRole(adminRole));
        });

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
        var identity = new ClaimsIdentity(claims, Scheme.Name, ClaimTypes.Name, ClaimTypes.Role);
        var ticket = new AuthenticationTicket(new ClaimsPrincipal(identity), Scheme.Name);
        return Task.FromResult(AuthenticateResult.Success(ticket));
    }
}

/// <summary>Restricts the Hangfire dashboard to authenticated admins.</summary>
public sealed class HangfireDashboardAuthFilter : IDashboardAuthorizationFilter
{
    private readonly string _adminRole;

    public HangfireDashboardAuthFilter(string adminRole) => _adminRole = adminRole;

    public bool Authorize(DashboardContext context)
    {
        var user = context.GetHttpContext().User;
        return user.Identity?.IsAuthenticated == true && user.IsInRole(_adminRole);
    }
}
