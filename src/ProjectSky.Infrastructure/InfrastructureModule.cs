using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using ProjectSky.Core.Interfaces;
using ProjectSky.Infrastructure.Data;
using ProjectSky.Infrastructure.Jobs;
using ProjectSky.Infrastructure.Realtime;
using ProjectSky.Infrastructure.Repositories;
using ProjectSky.Infrastructure.Security;
using ProjectSky.Infrastructure.Services;
using ProjectSky.Scanners.Base;
using ProjectSky.Scanners.Network;
using ProjectSky.Vulnerability.Nvd;
using ProjectSky.Vulnerability.Scoring;

namespace ProjectSky.Infrastructure;

/// <summary>
/// Registers all shared services (data, repositories, security, scanners,
/// vulnerability pipeline). Consumed by both the API and the Worker so they run
/// an identical object graph.
/// </summary>
public static class InfrastructureModule
{
    public static IServiceCollection AddProjectSkyInfrastructure(
        this IServiceCollection services,
        IConfiguration config)
    {
        // --- Data access ---
        services.AddDbContext<AppDbContext>(options =>
            options.UseNpgsql(config.GetConnectionString("Postgres")));

        services.AddScoped<ITargetRepository, TargetRepository>();
        services.AddScoped<IScanRepository, ScanRepository>();
        services.AddScoped<IFindingRepository, FindingRepository>();
        services.AddScoped<IScanPolicyRepository, ScanPolicyRepository>();
        services.AddScoped<ICveRepository, CveRepository>();

        // --- Security ---
        services.AddScoped<ITargetAuthorizer, TargetAuthorizer>();
        services.AddSingleton<SecretProtector>();

        // --- Vulnerability pipeline ---
        services.AddSingleton<RiskScoreService>();
        services.AddScoped<CveEnrichmentService>();
        services.AddSingleton<FindingReconciliationService>();

        // --- Scanner engine ---
        var scannerOptions =
            config.GetSection(ScannerOptions.SectionName).Get<ScannerOptions>() ?? new ScannerOptions();
        services.AddSingleton(scannerOptions);
        services.AddSingleton<CliRunner>();
        services.AddSingleton<IScanner, NmapScanner>();

        // --- NVD sync ---
        var nvdOptions = config.GetSection(NvdOptions.SectionName).Get<NvdOptions>() ?? new NvdOptions();
        services.AddSingleton(nvdOptions);
        services.AddHttpClient<NvdApiClient>()
            .AddStandardResilienceHandler();
        services.AddScoped<NvdSyncService>();

        // --- Realtime progress + background jobs ---
        services.AddScoped<IScanProgressReporter, SignalRScanProgressReporter>();
        services.AddScoped<IScanExecutionJob, ScanExecutionJob>();
        services.AddScoped<INvdSyncJob, NvdSyncJob>();

        return services;
    }

    /// <summary>
    /// Registers SignalR with the Redis backplane so the API and Worker can both
    /// publish scan progress to connected clients. Call from each host.
    /// </summary>
    public static IServiceCollection AddProjectSkyRealtime(
        this IServiceCollection services, IConfiguration config)
    {
        var redis = config.GetConnectionString("Redis");
        var signalR = services.AddSignalR();
        if (!string.IsNullOrWhiteSpace(redis))
            signalR.AddStackExchangeRedis(redis);
        return services;
    }
}
