using System.Text.Json.Serialization;
using Hangfire;
using Hangfire.PostgreSql;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using ProjectSky.Api.Auth;
using ProjectSky.Core.Interfaces;
using ProjectSky.Infrastructure;
using ProjectSky.Infrastructure.Data;
using ProjectSky.Infrastructure.Defender;
using ProjectSky.Infrastructure.Jobs;
using ProjectSky.Infrastructure.Realtime;

var builder = WebApplication.CreateBuilder(args);
var config = builder.Configuration;

// Serialize enums as strings so the API contract is stable and SPA-friendly
// ("Network"/"Completed" rather than integers).
builder.Services.AddControllers()
    .AddJsonOptions(o => o.JsonSerializerOptions.Converters.Add(new JsonStringEnumConverter()));
builder.Services.AddOpenApi();

builder.Services.AddProjectSkyInfrastructure(config);
builder.Services.AddProjectSkyRealtime(config);
builder.Services.AddProjectSkyAuth(config, builder.Environment);

// Persist Data Protection keys so stored secrets survive restarts (SECURITY.md).
var keyPath = config["DataProtection:KeyPath"];
if (!string.IsNullOrWhiteSpace(keyPath))
    builder.Services.AddDataProtection().PersistKeysToFileSystem(new DirectoryInfo(keyPath));

// Hangfire client (the Worker hosts the server that executes jobs).
var postgres = config.GetConnectionString("Postgres");
builder.Services.AddHangfire(cfg => cfg
    .SetDataCompatibilityLevel(CompatibilityLevel.Version_180)
    .UseSimpleAssemblyNameTypeSerializer()
    .UseRecommendedSerializerSettings()
    .UsePostgreSqlStorage(o => o.UseNpgsqlConnection(postgres)));

// CORS for the SPA (SignalR needs credentials + explicit origins).
var origins = config.GetSection("Cors:Origins").Get<string[]>() ?? ["http://localhost:3000"];
builder.Services.AddCors(o => o.AddPolicy("frontend", p => p
    .WithOrigins(origins)
    .AllowAnyHeader()
    .AllowAnyMethod()
    .AllowCredentials()));

var app = builder.Build();

// Create/upgrade the schema. Uses migrations when present, otherwise creates the
// schema from the model (greenfield: migrations are added once a .NET SDK is
// available — see README).
using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
    if (db.Database.GetMigrations().Any())
        db.Database.Migrate();
    else
        db.Database.EnsureCreated();

    // Re-register Hangfire recurring jobs for any enabled scan schedules.
    var schedules = scope.ServiceProvider.GetRequiredService<IScanScheduleRepository>();
    var recurring = scope.ServiceProvider.GetRequiredService<IRecurringJobManager>();
    foreach (var s in schedules.ListEnabledAsync(CancellationToken.None).GetAwaiter().GetResult())
    {
        recurring.AddOrUpdate<IScheduledScanJob>(
            s.RecurringJobId, j => j.RunAsync(s.Id, CancellationToken.None), s.Cron);
    }
}

// Publish the API schema only in Development (avoid anonymous schema disclosure).
if (app.Environment.IsDevelopment())
    app.MapOpenApi();

app.UseCors("frontend");
app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();
app.MapHub<ScanProgressHub>("/hubs/scan").RequireAuthorization();
app.MapGet("/health", () => Results.Ok(new { status = "ok" })).AllowAnonymous();

app.UseHangfireDashboard("/hangfire", new DashboardOptions
{
    Authorization = [new HangfireDashboardAuthFilter(config["Auth:Oidc:AdminRole"] ?? "Admin")],
});

// Schedule the recurring NVD incremental sync (executed by the Worker's server).
RecurringJob.AddOrUpdate<INvdSyncJob>(
    "nvd-incremental",
    j => j.RunIncrementalAsync(CancellationToken.None),
    config["Nvd:SyncCron"] ?? "0 3 * * *");

// Schedule Defender ingestion only when credentials are configured.
var defenderOptions = app.Services.GetRequiredService<DefenderOptions>();
if (defenderOptions.IsConfigured)
{
    RecurringJob.AddOrUpdate<IDefenderIngestionJob>(
        "defender-ingest",
        j => j.RunAsync(CancellationToken.None),
        defenderOptions.SyncCron);
}

app.Run();

// Exposed for WebApplicationFactory in integration tests.
public partial class Program { }
