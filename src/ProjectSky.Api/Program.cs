using Hangfire;
using Hangfire.PostgreSql;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using ProjectSky.Api.Auth;
using ProjectSky.Infrastructure;
using ProjectSky.Infrastructure.Data;
using ProjectSky.Infrastructure.Jobs;
using ProjectSky.Infrastructure.Realtime;

var builder = WebApplication.CreateBuilder(args);
var config = builder.Configuration;

builder.Services.AddControllers();
builder.Services.AddOpenApi();

builder.Services.AddProjectSkyInfrastructure(config);
builder.Services.AddProjectSkyRealtime(config);
builder.Services.AddProjectSkyAuth(config);

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
}

app.MapOpenApi();
app.UseCors("frontend");
app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();
app.MapHub<ScanProgressHub>("/hubs/scan");
app.MapGet("/health", () => Results.Ok(new { status = "ok" }));

app.UseHangfireDashboard("/hangfire", new DashboardOptions
{
    Authorization = [new HangfireDashboardAuthFilter()],
});

// Schedule the recurring NVD incremental sync (executed by the Worker's server).
RecurringJob.AddOrUpdate<INvdSyncJob>(
    "nvd-incremental",
    j => j.RunIncrementalAsync(CancellationToken.None),
    config["Nvd:SyncCron"] ?? "0 3 * * *");

app.Run();

// Exposed for WebApplicationFactory in integration tests.
public partial class Program { }
