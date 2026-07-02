using Hangfire;
using Hangfire.PostgreSql;
using ProjectSky.Infrastructure;

var builder = WebApplication.CreateBuilder(args);
var config = builder.Configuration;

// Same object graph as the API so jobs resolve identical services.
builder.Services.AddProjectSkyInfrastructure(config);
builder.Services.AddProjectSkyRealtime(config);

var postgres = config.GetConnectionString("Postgres");
builder.Services.AddHangfire(cfg => cfg
    .SetDataCompatibilityLevel(CompatibilityLevel.Version_180)
    .UseSimpleAssemblyNameTypeSerializer()
    .UseRecommendedSerializerSettings()
    .UsePostgreSqlStorage(o => o.UseNpgsqlConnection(postgres)));

// This host runs the Hangfire server that actually executes queued scans.
builder.Services.AddHangfireServer();

var app = builder.Build();

app.MapGet("/health", () => Results.Ok(new { status = "ok", role = "worker" }));

app.Run();
