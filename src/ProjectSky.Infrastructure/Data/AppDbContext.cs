using Microsoft.EntityFrameworkCore;
using ProjectSky.Core.Entities;

namespace ProjectSky.Infrastructure.Data;

/// <summary>EF Core context for Project-Sky (PostgreSQL).</summary>
public class AppDbContext : DbContext
{
    public AppDbContext(DbContextOptions<AppDbContext> options) : base(options) { }

    public DbSet<Target> Targets => Set<Target>();
    public DbSet<Scan> Scans => Set<Scan>();
    public DbSet<Finding> Findings => Set<Finding>();
    public DbSet<Cve> Cves => Set<Cve>();
    public DbSet<CpeMatch> CpeMatches => Set<CpeMatch>();
    public DbSet<User> Users => Set<User>();
    public DbSet<ScanPolicy> ScanPolicies => Set<ScanPolicy>();

    protected override void OnModelCreating(ModelBuilder b)
    {
        base.OnModelCreating(b);

        b.Entity<Target>(e =>
        {
            e.HasKey(x => x.Id);
            e.Property(x => x.Address).HasMaxLength(2048).IsRequired();
            e.HasMany(x => x.Scans).WithOne(x => x.Target!).HasForeignKey(x => x.TargetId);
        });

        b.Entity<Scan>(e =>
        {
            e.HasKey(x => x.Id);
            e.HasIndex(x => x.Status);
            e.Property(x => x.CreatedBySubject).HasMaxLength(256);
            // Scan ↔ Finding relationship is configured on the Finding side.
        });

        b.Entity<Finding>(e =>
        {
            e.HasKey(x => x.Id);
            e.Property(x => x.Title).HasMaxLength(1024).IsRequired();
            e.Property(x => x.Fingerprint).HasMaxLength(64).IsRequired();
            e.Property(x => x.CveId).HasMaxLength(32);
            e.Property(x => x.Source).HasMaxLength(32).IsRequired();
            e.HasIndex(x => x.Fingerprint);
            e.HasIndex(x => new { x.TargetId, x.State });
            e.HasOne(x => x.Cve).WithMany().HasForeignKey(x => x.CveId)
                .OnDelete(DeleteBehavior.SetNull);
            // ScanId is optional (null for ingested findings); deleting a scan
            // detaches its findings rather than cascading.
            e.HasOne(x => x.Scan).WithMany(x => x.Findings).HasForeignKey(x => x.ScanId)
                .OnDelete(DeleteBehavior.SetNull);
        });

        b.Entity<Cve>(e =>
        {
            e.HasKey(x => x.Id);
            e.Property(x => x.Id).HasMaxLength(32);
            e.HasIndex(x => x.LastModifiedAt);
            e.HasMany(x => x.CpeMatches).WithOne(x => x.Cve!).HasForeignKey(x => x.CveId)
                .OnDelete(DeleteBehavior.Cascade);
        });

        b.Entity<CpeMatch>(e =>
        {
            e.HasKey(x => x.Id);
            e.Property(x => x.Criteria).HasMaxLength(512).IsRequired();
            e.HasIndex(x => x.Criteria);
        });

        b.Entity<User>(e =>
        {
            e.HasKey(x => x.Id);
            e.Property(x => x.Subject).HasMaxLength(256).IsRequired();
            e.HasIndex(x => x.Subject).IsUnique();
        });

        b.Entity<ScanPolicy>(e =>
        {
            e.HasKey(x => x.Id);
            e.Property(x => x.Name).HasMaxLength(256).IsRequired();
            // List<string> maps to a jsonb column via EF Core primitive collections.
            e.Property(x => x.AllowedTargets).HasColumnType("jsonb");
        });
    }
}
