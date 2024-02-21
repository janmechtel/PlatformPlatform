using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using PlatformPlatform.SharedKernel.InfrastructureCore.EntityFramework;
using IdentityUser = PlatformPlatform.AccountManagement.Infrastructure.Identity.IdentityUser;

namespace PlatformPlatform.AccountManagement.Infrastructure;

public sealed class AccountManagementDbContext(DbContextOptions<AccountManagementDbContext> options)
    : SharedKernelDbContext<AccountManagementDbContext>(options)
{
    public DbSet<Tenant> Tenants => Set<Tenant>();

    public DbSet<User> Users => Set<User>();

    [UsedImplicitly]
    public DbSet<IdentityUser> IdentityUsers => Set<IdentityUser>();

    [UsedImplicitly]
    public DbSet<IdentityUserClaim<UserId>> IdentityUserClaims => Set<IdentityUserClaim<UserId>>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        // Tenant
        modelBuilder.MapStronglyTypedId<Tenant, TenantId, string>(t => t.Id);

        // User
        modelBuilder.MapStronglyTypedUuid<User, UserId>(u => u.Id);
        modelBuilder.MapStronglyTypedId<User, TenantId, string>(u => u.TenantId);
        modelBuilder.Entity<User>()
            .HasOne<Tenant>()
            .WithMany()
            .HasForeignKey(u => u.TenantId)
            .HasPrincipalKey(t => t.Id);

        // IdentityUser
        modelBuilder.MapStronglyTypedUuid<IdentityUser, UserId>(u => u.Id);
        modelBuilder.MapStronglyTypedId<IdentityUser, TenantId, string>(u => u.TenantId!);

        // IdentityUserClaim
        modelBuilder.MapStronglyTypedUuid<IdentityUserClaim<UserId>, UserId>(u => u.UserId);
    }
}