using Microsoft.AspNetCore.Identity;

namespace PlatformPlatform.AccountManagement.Infrastructure.Identity;

public sealed class IdentityUser : IdentityUser<UserId>
{
    [UsedImplicitly]
    public TenantId? TenantId { get; init; }

    public override UserId Id { get; set; } = UserId.NewId();

    [UsedImplicitly]
    public UserRole UserRole { get; init; }
}