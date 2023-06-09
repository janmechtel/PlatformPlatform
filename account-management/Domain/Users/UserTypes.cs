using System.ComponentModel;
using JetBrains.Annotations;
using PlatformPlatform.SharedKernel.DomainCore.Identity;

namespace PlatformPlatform.AccountManagement.Domain.Users;

[TypeConverter(typeof(UserIdTypeConverter))]
public sealed record UserId(long Value) : StronglyTypedId<UserId>(Value)
{
    public override string ToString()
    {
        return Value.ToString();
    }
}

public sealed class UserIdTypeConverter : StronglyTypedIdTypeConverter<UserId>
{
}

[UsedImplicitly(ImplicitUseTargetFlags.Members)]
public enum UserRole
{
    TenantUser = 0,
    TenantAdmin = 1,
    TenantOwner = 2
}