
using Microsoft.AspNetCore.Identity;

namespace PlatformPlatform.AccountManagement.Api.Auth;

public class ApplicationUser : IdentityUser
{
    public string Role { get; set; } = "member";

    public string TenantId { get; set; }
    
    [PersonalData]
    public string? Name { get; set; }
 
    public string? RefreshToken { get; set; }
    
}