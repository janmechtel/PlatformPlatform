using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace PlatformPlatform.AccountManagement.Api.Auth;

public static class IdentityConfiguration
{
    public static IServiceCollection AddIdentityServices(this IServiceCollection services)
    {
        services.Configure<IdentityOptions>(options => options.User.RequireUniqueEmail = false);

        services
            .AddAuthentication(JwtCookieAuthAuthenticationOptions.DefaultScheme)
            .AddJwtCookieAuthentication();

        services.AddDbContext<ApplicationDbContext>(options => options.UseInMemoryDatabase("AppDb"));

        services.AddIdentityApiEndpoints<ApplicationUser>(options =>
            {
                options.SignIn.RequireConfirmedAccount = true;
            })
            // .AddRoles<IdentityRole>()
            .AddEntityFrameworkStores<ApplicationDbContext>();

        services.AddSingleton<IEmailSender<ApplicationUser>, IdentityEmailTestSender>();

        return services;
    }
}