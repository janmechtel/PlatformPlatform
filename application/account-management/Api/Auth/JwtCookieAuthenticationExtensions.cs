using Microsoft.AspNetCore.Identity;
using PlatformPlatform.AccountManagement.Infrastructure;
using IdentityUser = PlatformPlatform.AccountManagement.Infrastructure.Identity.IdentityUser;

namespace PlatformPlatform.AccountManagement.Api.Auth;

public static class JwtCookieAuthenticationExtensions
{
    [UsedImplicitly]
    public static IServiceCollection AddJwtCookieAuthentication(this IServiceCollection services)
    {
        services.Configure<IdentityOptions>(options => options.User.RequireUniqueEmail = false);

        services.AddAuthentication(options =>
            {
                options.DefaultScheme = JwtCookieAuthenticationSchemeOptions.AuthenticationScheme;
                options.DefaultAuthenticateScheme = JwtCookieAuthenticationSchemeOptions.AuthenticationScheme;
                options.DefaultChallengeScheme = JwtCookieAuthenticationSchemeOptions.AuthenticationScheme;
                options.DefaultSignInScheme = JwtCookieAuthenticationSchemeOptions.AuthenticationScheme;
            })
            .AddScheme<JwtCookieAuthenticationSchemeOptions, JwtCookieAuthenticationHandler>(
                JwtCookieAuthenticationSchemeOptions.AuthenticationScheme, null);

        services.AddAuthorization();

        services
            .AddIdentityApiEndpoints<IdentityUser>(options => { options.SignIn.RequireConfirmedAccount = true; })
            // .AddRoles<IdentityRole>()
            .AddEntityFrameworkStores<AccountManagementDbContext>();

        services.AddSingleton<IEmailSender<IdentityUser>, IdentityEmailTestSender>();

        return services;
    }
}