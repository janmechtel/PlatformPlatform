using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using PlatformPlatform.AccountManagement.Api.Auth.JwtCookieAuthentication;
using PlatformPlatform.AccountManagement.Infrastructure;
using IdentityUser = PlatformPlatform.AccountManagement.Infrastructure.Identity.IdentityUser;

namespace PlatformPlatform.AccountManagement.Api.Auth;

public static class AuthenticationServicesExtensions
{
    [UsedImplicitly]
    public static IServiceCollection AddAuthenticationServices(this IServiceCollection services)
    {
        var jwtSecretKey = Environment.GetEnvironmentVariable("JWT_SECRET_KEY") ??
                           throw new InvalidOperationException("JWT_SECRET_KEY environment variable is not set.");
        var jwtSecurityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSecretKey));

        services.Configure<IdentityOptions>(options => options.User.RequireUniqueEmail = false);

        services
            .AddAuthentication(options =>
            {
                options.DefaultScheme = JwtCookieAuthenticationOptions.DefaultScheme;
                options.DefaultAuthenticateScheme = JwtCookieAuthenticationOptions.DefaultScheme;
                options.DefaultSignInScheme = JwtCookieAuthenticationOptions.DefaultScheme;
                options.DefaultSignOutScheme = JwtCookieAuthenticationOptions.DefaultScheme;
                options.DefaultChallengeScheme = JwtCookieAuthenticationOptions.DefaultScheme;
                options.DefaultForbidScheme = JwtCookieAuthenticationOptions.DefaultScheme;
            })
            .AddJwtCookieAuthentication(options =>
            {
                options.SigningSecurityKey = jwtSecurityKey;
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidIssuer = "localhost",
                    ValidAudience = "localhost",
                    IssuerSigningKeys = new[]
                    {
                        jwtSecurityKey
                    }
                };

                // options.Events = PocCustomJwtCookieAuthenticationEvents(), // Add custom events for refresh and logging
            });

        services
            .AddAuthorizationBuilder()
            .AddPolicy("RequireOwnerRole", policy => policy.RequireClaim(ClaimTypes.Role, "Owner"))
            .AddPolicy("RequireMemberRole", policy => policy.RequireClaim(ClaimTypes.Role, "Owner"));

        services
            .AddIdentityApiEndpoints<IdentityUser>(options => { options.SignIn.RequireConfirmedAccount = true; })
            // .AddRoles<IdentityRole>()
            .AddEntityFrameworkStores<AccountManagementDbContext>();

        services.AddSingleton<IEmailSender<IdentityUser>, IdentityEmailTestSender>();

        return services;
    }
}