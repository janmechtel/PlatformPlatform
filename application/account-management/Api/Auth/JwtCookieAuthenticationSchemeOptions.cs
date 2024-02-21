using Microsoft.AspNetCore.Authentication;

namespace PlatformPlatform.AccountManagement.Api.Auth;

public class JwtCookieAuthenticationSchemeOptions : AuthenticationSchemeOptions
{
    public const string AuthenticationScheme = "JwtCookieAuthScheme";

    public string AccessTokenName => "X-Access-Token";

    public string RefreshTokenName => "X-Refresh-Token";

    public TimeSpan NotBefore { get; } = TimeSpan.FromSeconds(-30);

    public TimeSpan RefreshTokenExpireTimeSpan { get; } = TimeSpan.FromDays(30);

    public TimeSpan AccessTokenExpireTimeSpan { get; } = TimeSpan.FromMinutes(10);
}