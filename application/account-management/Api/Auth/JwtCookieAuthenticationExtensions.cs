using Microsoft.AspNetCore.Authentication;

namespace PlatformPlatform.AccountManagement.Api.Auth;

// CookieExtensions
public static class JwtCookieAuthenticationExtensions
{
    /// <summary>
    ///     JWT Cookie Authentication using a HTTP cookie persisted in the client to perform authentication.
    /// </summary>
    /// <param name="builder"></param>
    /// <returns></returns>
    public static AuthenticationBuilder AddJwtCookieAuthentication(this AuthenticationBuilder builder)
    {
        return builder.AddJwtCookieAuthentication(null!);
    }

    /// <summary>
    ///     JWT Cookie Authentication using a HTTP cookie persisted in the client to perform authentication.
    /// </summary>
    /// <param name="builder"></param>
    /// <param name="configureOptions"></param>
    /// <returns></returns>
    public static AuthenticationBuilder AddJwtCookieAuthentication(
        this AuthenticationBuilder builder,
        Action<JwtCookieAuthAuthenticationOptions> configureOptions
    )
    {
        return builder.AddJwtCookieAuthentication(null, configureOptions);
    }

    /// <summary>
    ///     JWT Cookie Authentication using a HTTP cookie persisted in the client to perform authentication.
    /// </summary>
    /// <param name="builder"></param>
    /// <param name="displayName"></param>
    /// <param name="configureOptions"></param>
    /// <returns></returns>
    public static AuthenticationBuilder AddJwtCookieAuthentication(
        this AuthenticationBuilder builder,
        string? displayName,
        Action<JwtCookieAuthAuthenticationOptions> configureOptions
    )
    {
//        builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<IPostConfigureOptions<CookieAuthenticationOptions>, PostConfigureCookieAuthenticationOptions>());
//        builder.Services.AddOptions<CookieAuthenticationOptions>(authenticationScheme).Validate(o => o.Cookie.Expiration == null, "Cookie.Expiration is ignored, use ExpireTimeSpan instead.");
//        return builder.AddScheme<CookieAuthenticationOptions, CookieAuthenticationHandler>(authenticationScheme, displayName, configureOptions);

        builder.Services.AddOptions<JwtCookieAuthAuthenticationOptions>(
            JwtCookieAuthAuthenticationOptions.DefaultScheme);
        return builder.AddScheme<JwtCookieAuthAuthenticationOptions, JwtCookieAuthenticationHandler>(
            JwtCookieAuthAuthenticationOptions.DefaultScheme, displayName,
            configureOptions);
    }
}