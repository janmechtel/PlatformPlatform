using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace PlatformPlatform.AccountManagement.Api.Auth.JwtCookieAuthentication;

// CookieExtensions
public static class JwtCookieAuthenticationExtensions
{
    /// <summary>
    ///     JWT Cookie Authentication using a HTTP cookie persisted in the client to perform authentication.
    /// </summary>
    /// <param name="builder"></param>
    /// <param name="configureOptions"></param>
    /// <returns></returns>
    public static AuthenticationBuilder AddJwtCookieAuthentication(
        this AuthenticationBuilder builder,
        Action<JwtCookieAuthenticationOptions> configureOptions
    )
    {
        return builder.AddJwtCookieAuthentication(JwtCookieAuthenticationOptions.DefaultScheme, configureOptions);
    }

    /// <summary>
    ///     JWT Cookie Authentication using a HTTP cookie persisted in the client to perform authentication.
    /// </summary>
    /// <param name="builder"></param>
    /// <param name="authenticationScheme"></param>
    /// <param name="configureOptions"></param>
    /// <returns></returns>
    public static AuthenticationBuilder AddJwtCookieAuthentication(
        this AuthenticationBuilder builder,
        string authenticationScheme,
        Action<JwtCookieAuthenticationOptions> configureOptions
    )
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(authenticationScheme);
        ArgumentNullException.ThrowIfNull(configureOptions);
        
        builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<IConfigureOptions<JwtCookieAuthenticationOptions>, JwtCookieConfigureOptions>());
        // builder.Services.AddOptions<JwtCookieAuthenticationOptions>(authenticationScheme);
        return builder.AddScheme<JwtCookieAuthenticationOptions, JwtCookieAuthenticationHandler>(authenticationScheme, configureOptions);
    }
}