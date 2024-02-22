using Microsoft.AspNetCore.Authentication;

namespace PlatformPlatform.AccountManagement.Api.Auth.JwtCookieAuthentication.Events;

public class JwtCookieSigningOutContext(
    HttpContext context,
    AuthenticationScheme scheme,
    JwtCookieAuthenticationOptions options,
    AuthenticationProperties? properties,
    CookieOptions cookieOptions
)
    : PropertiesContext<JwtCookieAuthenticationOptions>(context, scheme, options, properties)
{
    /// <summary>
    /// The options for creating the outgoing cookie.
    /// May be replace or altered during the SigningOut call.
    /// </summary>
    public CookieOptions CookieOptions { get; set; } = cookieOptions;
}