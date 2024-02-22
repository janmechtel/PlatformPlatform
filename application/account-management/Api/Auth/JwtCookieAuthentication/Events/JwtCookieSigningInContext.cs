using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;

namespace PlatformPlatform.AccountManagement.Api.Auth.JwtCookieAuthentication.Events;

public sealed class JwtCookieSigningInContext : PrincipalContext<JwtCookieAuthenticationOptions>
{
    public JwtCookieSigningInContext(
        HttpContext context,
        AuthenticationScheme scheme,
        ClaimsPrincipal principal,
        AuthenticationProperties? properties,
        JwtCookieAuthenticationOptions options
    ) : base(context, scheme, options, properties)
    {
        JwtCookieAuthenticationOptions = options;
        Principal = principal;
    }
    
    /// <summary>
    /// The options for creating the outgoing JWT cookie.
    /// </summary>
    public JwtCookieAuthenticationOptions JwtCookieAuthenticationOptions { get; set; }
}