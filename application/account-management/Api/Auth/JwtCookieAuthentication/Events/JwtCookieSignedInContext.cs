using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;

namespace PlatformPlatform.AccountManagement.Api.Auth.JwtCookieAuthentication.Events;

public sealed class JwtCookieSignedInContext : PrincipalContext<JwtCookieAuthenticationOptions>
{
    public JwtCookieSignedInContext(
        HttpContext context,
        AuthenticationScheme scheme,
        ClaimsPrincipal principal,
        AuthenticationProperties? properties,
        JwtCookieAuthenticationOptions options
    ) : base(context, scheme, options, properties)
    {
        Principal = principal;
    }
}