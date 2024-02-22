using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;

namespace PlatformPlatform.AccountManagement.Api.Auth.JwtCookieAuthentication.Events;

public class JwtCookieValidatePrincipalContext : PrincipalContext<JwtCookieAuthenticationOptions>
{
    public JwtCookieValidatePrincipalContext(
        HttpContext context,
        AuthenticationScheme scheme,
        JwtCookieAuthenticationOptions options,
        AuthenticationTicket ticket
    ) : base(context, scheme, options, ticket?.Properties)
    {
        ArgumentNullException.ThrowIfNull(ticket);
        Principal = ticket.Principal;
    }
    
    public bool ShouldRenew { get; set; }
    
    public void ReplacePrincipal(ClaimsPrincipal principal) => Principal = principal;
    
    public void RejectPrincipal() => Principal = null;
}