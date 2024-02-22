using Microsoft.AspNetCore.Authentication;

namespace PlatformPlatform.AccountManagement.Api.Auth.JwtCookieAuthentication.Events;

public sealed class JwtCookieRefreshTokenContext : PrincipalContext<JwtCookieAuthenticationOptions>
{
    public JwtCookieRefreshTokenContext(
        HttpContext context,
        AuthenticationScheme scheme,
        JwtCookieAuthenticationOptions options,
        AuthenticationTicket ticket,
        AuthenticationProperties properties
    ) : base(context, scheme, options, properties)
    {
        ArgumentNullException.ThrowIfNull(ticket);
        Principal = ticket.Principal;

        RefreshTokenDetails = new RefreshTokenDetails(properties.Items);

        var utcNow = DateTime.UtcNow;
        
        TicketExpired = utcNow > ticket.Properties.ExpiresUtc;
    }

    public bool TicketExpired { get; set; }
    
    public bool ShouldRenew { get; set; }
    
    public RefreshTokenDetails RefreshTokenDetails { get; }
}