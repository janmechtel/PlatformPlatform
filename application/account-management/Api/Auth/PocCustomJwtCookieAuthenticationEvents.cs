using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using PlatformPlatform.AccountManagement.Api.Auth.JwtCookieAuthentication.Events;
using IdentityUser = PlatformPlatform.AccountManagement.Infrastructure.Identity.IdentityUser;

namespace PlatformPlatform.AccountManagement.Api.Auth;

public class PocCustomJwtCookieAuthenticationEvents(UserManager<IdentityUser> userManager)
    : JwtCookieAuthenticationEvents
{
    public override async Task CheckRefreshToken(JwtCookieRefreshTokenContext eventContext)
    {
        if (eventContext.TicketExpired)
        {
            eventContext.ShouldRenew = false;
            return;
        }

        var user = await GetLatestUserClaims(eventContext.Properties);
        if (user is null)
        {
            eventContext.ShouldRenew = false;
            return;
        }

        eventContext.Principal = user;
        eventContext.ShouldRenew = true;
    }

    /// <summary>
    ///     Using the refresh token, get the latest user claims from the database
    ///     This method also makes sure to mark the refresh token as compromised if an old version is being used
    /// </summary>
    /// <param name="properties"></param>
    /// <returns>Latest User Claims or null</returns>
    private async Task<ClaimsPrincipal?> GetLatestUserClaims(AuthenticationProperties properties)
    {
        /*

        var refreshTokenDetails = new RefreshTokenDetails(properties.Items);
        if (refreshTokenDetails.UserId is null)
        {
            return null;
        }

        var user = await userManager.FindByIdAsync(refreshTokenDetails.UserId);
        if (user is null)
        {
            return null;
        }

        var activeRotationToken = user.ActiveRefreshTokens[refreshTokenDetails.Id];

        if (refreshTokenDetails.RotatingToken != activeRotationToken)
        {
            // Check if old version of the refresh token is being used - if so mark as compromised
            user.CompromisedRefreshTokens[refreshTokenDetails.Id] = refreshTokenDetails.RotatingToken;
            user.ActiveRefreshTokens.Remove(refreshTokenDetails.Id);
            await userManager.UpdateAsync(user);
            return null;
        }
        */

        // return user claims from data base to be used for issuing new tokens
        return null;
    }
}