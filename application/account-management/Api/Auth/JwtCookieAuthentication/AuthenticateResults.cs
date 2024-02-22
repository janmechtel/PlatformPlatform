using Microsoft.AspNetCore.Authentication;

namespace PlatformPlatform.AccountManagement.Api.Auth.JwtCookieAuthentication;

public static class AuthenticateResults
{
    internal static readonly AuthenticateResult FailedMissingCookies =
        AuthenticateResult.Fail("Missing authentication cookies");

    internal static readonly AuthenticateResult FailedInvalidAccessToken =
        AuthenticateResult.Fail("Invalid access token");

    internal static readonly AuthenticateResult FailedInvalidRefreshToken =
        AuthenticateResult.Fail("Invalid refresh token");

    internal static readonly Func<AuthenticationProperties, AuthenticateResult> FailedExpiredAccessToken = properties =>
        AuthenticateResult.Fail("Access token expired", properties);
}