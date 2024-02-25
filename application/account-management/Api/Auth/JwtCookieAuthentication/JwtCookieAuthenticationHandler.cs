using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using PlatformPlatform.AccountManagement.Api.Auth.JwtCookieAuthentication.Events;

namespace PlatformPlatform.AccountManagement.Api.Auth.JwtCookieAuthentication;

// CookieAuthenticationHandler
public class JwtCookieAuthenticationHandler(
    IOptionsMonitor<JwtCookieAuthenticationOptions> options,
    ILoggerFactory logger,
    UrlEncoder encoder
)
    : SignInAuthenticationHandler<JwtCookieAuthenticationOptions>(options, logger, encoder)
{
    protected new JwtCookieAuthenticationEvents Events
    {
        get => (JwtCookieAuthenticationEvents)base.Events!;
        set => base.Events = value;
    }

    protected override Task<object> CreateEventsAsync()
    {
        return Task.FromResult<object>(new JwtCookieAuthenticationEvents());
    }

    /// <inheritdoc />
    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        Request.Cookies.TryGetValue(Options.AccessTokenName, out var accessToken);
        Request.Cookies.TryGetValue(Options.RefreshTokenName, out var refreshToken);
        if (accessToken is null || refreshToken is null)
        {
            return AuthenticateResults.FailedMissingCookies;
        }

        var tokenHandler = new JwtSecurityTokenHandler();

        try
        {
            var tokenValidationParameters = Options.TokenValidationParameters.Clone();

            var tokenValidationResult =
                await tokenHandler.ValidateTokenAsync(accessToken, tokenValidationParameters);

            if (tokenValidationResult.IsValid)
            {
                var user = new ClaimsPrincipal(tokenValidationResult.ClaimsIdentity);
                return AuthenticateResult.Success(new AuthenticationTicket(user, Scheme.Name));
            }
        }
        catch (SecurityTokenValidationException)
        {
            if (Options.RefreshTokenProtector.Unprotect(refreshToken, GetTlsTokenBinding()) is not
                { } refreshTokenTicket)
            {
                return AuthenticateResults.FailedInvalidRefreshToken;
            }

            var eventContext = new JwtCookieRefreshTokenContext(Context, Scheme, Options, refreshTokenTicket,
                refreshTokenTicket.Properties);

            await Events.CheckRefreshToken(eventContext);

            if (eventContext is { ShouldRenew: true, Principal: not null })
            {
                await HandleSignInAsync(eventContext.Principal, eventContext.Properties);
                return AuthenticateResult.Success(new AuthenticationTicket(eventContext.Principal, Scheme.Name));
            }

            return AuthenticateResults.FailedExpiredAccessToken(refreshTokenTicket.Properties);
        }

        return AuthenticateResults.FailedInvalidAccessToken;
    }

    /// <inheritdoc />
    protected override Task HandleSignInAsync(ClaimsPrincipal user, AuthenticationProperties? properties)
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        var jwtSigningCredentials = new SigningCredentials(Options.SigningSecurityKey, SecurityAlgorithms.HmacSha256);

        var utcNow = DateTime.UtcNow;
        var accessToken = CreateAccessToken(user, tokenHandler, utcNow, jwtSigningCredentials);
        var refreshTokenTicket = CreateRefreshTicket(user, utcNow, properties);
        var refreshToken = Options.RefreshTokenProtector.Protect(refreshTokenTicket, GetTlsTokenBinding());

        var securityCookieOptions = BuildCookieOptions();
        Response.Cookies.Append(Options.AccessTokenName, accessToken, securityCookieOptions);
        Response.Cookies.Append(Options.RefreshTokenName, refreshToken, securityCookieOptions);

        return Task.CompletedTask;
    }

    /// <inheritdoc />
    protected override async Task HandleSignOutAsync(AuthenticationProperties? properties)
    {
        var cookieOptions = BuildCookieOptions();
        await Events.SigningOut(new JwtCookieSigningOutContext(Context, Scheme, Options, properties, cookieOptions));
        Response.Cookies.Delete(Options.AccessTokenName);
        Response.Cookies.Delete(Options.RefreshTokenName);
    }

    private AuthenticationTicket CreateRefreshTicket(
        ClaimsPrincipal user,
        DateTime utcNow,
        AuthenticationProperties? properties
    )
    {
        var refreshTokenDetails = new RefreshTokenDetails(properties?.Items)
        {
            UserId = user.FindFirstValue(ClaimTypes.NameIdentifier)
        };
        var refreshProperties = new AuthenticationProperties(refreshTokenDetails.ToDictionary())
        {
            ExpiresUtc = utcNow.Add(Options.RefreshTokenExpireTimeSpan)
        };

        return new AuthenticationTicket(user, refreshProperties, $"{Scheme.Name};RefreshToken");
    }

    private string CreateAccessToken(
        ClaimsPrincipal user,
        JwtSecurityTokenHandler tokenHandler,
        DateTime utcNow,
        SigningCredentials signingCredentials
    )
    {
        var accessSecurityToken = tokenHandler.CreateToken(new SecurityTokenDescriptor
        {
            Subject = user.Identity as ClaimsIdentity,
            Audience = Options.TokenValidationParameters.ValidAudience,
            Issuer = Options.TokenValidationParameters.ValidIssuer,
            IssuedAt = utcNow,
            Expires = utcNow.Add(Options.AccessTokenExpireTimeSpan),
            NotBefore = utcNow.Add(Options.NotBeforeTimeSpan),
            SigningCredentials = signingCredentials
            // EncryptingCredentials = jwtEncryptingCredentials, // Add encryption
        });
        return tokenHandler.WriteToken(accessSecurityToken);
    }

    private CookieOptions BuildCookieOptions()
    {
        var cookieOptions = Options.Cookie.Build(Context);
        cookieOptions.Expires = null;
        return cookieOptions;
    }

    private string? GetTlsTokenBinding()
    {
        var binding = Context.Features.Get<ITlsTokenBindingFeature>()?.GetProvidedTokenBindingId();
        return binding == null ? null : Convert.ToBase64String(binding);
    }
}