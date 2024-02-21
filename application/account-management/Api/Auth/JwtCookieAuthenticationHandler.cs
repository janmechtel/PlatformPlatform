using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace PlatformPlatform.AccountManagement.Api.Auth;

public class JwtCookieAuthenticationHandler(
    IOptionsMonitor<JwtCookieAuthenticationSchemeOptions> options,
    ILoggerFactory logger,
    UrlEncoder encoder
)
    : SignInAuthenticationHandler<JwtCookieAuthenticationSchemeOptions>(options, logger, encoder)
{
    private const string EncryptionAlgorithm = SecurityAlgorithms.HmacSha256;

    private static readonly SymmetricSecurityKey SecurityKey
        = new(Encoding.UTF8.GetBytes(GenerateSecret())); // Read from environment variable

    private static readonly JwtSecurityTokenHandler JwtSecurityTokenHandler = new();

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        Request.Cookies.TryGetValue(Options.AccessTokenName, out var accessToken);
        Request.Cookies.TryGetValue(Options.RefreshTokenName, out var refreshToken);
        if (accessToken is null || refreshToken is null)
        {
            return AuthenticateResult.Fail("Missing authentication cookies.");
        }

        var issuer = Request.Host.Value;
        var audience = Request.Host.Value;

        var validAccessToken = ValidateToken(accessToken, issuer, audience, SecurityKey);
        if (validAccessToken is null)
        {
            var validRefreshToken = ValidateToken(refreshToken, issuer, audience, SecurityKey);

            if (validRefreshToken is null)
            {
                return AuthenticateResult.Fail("Failed validate refresh token.");
            }

            validAccessToken = await RefreshTokens(validRefreshToken, Response);
            if (validAccessToken is null)
            {
                return AuthenticateResult.Fail("Failed to refresh access token.");
            }
        }

        var claims = new[]
        {
            new Claim(ClaimTypes.Name, validAccessToken.Claims.Single(c => c.Type == ClaimTypes.Name).Value),
            new Claim(ClaimTypes.Email, validAccessToken.Claims.Single(c => c.Type == ClaimTypes.Email).Value),
            new Claim(ClaimTypes.Role, validAccessToken.Claims.Single(c => c.Type == ClaimTypes.Role).Value)
        };

        var principal = new ClaimsPrincipal(new ClaimsIdentity(claims, "Tokens"));
        var ticket = new AuthenticationTicket(principal, Scheme.Name);

        return AuthenticateResult.Success(ticket);
    }

    protected override Task HandleSignOutAsync(AuthenticationProperties? properties)
    {
        Response.Cookies.Delete(Options.AccessTokenName);
        Response.Cookies.Delete(Options.RefreshTokenName);
        return Task.CompletedTask;
    }

    protected override Task HandleSignInAsync(ClaimsPrincipal user, AuthenticationProperties? properties)
    {
        var cookieOptions = new CookieOptions { HttpOnly = true, Secure = true, SameSite = SameSiteMode.Lax };

        var accessTokenClaims = new Claim[]
        {
            new(ClaimTypes.Name, user.Identity?.Name!),
            new(ClaimTypes.Email, user.FindFirstValue(ClaimTypes.Email)!),
            new(ClaimTypes.Role, user.FindFirstValue(ClaimTypes.Role) ?? "member")
        };

        var accessToken = CreateToken(Request.Host.Value, Request.Host.Value, Options.AccessTokenExpireTimeSpan,
            Options.NotBefore, SecurityKey, accessTokenClaims);
        Response.Cookies.Append(Options.AccessTokenName, accessToken, cookieOptions);

        var refreshTokenClaims = new Claim[]
        {
            new("id", $"client_{Guid.NewGuid().ToString()}"),
            new("rotating_token", DateTime.Now.Ticks.ToString())
        };

        var refreshToken = CreateToken(Request.Host.Value, Request.Host.Value, Options.RefreshTokenExpireTimeSpan,
            Options.NotBefore, SecurityKey, refreshTokenClaims);
        Response.Cookies.Append(Options.RefreshTokenName, refreshToken, cookieOptions);
        return Task.CompletedTask;
    }

    private Task<JwtSecurityToken?> RefreshTokens(JwtSecurityToken validRefreshToken, HttpResponse response)
    {
        Logger.LogInformation("Refreshing access token, {id}, {response}", validRefreshToken.Id, response);
        return Task.FromResult<JwtSecurityToken?>(null);
    }

    private string CreateToken(
        string issuer,
        string audience,
        TimeSpan lifetime,
        TimeSpan notBefore,
        SymmetricSecurityKey securityKey,
        Claim[] claims
    )
    {
        var signingCredentials = new SigningCredentials(securityKey, EncryptionAlgorithm);
        var payload = new JwtPayload(issuer, audience, claims, DateTime.UtcNow.Add(notBefore),
            DateTime.UtcNow.Add(lifetime), DateTime.UtcNow);
        return JwtSecurityTokenHandler.WriteToken(new JwtSecurityToken(new JwtHeader(signingCredentials), payload));
    }

    private JwtSecurityToken? ValidateToken(
        string token,
        string issuer,
        string audience,
        SymmetricSecurityKey securityKey
    )
    {
        var validationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = issuer,
            ValidateAudience = true,
            ValidAudience = audience,
            ValidateIssuerSigningKey = true,
            IssuerSigningKeys = new List<SecurityKey> { securityKey },
            ValidateLifetime = true
        };

        try
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            tokenHandler.ValidateToken(token, validationParameters, out var validatedToken);
            return (JwtSecurityToken)validatedToken;
        }
        catch (SecurityTokenValidationException)
        {
            // Log the reason why the token is not valid
            return null;
        }
    }

    private static string GenerateSecret()
    {
        var key = new byte[32];
        RandomNumberGenerator.Create().GetBytes(key);
        return Convert.ToBase64String(key);
    }
}