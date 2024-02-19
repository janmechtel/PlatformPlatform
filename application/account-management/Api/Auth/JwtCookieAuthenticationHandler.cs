using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace PlatformPlatform.AccountManagement.Api.Auth;

// CookieAuthenticationHandler
public class JwtCookieAuthenticationHandler : SignInAuthenticationHandler<JwtCookieAuthAuthenticationOptions>
{
    private static readonly SymmetricSecurityKey
        SecurityKey = new(Encoding.UTF8.GetBytes(GenerateSecret())); // Read from environment variable

    public JwtCookieAuthenticationHandler(
        IOptionsMonitor<JwtCookieAuthAuthenticationOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder
    ) : base(options, logger, encoder)
    {
    }

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        if (!Request.Cookies.ContainsKey(Options.AccessTokenName) ||
            !Request.Cookies.ContainsKey(Options.RefreshTokenName))
        {
            return AuthenticateResult.Fail("Missing authentication cookies");
        }

        var issuer = Request.Host.Value;
        var audience = Request.Host.Value;

        Jwt.Validate(Request.Cookies[Options.AccessTokenName]!, issuer, audience, SecurityKey,
            out var validAccessToken);
        if (validAccessToken is null)
        {
            Jwt.Validate(Request.Cookies[Options.RefreshTokenName]!, issuer, audience, SecurityKey,
                out var validRefreshToken);

            validAccessToken = await RefreshTokens(validRefreshToken, Response);
            if (validAccessToken is null)
            {
                return AuthenticateResult.Fail("Failed to refresh access token");
            }
        }

        var name = validAccessToken.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Name)?.Value ?? "";
        var email = validAccessToken.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Email)?.Value ?? "";
        var role = validAccessToken.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Role)?.Value ?? "member";

        var claims = new[]
        {
            new Claim(ClaimTypes.Name, name),
            new Claim(ClaimTypes.Email, email),
            new Claim(ClaimTypes.Role, role)
        };
        var principal = new ClaimsPrincipal(new ClaimsIdentity(claims, "Tokens"));
        var ticket = new AuthenticationTicket(principal, Scheme.Name);
        return AuthenticateResult.Success(ticket);
    }

    protected override async Task HandleSignOutAsync(AuthenticationProperties? properties)
    {
        Response.Cookies.Delete(Options.AccessTokenName);
        Response.Cookies.Delete(Options.RefreshTokenName);
    }

    protected override async Task HandleSignInAsync(ClaimsPrincipal user, AuthenticationProperties? properties)
    {
        var cookieOptions = new CookieOptions
        {
            HttpOnly = true,
            Secure = false,
            SameSite = SameSiteMode.Lax
            // SameSite = SameSiteMode.Strict
        };

        var accessToken = Jwt.Create(Request.Host.Value, Request.Host.Value, Options.AccessTokenExpireTimeSpan,
            Options.NotBefore, SecurityKey, new Dictionary<string, string>
            {
                { "sub", user.Identity?.Name ?? "" },
                { "email", user.FindFirstValue(ClaimTypes.Email) ?? ""},
                { "role", user.FindFirstValue(ClaimTypes.Role) ?? "" }
            });
        Response.Cookies.Append(Options.AccessTokenName, accessToken, cookieOptions);
        
        var refreshToken = Jwt.Create(Request.Host.Value, Request.Host.Value, Options.RefreshTokenExpireTimeSpan,
            Options.NotBefore, SecurityKey,
            new Dictionary<string, string>
            {
                { "id", $"client_{Guid.NewGuid().ToString()}" }, // Read client id or create new
                { "rotating_token", DateTime.Now.Ticks.ToString() }
            });
        Response.Cookies.Append(Options.RefreshTokenName, refreshToken, cookieOptions);
    }

    private async Task<JwtSecurityToken?> RefreshTokens(
        JwtSecurityToken validRefreshToken,
        HttpResponse response
    )
    {
        Logger.LogInformation("Refreshing access token");
        return null;
    }

    private static string GenerateSecret()
    {
        var key = new byte[32];
        RandomNumberGenerator.Create().GetBytes(key);
        return Convert.ToBase64String(key);
    }
}

public class JwtCookieAuthAuthenticationOptions : AuthenticationSchemeOptions
{
    public const string DefaultScheme = "JwtCookieAuthScheme";

    private CookieBuilder _cookieBuilder = new RequestPathBaseCookieBuilder
    {
        SameSite = SameSiteMode.Lax,
        HttpOnly = true,
        SecurePolicy = CookieSecurePolicy.SameAsRequest,
        IsEssential = true
    };

    public JwtCookieAuthAuthenticationOptions()
    {
        NotBefore = TimeSpan.FromSeconds(-30);
        AccessTokenExpireTimeSpan = TimeSpan.FromMinutes(10);
        RefreshTokenExpireTimeSpan = TimeSpan.FromDays(30);
    }

    public string AccessTokenName { get; set; } = "X-Access-Token";

    public string RefreshTokenName { get; set; } = "X-Refresh-Token";

    public string IdentifierName { get; set; } = "X-Username";

    public TimeSpan NotBefore { get; set; }

    public TimeSpan RefreshTokenExpireTimeSpan { get; set; }

    public TimeSpan AccessTokenExpireTimeSpan { get; set; }
}