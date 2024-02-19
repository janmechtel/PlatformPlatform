using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;

namespace PlatformPlatform.AccountManagement.Api.Auth;

public static class Jwt
{
    private static readonly string EncryptionAlgorithm = SecurityAlgorithms.HmacSha256;
    private static readonly JwtSecurityTokenHandler JwtSecurityTokenHandler = new();

    public static string Create(
        string issuer,
        string audience,
        TimeSpan lifetime,
        TimeSpan notBefore,
        SymmetricSecurityKey securityKey,
        IReadOnlyDictionary<string, string> payloadContents
    )
    {
        var signingCredentials = new SigningCredentials(securityKey, EncryptionAlgorithm);
        var payloadClaims = payloadContents.Select(c => new Claim(c.Key, c.Value));
        var payload = new JwtPayload(issuer, audience, payloadClaims, DateTime.UtcNow.Add(notBefore),
            DateTime.UtcNow.Add(lifetime), DateTime.UtcNow);
        return JwtSecurityTokenHandler.WriteToken(new JwtSecurityToken(new JwtHeader(signingCredentials), payload));
    }

    public static bool Validate(
        string token,
        string issuer,
        string audience,
        SymmetricSecurityKey securityKey,
        out JwtSecurityToken? jwt
    )
    {
        var validationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = issuer,
            ValidateAudience = true,
            ValidAudience = audience,
            ValidateIssuerSigningKey = true,
            IssuerSigningKeys = new List<SecurityKey>
            {
                securityKey
            },
            ValidateLifetime = true
        };

        try
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            tokenHandler.ValidateToken(token, validationParameters, out var validatedToken);
            jwt = (JwtSecurityToken)validatedToken;

            return true;
        }
        catch (SecurityTokenValidationException)
        {
            // Log the reason why the token is not valid
            jwt = null;
            return false;
        }
    }
}