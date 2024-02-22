namespace PlatformPlatform.AccountManagement.Api.Auth.JwtCookieAuthentication;

public class RefreshTokenDetails(IDictionary<string, string?>? properties)
{
    public string Id { get; set; } = properties != null && properties.TryGetValue("id", out var value)
        ? value!
        : Guid.NewGuid().ToString();

    public string? UserId { get; set; } =
        properties != null && properties.TryGetValue("sub", out var value) ? value! : null;

    public string RotatingToken { get; set; } =
        properties != null && properties.TryGetValue("rotating_token", out var value)
            ? value!
            : DateTime.Now.Ticks.ToString();

    public Dictionary<string, string?> ToDictionary()
    {
        return new Dictionary<string, string?>
        {
            { "id", Id },
            { "sub", UserId },
            { "rotating_token", RotatingToken }
        };
    }
}