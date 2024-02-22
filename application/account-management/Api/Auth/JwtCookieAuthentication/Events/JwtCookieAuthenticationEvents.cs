namespace PlatformPlatform.AccountManagement.Api.Auth.JwtCookieAuthentication.Events;

public class JwtCookieAuthenticationEvents
{
    /// <summary>
    /// Invoked on signing in.
    /// </summary>
    public Func<JwtCookieSigningInContext, Task> OnSigningIn { get; set; } = context => Task.CompletedTask;

    /// <summary>
    /// Invoked after sign in has completed.
    /// </summary>
    public Func<JwtCookieSignedInContext, Task> OnSignedIn { get; set; } = context => Task.CompletedTask;

    /// <summary>
    /// Invoked on signing out.
    /// </summary>
    public Func<JwtCookieSigningOutContext, Task> OnSigningOut { get; set; } = context => Task.CompletedTask;
    
    /// <summary>
    /// Invoked after sign in has completed.
    /// </summary>
    /// <param name="context">The <see cref="JwtCookieSignedInContext"/>.</param>
    public virtual Task SignedIn(JwtCookieSignedInContext context) => OnSignedIn(context);

    /// <summary>
    /// Invoked on sign out.
    /// </summary>
    /// <param name="context">The <see cref="JwtCookieSigningOutContext"/>.</param>
    public virtual Task SigningOut(JwtCookieSigningOutContext context) => OnSigningOut(context);

    /// <summary>
    /// Event to be called when a refresh token is being used to refresh the access token
    /// </summary>
    /// <param name="eventContext"></param>
    /// <returns></returns>
    public virtual Task CheckRefreshToken(JwtCookieRefreshTokenContext eventContext) => Task.CompletedTask;
}