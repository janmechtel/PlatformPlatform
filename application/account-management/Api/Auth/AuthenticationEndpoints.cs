using System.Web;
using Microsoft.AspNetCore.Identity;
using PlatformPlatform.AccountManagement.Api.Auth.JwtCookieAuthentication;
using IdentityUser = PlatformPlatform.AccountManagement.Infrastructure.Identity.IdentityUser;

namespace PlatformPlatform.AccountManagement.Api.Auth;

public static class AuthenticationEndpoints
{
    private const string RoutesPrefix = "/api/auth";

    public static void MapRegistrationEndpoints(this IEndpointRouteBuilder routes)
    {
        var group = routes.MapGroup(RoutesPrefix);

        group.MapPost("/register", async (
            RegisterCommand command,
            HttpContext context,
            UserManager<IdentityUser> userManager,
            IEmailSender<IdentityUser> emailSender
        ) =>
        {
            var user = new IdentityUser
            {
                TenantId = new TenantId(command.TenantId),
                UserName = command.Email,
                Email = command.Email,
                UserRole = UserRole.TenantUser
            };

            var result = await userManager.CreateAsync(user, command.Password);
            if (!result.Succeeded) return Results.Problem(result.ToString(), statusCode: 400);

            await SendConfirmationEmail(user, context.Request, userManager, emailSender);
            return Results.Ok();
        });

        group.MapPost("/verify-email", async (string code, UserManager<IdentityUser> userManager) =>
        {
            var user = await userManager.FindByEmailAsync(code);
            if (user == null) return Results.NotFound();

            var result = await userManager.ConfirmEmailAsync(user, code);
            return result.Succeeded ? Results.Ok() : Results.Problem(result.ToString(), statusCode: 400);
        });

        group.MapGet("/confirm-email", async (string email, string code, UserManager<IdentityUser> userManager) =>
        {
            var user = await userManager.FindByEmailAsync(email);
            if (user is null) return Results.Unauthorized();

            var result = await userManager.ConfirmEmailAsync(user, code);
            return result.Succeeded ? Results.Ok("Thank you for confirming your email.") : Results.Unauthorized();
        });

        group.MapPost("/resend-confirmation-email", async (
            ResendConfirmationEmailCommand command,
            HttpContext context,
            UserManager<IdentityUser> userManager,
            IEmailSender<IdentityUser> emailSender
        ) =>
        {
            var user = await userManager.FindByEmailAsync(command.Email);
            if (user is null) return Results.Unauthorized();

            await SendConfirmationEmail(user, context.Request, userManager, emailSender);
            return Results.Ok();
        });
    }

    public static void MapAuthenticationEndpoints(this IEndpointRouteBuilder routes)
    {
        var group = routes.MapGroup(RoutesPrefix);

        group.MapPost("/login", async (LoginCommand command, SignInManager<IdentityUser> signInManager) =>
        {
            signInManager.AuthenticationScheme = JwtCookieAuthenticationOptions.DefaultScheme;
            var result = await signInManager.PasswordSignInAsync(command.Email, command.Password, false, true);
            return result.Succeeded ? Results.Ok() : Results.Unauthorized();
        });

        group.MapPost("/logout", async (SignInManager<IdentityUser> signInManager) =>
        {
            signInManager.AuthenticationScheme = JwtCookieAuthenticationOptions.DefaultScheme;
            await signInManager.SignOutAsync();
            return Results.Ok();
        });
    }

    public static void MapPasswordEndpoints(this IEndpointRouteBuilder routes)
    {
        var group = routes.MapGroup(RoutesPrefix);

        group.MapPost("/forgot-password", async (
            ForgotPasswordCommand command,
            UserManager<IdentityUser> userManager,
            IEmailSender<IdentityUser> emailSender
        ) =>
        {
            var user = await userManager.FindByEmailAsync(command.Email);
            if (user is null) return Results.Unauthorized();

            await SendResetPasswordMail(user, userManager, emailSender);
            return Results.Ok();
        });

        group.MapPost("/reset-password", async (ResetPasswordCommand command, UserManager<IdentityUser> userManager) =>
        {
            var user = await userManager.FindByEmailAsync(command.Email);
            if (user is null) return Results.Unauthorized();

            var result = await userManager.ResetPasswordAsync(user, command.Code, command.Password);
            return result.Succeeded ? Results.Ok() : Results.Unauthorized();
        });

        group.MapPost("/change-password", async (
            ChangePasswordCommand command,
            UserManager<IdentityUser> userManager
        ) =>
        {
            var user = await userManager.FindByEmailAsync(command.Email);
            if (user is null) return Results.Unauthorized();

            var result = await userManager.ChangePasswordAsync(user, command.CurrentPassword, command.NewPassword);
            return result.Succeeded ? Results.Ok() : Results.Unauthorized();
        });
    }

    private static async Task SendConfirmationEmail(
        IdentityUser user,
        HttpRequest request,
        UserManager<IdentityUser> userManager,
        IEmailSender<IdentityUser> emailSender
    )
    {
        var urlEncodedCode = HttpUtility.UrlEncode(await userManager.GenerateEmailConfirmationTokenAsync(user));
        var urlEncodedEmail = HttpUtility.UrlEncode(user.Email);
        var confirmUrlBuilder = new UriBuilder
        {
            Scheme = request.Scheme,
            Host = request.Host.Host,
            Path = "/api/auth/confirm-email",
            Query = $"email={urlEncodedEmail}&code={urlEncodedCode}"
        };
        if (request.Host.Port.HasValue) confirmUrlBuilder.Port = request.Host.Port.Value;

        await emailSender.SendConfirmationLinkAsync(user, user.Email!, confirmUrlBuilder.ToString());
    }

    private static async Task SendResetPasswordMail(
        IdentityUser user,
        UserManager<IdentityUser> userManager,
        IEmailSender<IdentityUser> emailSender
    )
    {
        var passwordResetToken = await userManager.GeneratePasswordResetTokenAsync(user);
        await emailSender.SendPasswordResetCodeAsync(user, user.Email!, passwordResetToken);
    }
}

[UsedImplicitly]
public record RegisterCommand(string TenantId, string Email, string Password);

[UsedImplicitly]
public record LoginCommand(string Email, string Password);

[UsedImplicitly]
public record ResendConfirmationEmailCommand(string Email);

[UsedImplicitly]
public record ForgotPasswordCommand(string Email);

[UsedImplicitly]
public record ResetPasswordCommand(string Email, string Password, string Code);

[UsedImplicitly]
public record ChangePasswordCommand(string Email, string CurrentPassword, string NewPassword);