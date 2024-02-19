using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.IdentityModel.Tokens;

namespace PlatformPlatform.AccountManagement.Api.Auth;

public static class IdentityEndpoints
{
    private const string RoutesPrefix = "/api/auth";

    public static void MapIdentityEndpoints(this IEndpointRouteBuilder routes)
    {
        var emailSender = routes.ServiceProvider.GetRequiredService<IEmailSender<ApplicationUser>>();
        var group = routes.MapGroup(RoutesPrefix);

        group.MapPost("/register", async (
            HttpContext context,
            RegisterModel register,
            UserManager<ApplicationUser> userManager
        ) =>
        {
            var user = new ApplicationUser
            {
                UserName = register.Email,
                Email = register.Email,
                TenantId = "acme", // Create a tenant for the user...
                Role = "owner"
            };
            
            // await userStore.SetUserNameAsync(user, email, CancellationToken.None);
            // await emailStore.SetEmailAsync(user, email, CancellationToken.None);

            var result = await userManager.CreateAsync(user, register.Password);
            if (!result.Succeeded)
            {
                return CreateValidationProblem(result);
            }

            await SendConfirmationEmail(user, register.Email, userManager, context);

            return Results.Ok();
        });

        group.MapPost("/login", async (
            LoginModel login,
            HttpContext context,
            SignInManager<ApplicationUser> signInManager,
            UserManager<ApplicationUser> userManager
        ) =>
        {
            signInManager.AuthenticationScheme = JwtCookieAuthAuthenticationOptions.DefaultScheme;

            var result = await signInManager.PasswordSignInAsync(login.Email, login.Password, false, false);
            if (!result.Succeeded)
            {
                return Results.Unauthorized();
            }

            // The signInManager already produced the needed response in the form of cookies, so we don't need to do anything here.
            return Results.Empty;
        });

        group.MapPost("/logout", async (
            HttpContext context,
            SignInManager<ApplicationUser> signInManager
        ) =>
        {
            await signInManager.SignOutAsync();
            return Results.Ok();
        });

        // create endpoint for verifying the email using the code sent to the user's email
        group.MapPost("/verify-email", async (
            string code,
            UserManager<ApplicationUser> userManager
        ) =>
        {
            var user = await userManager.FindByEmailAsync(code);
            if (user == null)
            {
                return Results.NotFound();
            }

            var result = await userManager.ConfirmEmailAsync(user, code);
            if (result.Succeeded)
            {
                return Results.Ok();
            }

            return Results.Problem(result.ToString(), statusCode: 400);
        });

        group.MapGet("/confirmEmail", async (
            string email,
            string code,
            UserManager<ApplicationUser> userManager
        ) =>
        {
            if (await userManager.FindByEmailAsync(email) is not { } user)
            {
                return Results.Unauthorized();
            }

            try
            {
                code = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(code));
            }
            catch (FormatException)
            {
                return Results.Unauthorized();
            }

            var result = await userManager.ConfirmEmailAsync(user, code);
            if (!result.Succeeded)
            {
                return Results.Unauthorized();
            }

            return Results.Ok("Thank you for confirming your email.");
        });

        group.MapPost("/resendConfirmationEmail", async (
            HttpContext context,
            string email,
            UserManager<ApplicationUser> userManager
        ) =>
        {
            if (await userManager.FindByEmailAsync(email) is not { } user)
            {
                return Results.Unauthorized();
            }

            await SendConfirmationEmail(user, email, userManager, context);


            // send the code to the user's email
            return Results.Ok();
        });

        group.MapPost("/forgotPassword", async (
            string email,
            UserManager<ApplicationUser> userManager
        ) =>
        {
            if (await userManager.FindByEmailAsync(email) is not { } user)
            {
                return Results.Unauthorized();
            }

            var code = await userManager.GeneratePasswordResetTokenAsync(user);
            return Results.Ok(code);
        });

        group.MapPost("/resetPassword", async (
            string email,
            string code,
            string password,
            UserManager<ApplicationUser> userManager
        ) =>
        {
            if (await userManager.FindByEmailAsync(email) is not { } user)
            {
                return Results.Unauthorized();
            }

            var result = await userManager.ResetPasswordAsync(user, code, password);
            if (!result.Succeeded)
            {
                return Results.Unauthorized();
            }

            return Results.Ok();
        });

        group.MapPost("/changePassword", async (
            string email,
            string currentPassword,
            string newPassword,
            UserManager<ApplicationUser> userManager
        ) =>
        {
            if (await userManager.FindByEmailAsync(email) is not { } user)
            {
                return Results.Unauthorized();
            }

            var result = await userManager.ChangePasswordAsync(user, currentPassword, newPassword);
            if (!result.Succeeded)
            {
                return Results.Unauthorized();
            }

            return Results.Ok();
        });

        async Task SendConfirmationEmail(
            ApplicationUser user,
            string email,
            UserManager<ApplicationUser> userManager,
            HttpContext context
        )
        {
            var host = context.Request.Host.Value;
            var code = await userManager.GenerateEmailConfirmationTokenAsync(user);
            code = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(code));
            var confirmEmailUrl = $"https://{host}/api/auth/confirmEmail?email={email}&code={code}";
            await emailSender.SendConfirmationLinkAsync(user, email, HtmlEncoder.Default.Encode(confirmEmailUrl));
        }
    }


    private static ValidationProblem CreateValidationProblem(IdentityResult result)
    {
        // We expect a single error code and description in the normal case.
        // This could be golfed with GroupBy and ToDictionary, but perf! :P
        Debug.Assert(!result.Succeeded);
        var errorDictionary = new Dictionary<string, string[]>(1);

        foreach (var error in result.Errors)
        {
            string[] newDescriptions;

            if (errorDictionary.TryGetValue(error.Code, out var descriptions))
            {
                newDescriptions = new string[descriptions.Length + 1];
                Array.Copy(descriptions, newDescriptions, descriptions.Length);
                newDescriptions[descriptions.Length] = error.Description;
            }
            else
            {
                newDescriptions = [error.Description];
            }

            errorDictionary[error.Code] = newDescriptions;
        }

        return TypedResults.ValidationProblem(errorDictionary);
    }
}

[UsedImplicitly]
public class RegisterModel
{
    public required string Email { get; set; }

    public required string Password { get; set; }
}

[UsedImplicitly]
public class LoginModel
{
    public required string Email { get; set; }

    public required string Password { get; set; }

    public string? TwoFactorCode { get; set; }

    public string? TwoFactorRecoveryCode { get; set; }

    public bool RememberMe { get; set; }
}