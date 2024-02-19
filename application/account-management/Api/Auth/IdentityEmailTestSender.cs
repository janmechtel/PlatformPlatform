using System.Net.Mail;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;

namespace PlatformPlatform.AccountManagement.Api.Auth;

internal sealed class IdentityEmailTestSender : IEmailSender<ApplicationUser>
{
    private readonly IEmailSender _emailSender = new SmtpEmailSender("localhost", 1025);

    public Task SendConfirmationLinkAsync(ApplicationUser user, string email, string confirmationLink)
    {
        return _emailSender.SendEmailAsync(email, "Confirm your email",
            $"Please confirm your account by clicking this link: <a href='{confirmationLink}'>link</a>");
    }

    public Task SendPasswordResetLinkAsync(ApplicationUser user, string email, string resetLink)
    {
        return _emailSender.SendEmailAsync(email, "Reset your password",
            $"Please reset your password by clicking here: <a href='{resetLink}'>link</a>");
    }

    public Task SendPasswordResetCodeAsync(ApplicationUser user, string email, string resetCode)
    {
        return _emailSender.SendEmailAsync(email, "Reset your password",
            $"Please reset your password using the following code: {resetCode}");
    }
}

internal class SmtpEmailSender(string host, int port) : IEmailSender
{
    private readonly SmtpClient _emailSender = new(host, port);

    public Task SendEmailAsync(string email, string subject, string htmlMessage)
    {
        return _emailSender.SendMailAsync(new MailMessage("test@localhost", email, subject, htmlMessage)
        {
            IsBodyHtml = true
        });
    }
}