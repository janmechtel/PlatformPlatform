using System.Net.Mail;

namespace PlatformPlatform.SharedKernel.InfrastructureCore.Services;

public sealed class SmtpEmailSender
{
    private readonly SmtpClient _emailSender = new("localhost", 1025);

    public Task SendEmailAsync(string email, string subject, string htmlMessage)
    {
        return _emailSender.SendMailAsync(new MailMessage("test@localhost", email, subject, htmlMessage)
        {
            IsBodyHtml = true
        });
    }
}