using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using BookwormsOnline.Models;
using Microsoft.AspNetCore.Identity;
using BookwormsOnline.Services;
using System.ComponentModel.DataAnnotations;

namespace BookwormsOnline.Pages
{
    public class ForgotPasswordModel : PageModel
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly IAuditLogger _auditLogger;
        private readonly IEmailSender _emailSender;

        public ForgotPasswordModel(UserManager<ApplicationUser> userManager,
                                   IAuditLogger auditLogger,
                                   IEmailSender emailSender)
        {
            _userManager = userManager;
            _auditLogger = auditLogger;
            _emailSender = emailSender;
        }

        [BindProperty]
        public InputModel Input { get; set; } = new InputModel();

        public class InputModel
        {
            [Required]
            [EmailAddress]
            public string Email { get; set; } = string.Empty;
        }

        public void OnGet() { }

        public async Task<IActionResult> OnPostAsync()
        {
            if (!ModelState.IsValid)
            {
                return Page();
            }
            var user = await _userManager.FindByEmailAsync(Input.Email);
            if (user == null)
            {
                // For security, do not reveal that the user doesn't exist.
                return RedirectToPage("/Account/ForgotPasswordConfirmation");
            }
            var token = await _userManager.GeneratePasswordResetTokenAsync(user);
            var resetLink = Url.Page("/Account/ResetPassword", null, new { token = token, email = user.Email }, Request.Scheme);

            // Compose the email.
            string subject = "Reset Your Password - Bookworms Online";
            string body = $"<p>Hello,</p><p>Please reset your password by clicking <a href='{resetLink}'>here</a>.</p><p>If you did not request a password reset, please ignore this email.</p>";

            // Send the email via SMTP.
            await _emailSender.SendEmailAsync(user.Email, subject, body);

            await _auditLogger.LogAsync(user.Id, "Password Reset Requested via Email");

            // Optionally, you can also store the reset link in TempData for testing.
            TempData["ResetLink"] = resetLink;

            return RedirectToPage("/Account/ForgotPasswordConfirmation");
        }
    }
}
