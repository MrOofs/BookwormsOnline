using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using BookwormsOnline.Models;
using Microsoft.AspNetCore.Identity;
using BookwormsOnline.Services;
using System.ComponentModel.DataAnnotations;

namespace BookwormsOnline.Pages
{
    public class TwoFactorAuthenticationModel : PageModel
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly IEmailSender _emailSender;
        private readonly IAuditLogger _auditLogger;

        public TwoFactorAuthenticationModel(UserManager<ApplicationUser> userManager,
                                              SignInManager<ApplicationUser> signInManager,
                                              IEmailSender emailSender,
                                              IAuditLogger auditLogger)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _emailSender = emailSender;
            _auditLogger = auditLogger;
        }

        [BindProperty]
        public InputModel Input { get; set; } = new InputModel();

        public string Email { get; set; } = string.Empty;

        public class InputModel
        {
            [Required]
            [Display(Name = "Verification Code")]
            public string Code { get; set; } = string.Empty;
        }

        public async Task<IActionResult> OnGetAsync()
        {
            // Retrieve the user id that was stored during login when 2FA was required.
            if (TempData["2FAUserId"] is string userId)
            {
                var user = await _userManager.FindByIdAsync(userId);
                if (user == null)
                {
                    return RedirectToPage("/Login");
                }
                Email = user.Email;
                // Generate the 2FA token using the email provider.
                var token = await _userManager.GenerateTwoFactorTokenAsync(user, "Email");
                // Send the token via email.
                string subject = "Your Two-Factor Authentication Code";
                string body = $"<p>Your two-factor authentication code is: <strong>{token}</strong></p>";
                await _emailSender.SendEmailAsync(user.Email, subject, body);
                await _auditLogger.LogAsync(user.Id, "2FA Code Sent via Email");
                // Preserve the user id for the POST.
                TempData["2FAUserId"] = userId;
                return Page();
            }
            return RedirectToPage("/Login");
        }

        public async Task<IActionResult> OnPostAsync()
        {
            if (!ModelState.IsValid)
            {
                return Page();
            }
            if (TempData["2FAUserId"] is string userId)
            {
                var user = await _userManager.FindByIdAsync(userId);
                if (user == null)
                {
                    return RedirectToPage("/Login");
                }
                // Verify the token provided by the user.
                var result = await _userManager.VerifyTwoFactorTokenAsync(user, "Email", Input.Code);
                if (result)
                {
                    await _auditLogger.LogAsync(user.Id, "2FA Successful");
                    // Sign in the user.
                    await _signInManager.SignInAsync(user, isPersistent: false);
                    // Update the session for multiple-login detection.
                    user.CurrentSessionId = Guid.NewGuid().ToString();
                    await _userManager.UpdateAsync(user);
                    HttpContext.Session.SetString("CurrentSessionId", user.CurrentSessionId);
                    return RedirectToPage("/Index");
                }
                else
                {
                    ModelState.AddModelError(string.Empty, "Invalid verification code.");
                    TempData["2FAUserId"] = userId; // Preserve user id for retry.
                    return Page();
                }
            }
            return RedirectToPage("/Login");
        }
    }
}
