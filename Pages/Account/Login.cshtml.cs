using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using BookwormsOnline.Models;
using Microsoft.AspNetCore.Identity;
using BookwormsOnline.Services;
using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Http;

namespace BookwormsOnline.Pages
{
    public class LoginModel : PageModel
    {
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly IAuditLogger _auditLogger;

        public LoginModel(SignInManager<ApplicationUser> signInManager, UserManager<ApplicationUser> userManager, IAuditLogger auditLogger)
        {
            _signInManager = signInManager;
            _userManager = userManager;
            _auditLogger = auditLogger;
        }

        [BindProperty]
        public InputModel Input { get; set; } = new InputModel();

        public string? ReturnUrl { get; set; }

        public class InputModel
        {
            [Required]
            [EmailAddress]
            public string Email { get; set; } = string.Empty;

            [Required]
            [DataType(DataType.Password)]
            public string Password { get; set; } = string.Empty;

            [Display(Name = "Remember Me")]
            public bool RememberMe { get; set; }
        }

        public void OnGet(string? returnUrl = null)
        {
            ReturnUrl = returnUrl;
        }

        public async Task<IActionResult> OnPostAsync(string? returnUrl = null)
        {
            returnUrl ??= Url.Content("~/");
            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByEmailAsync(Input.Email);
                if (user != null)
                {
                    if (await _userManager.IsLockedOutAsync(user))
                    {
                        ModelState.AddModelError(string.Empty, "Account locked out. Please try again later.");
                        return Page();
                    }
                }
                var result = await _signInManager.PasswordSignInAsync(Input.Email, Input.Password, Input.RememberMe, lockoutOnFailure: true);

                if (result.RequiresTwoFactor)
                {
                    // If the account requires 2FA, store the user id temporarily and redirect to the 2FA page.
                    TempData["2FAUserId"] = user?.Id;
                    return RedirectToPage("/TwoFactorAuthentication");
                }
                else if (result.Succeeded)
                {
                    // Update session id for multiple login detection.
                    user = await _userManager.FindByEmailAsync(Input.Email);
                    if (user != null)
                    {
                        user.CurrentSessionId = Guid.NewGuid().ToString();
                        await _userManager.UpdateAsync(user);
                        HttpContext.Session.SetString("CurrentSessionId", user.CurrentSessionId);
                        await _auditLogger.LogAsync(user.Id, "User Logged In");
                    }
                    return Redirect("/Home/Index");
                }
                if (result.IsLockedOut)
                {
                    ModelState.AddModelError(string.Empty, "Account locked out due to multiple failed login attempts.");
                    return Page();
                }
                else
                {
                    ModelState.AddModelError(string.Empty, "Invalid login attempt.");
                    return Page();
                }
            }
            return Page();
        }
    }
}
