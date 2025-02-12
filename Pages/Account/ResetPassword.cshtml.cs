using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using BookwormsOnline.Models;
using Microsoft.AspNetCore.Identity;
using BookwormsOnline.Data;
using BookwormsOnline.Services;
using System.ComponentModel.DataAnnotations;

namespace BookwormsOnline.Pages
{
    public class ResetPasswordModel : PageModel
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly ApplicationDbContext _context;
        private readonly IAuditLogger _auditLogger;

        public ResetPasswordModel(UserManager<ApplicationUser> userManager, ApplicationDbContext context, IAuditLogger auditLogger)
        {
            _userManager = userManager;
            _context = context;
            _auditLogger = auditLogger;
        }

        [BindProperty]
        public InputModel Input { get; set; } = new InputModel();

        public class InputModel
        {
            [Required]
            public string Token { get; set; } = string.Empty;

            [Required]
            [EmailAddress]
            public string Email { get; set; } = string.Empty;

            [Required]
            [DataType(DataType.Password)]
            [Display(Name = "New Password")]
            [RegularExpression(@"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).{12,}$", ErrorMessage = "Password must be at least 12 characters and include upper and lower case letters, a number, and a special character.")]
            public string Password { get; set; } = string.Empty;

            [Required]
            [DataType(DataType.Password)]
            [Display(Name = "Confirm New Password")]
            [Compare("Password", ErrorMessage = "Passwords do not match.")]
            public string ConfirmPassword { get; set; } = string.Empty;
        }

        public void OnGet(string token, string email)
        {
            Input = new InputModel { Token = token, Email = email };
        }

        public async Task<IActionResult> OnPostAsync()
        {
            if (!ModelState.IsValid)
            {
                return Page();
            }
            var user = await _userManager.FindByEmailAsync(Input.Email);
            if (user == null)
            {
                return RedirectToPage("/Account/ResetPasswordConfirmation");
            }
            var result = await _userManager.ResetPasswordAsync(user, Input.Token, Input.Password);
            if (result.Succeeded)
            {
                // Update password history.
                var passwordHistory = new PasswordHistory
                {
                    UserId = user.Id,
                    PasswordHash = user.PasswordHash,
                    ChangedDate = DateTime.UtcNow
                };
                _context.PasswordHistories.Add(passwordHistory);
                await _context.SaveChangesAsync();

                user.LastPasswordChangedDate = DateTime.UtcNow;
                await _userManager.UpdateAsync(user);

                await _auditLogger.LogAsync(user.Id, "Password Reset");
                return RedirectToPage("/Account/ResetPasswordConfirmation");
            }
            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }
            return Page();
        }
    }
}
