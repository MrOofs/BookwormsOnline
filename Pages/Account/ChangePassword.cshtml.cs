using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using BookwormsOnline.Models;
using Microsoft.AspNetCore.Identity;
using BookwormsOnline.Data;
using BookwormsOnline.Services;
using System.ComponentModel.DataAnnotations;

namespace BookwormsOnline.Pages
{
    public class ChangePasswordModel : PageModel
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly ApplicationDbContext _context;
        private readonly IAuditLogger _auditLogger;

        public ChangePasswordModel(UserManager<ApplicationUser> userManager,
                                   SignInManager<ApplicationUser> signInManager,
                                   ApplicationDbContext context,
                                   IAuditLogger auditLogger)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _context = context;
            _auditLogger = auditLogger;
        }

        [BindProperty]
        public InputModel Input { get; set; } = new InputModel();

        public class InputModel
        {
            [Required]
            [DataType(DataType.Password)]
            [Display(Name = "Old Password")]
            public string OldPassword { get; set; } = string.Empty;

            [Required]
            [DataType(DataType.Password)]
            [Display(Name = "New Password")]
            [RegularExpression(@"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).{12,}$", ErrorMessage = "Password must be at least 12 characters and include upper and lower case letters, a number, and a special character.")]
            public string NewPassword { get; set; } = string.Empty;

            [Required]
            [DataType(DataType.Password)]
            [Display(Name = "Confirm New Password")]
            [Compare("NewPassword", ErrorMessage = "Passwords do not match.")]
            public string ConfirmNewPassword { get; set; } = string.Empty;
        }

        public async Task<IActionResult> OnPostAsync()
        {
            if (!ModelState.IsValid)
            {
                return Page();
            }
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return RedirectToPage("/Login");
            }
            // Check for password reuse in last 2 changes.
            var histories = _context.PasswordHistories
                               .Where(ph => ph.UserId == user.Id)
                               .OrderByDescending(ph => ph.ChangedDate)
                               .Take(2)
                               .ToList();
            foreach (var history in histories)
            {
                if (_userManager.PasswordHasher.VerifyHashedPassword(user, history.PasswordHash, Input.NewPassword) == PasswordVerificationResult.Success)
                {
                    ModelState.AddModelError(string.Empty, "You cannot reuse your recent passwords.");
                    return Page();
                }
            }
            // Check minimum password age: cannot change within 5 minutes.
            if (user.LastPasswordChangedDate.HasValue && (DateTime.UtcNow - user.LastPasswordChangedDate.Value).TotalMinutes < 5)
            {
                ModelState.AddModelError(string.Empty, "You cannot change password within 5 minutes of your last change.");
                return Page();
            }
            var result = await _userManager.ChangePasswordAsync(user, Input.OldPassword, Input.NewPassword);
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

                await _auditLogger.LogAsync(user.Id, "Password Changed");
                return RedirectToPage("/Index");
            }
            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }
            return Page();
        }
    }
}
