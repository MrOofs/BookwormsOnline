using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using BookwormsOnline.Models;
using Microsoft.AspNetCore.Identity;

namespace BookwormsOnline.Pages
{
    public class EnableTwoFactorModel : PageModel
    {
        private readonly UserManager<ApplicationUser> _userManager;

        public EnableTwoFactorModel(UserManager<ApplicationUser> userManager)
        {
            _userManager = userManager;
        }

        public bool IsEnabled { get; set; }

        public async Task<IActionResult> OnGetAsync()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return RedirectToPage("/Login");
            }
            IsEnabled = user.TwoFactorEnabled;
            return Page();
        }

        public async Task<IActionResult> OnPostAsync()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return RedirectToPage("/Login");
            }
            var result = await _userManager.SetTwoFactorEnabledAsync(user, true);
            if (result.Succeeded)
            {
                return RedirectToPage("/EnableTwoFactor");
            }
            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }
            return Page();
        }
    }
}
