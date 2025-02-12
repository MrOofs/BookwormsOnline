using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.Identity;
using BookwormsOnline.Models;
using BookwormsOnline.Services;

namespace BookwormsOnline.Pages
{
    public class LogoutModel : PageModel
    {
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly IAuditLogger _auditLogger;

        public LogoutModel(SignInManager<ApplicationUser> signInManager, IAuditLogger auditLogger)
        {
            _signInManager = signInManager;
            _auditLogger = auditLogger;
        }

        public void OnGet()
        {
        }

        public async Task<IActionResult> OnPostAsync()
        {
            var user = await _signInManager.UserManager.GetUserAsync(User);
            if (user != null)
            {
                await _auditLogger.LogAsync(user.Id, "User Logged Out");
            }
            await _signInManager.SignOutAsync();
            HttpContext.Session.Clear();
            return RedirectToPage("/Account/Login");
        }
    }
}
