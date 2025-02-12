using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.Identity;
using BookwormsOnline.Models;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Authentication;
using System.Threading.Tasks;

namespace BookwormsOnline.Pages
{
    public class IndexModel : PageModel
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly IDataProtector _protector;

        public IndexModel(UserManager<ApplicationUser> userManager, IDataProtectionProvider dataProtectionProvider)
        {
            _userManager = userManager;
            _protector = dataProtectionProvider.CreateProtector("CreditCardProtector");
        }

        // Bound properties for authenticated user data.
        public bool IsAuthenticated { get; set; }
        public string? FirstName { get; set; }
        public string? LastName { get; set; }
        public string? Email { get; set; }
        public string? MobileNo { get; set; }
        public string? BillingAddress { get; set; }
        public string? ShippingAddress { get; set; }
        public string? CreditCardNumber { get; set; }
        public string? PhotoPath { get; set; }

        public async Task<IActionResult> OnGetAsync()
        {
            if (User.Identity != null && User.Identity.IsAuthenticated)
            {
                IsAuthenticated = true;
                var user = await _userManager.GetUserAsync(User);
                if (user != null)
                {
                    // Validate session: if the session ID does not match, force logout.
                    var sessionId = HttpContext.Session.GetString("CurrentSessionId");
                    if (user.CurrentSessionId != sessionId)
                    {
                        // Sign out the user.
                        await HttpContext.SignOutAsync();
                        // Clear the session.
                        HttpContext.Session.Clear();
                        // Delete the authentication cookie (adjust the cookie name if you use a custom one).
                        HttpContext.Response.Cookies.Delete(".AspNetCore.Identity.Application");
                        // Redirect to this same page; now the user will be anonymous.
                        return RedirectToPage("/Home/Index");
                    }

                    // Otherwise, load the user's data.
                    FirstName = user.FirstName;
                    LastName = user.LastName;
                    Email = user.Email;
                    MobileNo = user.MobileNo;
                    BillingAddress = user.BillingAddress;
                    ShippingAddress = user.ShippingAddress;
                    PhotoPath = user.PhotoPath;
                    try
                    {
                        if (!string.IsNullOrEmpty(user.EncryptedCreditCard))
                        {
                            CreditCardNumber = _protector.Unprotect(user.EncryptedCreditCard);
                        }
                    }
                    catch
                    {
                        CreditCardNumber = "Error decrypting";
                    }
                }
            }
            else
            {
                IsAuthenticated = false;
            }
            return Page();
        }
    }
}
