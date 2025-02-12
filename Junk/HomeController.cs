using BookwormsOnline.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Authentication;

namespace BookwormsOnline.Controllers
{
    public class HomeController : Controller
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly IDataProtector _protector;

        public HomeController(UserManager<ApplicationUser> userManager, IDataProtectionProvider dataProtectionProvider)
        {
            _userManager = userManager;
            _protector = dataProtectionProvider.CreateProtector("CreditCardProtector");
        }

        public async Task<IActionResult> Index()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user != null)
            {
                // Validate session id to detect multiple concurrent logins.
                var sessionId = HttpContext.Session.GetString("CurrentSessionId");
                if (user.CurrentSessionId != sessionId)
                {
                    await HttpContext.SignOutAsync();
                    return RedirectToAction("Login", "Account");
                }

                // Decrypt credit card for display.
                string decryptedCreditCard = "";
                try
                {
                    if (!string.IsNullOrEmpty(user.EncryptedCreditCard))
                    {
                        decryptedCreditCard = _protector.Unprotect(user.EncryptedCreditCard);
                    }
                }
                catch
                {
                    decryptedCreditCard = "Error decrypting";
                }

                var model = new HomeViewModel
                {
                    FirstName = user.FirstName,
                    LastName = user.LastName,
                    Email = user.Email,
                    MobileNo = user.MobileNo,
                    BillingAddress = user.BillingAddress,
                    ShippingAddress = user.ShippingAddress,
                    CreditCardNumber = decryptedCreditCard,
                    PhotoPath = user.PhotoPath
                };
                return View("AuthenticatedIndex", model);
            }
            // If user is not authenticated, return the public landing page.
            return View("PublicIndex");
        }

        public IActionResult Privacy()
        {
            return View();
        }

        public IActionResult Error()
        {
            return View();
        }
    }

    public class HomeViewModel
    {
        public string? FirstName { get; set; }
        public string? LastName { get; set; }
        public string? Email { get; set; }
        public string? MobileNo { get; set; }
        public string? BillingAddress { get; set; }
        public string? ShippingAddress { get; set; }
        public string? CreditCardNumber { get; set; }
        public string? PhotoPath { get; set; }
    }
}
