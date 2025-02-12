using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using BookwormsOnline.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.DataProtection;
using BookwormsOnline.Data;
using BookwormsOnline.Services;
using System.ComponentModel.DataAnnotations;

namespace BookwormsOnline.Pages
{
    public class RegisterModel : PageModel
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly IDataProtector _protector;
        private readonly IConfiguration _configuration;
        private readonly IHttpClientFactory _httpClientFactory;
        private readonly IAuditLogger _auditLogger;
        private readonly ApplicationDbContext _context;

        public RegisterModel(UserManager<ApplicationUser> userManager,
                             SignInManager<ApplicationUser> signInManager,
                             IDataProtectionProvider dataProtectionProvider,
                             IConfiguration configuration,
                             IHttpClientFactory httpClientFactory,
                             IAuditLogger auditLogger,
                             ApplicationDbContext context)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _protector = dataProtectionProvider.CreateProtector("CreditCardProtector");
            _configuration = configuration;
            _httpClientFactory = httpClientFactory;
            _auditLogger = auditLogger;
            _context = context;
            SiteKey = _configuration["GoogleReCaptcha:SiteKey"];
        }

        [BindProperty]
        public InputModel Input { get; set; } = new InputModel();

        public string SiteKey { get; }

        public class InputModel
        {
            [Required]
            [Display(Name = "First Name")]
            public string FirstName { get; set; } = string.Empty;

            [Required]
            [Display(Name = "Last Name")]
            public string LastName { get; set; } = string.Empty;

            [Required]
            [Display(Name = "Credit Card Number")]

            [DataType(DataType.CreditCard)] 
            public string CreditCardNo { get; set; } = string.Empty;

            [Required]
            [Display(Name = "Mobile Number")]
            [RegularExpression(@"^\+?[1-9]\d{1,14}$", ErrorMessage = "Invalid mobile number.")]
            public string MobileNo { get; set; } = string.Empty;

            [Required]
            [Display(Name = "Billing Address")]
            public string BillingAddress { get; set; } = string.Empty;

            [Required]
            [Display(Name = "Shipping Address")]
            public string ShippingAddress { get; set; } = string.Empty;

            [Required]
            [EmailAddress]
            public string Email { get; set; } = string.Empty;

            [Required]
            [DataType(DataType.Password)]
            [Display(Name = "Password")]
            [RegularExpression(@"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).{12,}$", ErrorMessage = "Password must be at least 12 characters and include upper and lower case letters, a number, and a special character.")]
            public string Password { get; set; } = string.Empty;

            [Required]
            [DataType(DataType.Password)]
            [Display(Name = "Confirm Password")]
            [Compare("Password", ErrorMessage = "Passwords do not match.")]
            public string ConfirmPassword { get; set; } = string.Empty;

            [Display(Name = "Photo (.JPG only)")]
            public IFormFile? Photo { get; set; }

            // reCAPTCHA token.
            public string RecaptchaToken { get; set; } = string.Empty;
        }

        public async Task<IActionResult> OnPostAsync()
        {
            if (!await VerifyReCaptchaAsync(Input.RecaptchaToken))
            {
                ModelState.AddModelError(string.Empty, "reCAPTCHA validation failed.");
                return Page();
            }

            if (ModelState.IsValid)
            {
                // Check for duplicate email.
                var existingUser = await _userManager.FindByEmailAsync(Input.Email);
                if (existingUser != null)
                {
                    ModelState.AddModelError(string.Empty, "Email already exists.");
                    return Page();
                }

                // Process photo upload.
                string photoPath = "";
                if (Input.Photo != null && Input.Photo.Length > 0)
                {
                    var extension = Path.GetExtension(Input.Photo.FileName);
                    if (extension.ToLower() != ".jpg")
                    {
                        ModelState.AddModelError(string.Empty, "Only .JPG files are allowed for photo.");
                        return Page();
                    }
                    var fileName = Guid.NewGuid().ToString() + ".jpg";
                    var filePath = Path.Combine(Directory.GetCurrentDirectory(), "wwwroot", "images", fileName);
                    using (var stream = new FileStream(filePath, FileMode.Create))
                    {
                        await Input.Photo.CopyToAsync(stream);
                    }
                    photoPath = "/images/" + fileName;
                }

                // Encrypt the credit card number.
                var encryptedCreditCard = _protector.Protect(Input.CreditCardNo);

                var user = new ApplicationUser
                {
                    UserName = Input.Email,
                    Email = Input.Email,
                    FirstName = Input.FirstName,
                    LastName = Input.LastName,
                    MobileNo = Input.MobileNo,
                    BillingAddress = Input.BillingAddress,
                    ShippingAddress = Input.ShippingAddress,
                    EncryptedCreditCard = encryptedCreditCard,
                    PhotoPath = photoPath,
                    LastPasswordChangedDate = DateTime.UtcNow
                };

                var result = await _userManager.CreateAsync(user, Input.Password);
                if (result.Succeeded)
                {
                    // Save password history.
                    var passwordHistory = new PasswordHistory
                    {
                        UserId = user.Id,
                        PasswordHash = user.PasswordHash,
                        ChangedDate = DateTime.UtcNow
                    };
                    _context.PasswordHistories.Add(passwordHistory);
                    await _context.SaveChangesAsync();

                    await _auditLogger.LogAsync(user.Id, "User Registered");

                    await _signInManager.SignInAsync(user, isPersistent: false);

                    // Set a unique session ID.
                    user.CurrentSessionId = Guid.NewGuid().ToString();
                    await _userManager.UpdateAsync(user);
                    HttpContext.Session.SetString("CurrentSessionId", user.CurrentSessionId);

                    return RedirectToPage("/Home");
                }
                else
                {
                    foreach (var error in result.Errors)
                        ModelState.AddModelError(string.Empty, error.Description);
                }
            }

            return Page();
        }

        private async Task<bool> VerifyReCaptchaAsync(string token)
        {
            var secretKey = _configuration["GoogleReCaptcha:SecretKey"];
            var client = _httpClientFactory.CreateClient();
            var response = await client.PostAsync($"https://www.google.com/recaptcha/api/siteverify?secret={secretKey}&response={token}", null);
            var googleResponse = await response.Content.ReadFromJsonAsync<GoogleReCaptchaResponse>();
            return googleResponse != null && googleResponse.Success && googleResponse.Score >= 0.5;
        }

        public class GoogleReCaptchaResponse
        {
            public bool Success { get; set; }
            public double Score { get; set; }
            public string Action { get; set; }
            public DateTime Challenge_TS { get; set; }
            public string Hostname { get; set; }
            public List<string> ErrorCodes { get; set; }
        }
    }
}
