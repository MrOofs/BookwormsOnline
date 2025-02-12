using BookwormsOnline.Models;
using BookwormsOnline.Data;
using BookwormsOnline.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.DataProtection;
using System.Text.RegularExpressions;
using System.Net.Http.Json;

namespace BookwormsOnline.Controllers
{
    public class AccountController : Controller
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly IDataProtector _protector;
        private readonly IConfiguration _configuration;
        private readonly IHttpClientFactory _httpClientFactory;
        private readonly IAuditLogger _auditLogger;
        private readonly ApplicationDbContext _context;

        public AccountController(UserManager<ApplicationUser> userManager,
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
        }

        // GET: /Account/Register
        [HttpGet]
        public IActionResult Register()
        {
            return View();
        }

        // POST: /Account/Register
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Register(RegisterViewModel model)
        {
            // Validate reCAPTCHA.
            var recaptchaResponse = model.RecaptchaToken;
            if (!await VerifyReCaptchaAsync(recaptchaResponse))
            {
                ModelState.AddModelError("", "reCAPTCHA validation failed.");
                return View(model);
            }

            if (ModelState.IsValid)
            {
                // Check for duplicate email.
                var existingUser = await _userManager.FindByEmailAsync(model.Email);
                if (existingUser != null)
                {
                    ModelState.AddModelError("", "Email already exists.");
                    return View(model);
                }

                // Process photo upload: only .JPG is allowed.
                string photoPath = "";
                if (model.Photo != null && model.Photo.Length > 0)
                {
                    var extension = Path.GetExtension(model.Photo.FileName);
                    if (extension.ToLower() != ".jpg")
                    {
                        ModelState.AddModelError("", "Only .JPG files are allowed for photo.");
                        return View(model);
                    }
                    // Save photo to wwwroot/images.
                    var fileName = Guid.NewGuid().ToString() + ".jpg";
                    var filePath = Path.Combine(Directory.GetCurrentDirectory(), "wwwroot", "images", fileName);
                    using (var stream = new FileStream(filePath, FileMode.Create))
                    {
                        await model.Photo.CopyToAsync(stream);
                    }
                    photoPath = "/images/" + fileName;
                }

                // Encrypt credit card number.
                var encryptedCreditCard = _protector.Protect(model.CreditCardNo);

                var user = new ApplicationUser
                {
                    UserName = model.Email,
                    Email = model.Email,
                    FirstName = model.FirstName,
                    LastName = model.LastName,
                    MobileNo = model.MobileNo,
                    BillingAddress = model.BillingAddress,
                    ShippingAddress = model.ShippingAddress,
                    EncryptedCreditCard = encryptedCreditCard,
                    PhotoPath = photoPath,
                    LastPasswordChangedDate = DateTime.UtcNow
                };

                var result = await _userManager.CreateAsync(user, model.Password);
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

                    // Sign in the user.
                    await _signInManager.SignInAsync(user, isPersistent: false);

                    // Set a new session id.
                    user.CurrentSessionId = Guid.NewGuid().ToString();
                    await _userManager.UpdateAsync(user);
                    HttpContext.Session.SetString("CurrentSessionId", user.CurrentSessionId);

                    return RedirectToAction("Index", "Home");
                }
                else
                {
                    foreach (var error in result.Errors)
                        ModelState.AddModelError("", error.Description);
                }
            }
            return View(model);
        }

        // GET: /Account/Login
        [HttpGet]
        public IActionResult Login()
        {
            return View();
        }

        // POST: /Account/Login
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LoginViewModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByEmailAsync(model.Email);
                if (user != null)
                {
                    if (await _userManager.IsLockedOutAsync(user))
                    {
                        ModelState.AddModelError("", "Account locked out. Please try again later.");
                        return View(model);
                    }

                    var result = await _signInManager.PasswordSignInAsync(model.Email, model.Password, model.RememberMe, lockoutOnFailure: true);
                    if (result.Succeeded)
                    {
                        // Update session id for multiple login detection.
                        user.CurrentSessionId = Guid.NewGuid().ToString();
                        await _userManager.UpdateAsync(user);
                        HttpContext.Session.SetString("CurrentSessionId", user.CurrentSessionId);

                        await _auditLogger.LogAsync(user.Id, "User Logged In");

                        return RedirectToAction("Index", "Home");
                    }
                    else if (result.IsLockedOut)
                    {
                        ModelState.AddModelError("", "Account locked out due to multiple failed login attempts.");
                    }
                    else
                    {
                        ModelState.AddModelError("", "Invalid login attempt.");
                    }
                }
                else
                {
                    ModelState.AddModelError("", "Invalid login attempt.");
                }
            }
            return View(model);
        }

        // POST: /Account/Logout
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Logout()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user != null)
            {
                await _auditLogger.LogAsync(user.Id, "User Logged Out");
            }
            await _signInManager.SignOutAsync();
            HttpContext.Session.Clear();
            return RedirectToAction("Login", "Account");
        }

        // GET: /Account/ChangePassword
        [HttpGet]
        public IActionResult ChangePassword()
        {
            return View();
        }

        // POST: /Account/ChangePassword
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ChangePassword(ChangePasswordViewModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.GetUserAsync(User);
                if (user == null)
                {
                    return RedirectToAction("Login");
                }

                // Check password reuse: ensure the new password was not used in the last 2 changes.
                var histories = _context.PasswordHistories
                                .Where(ph => ph.UserId == user.Id)
                                .OrderByDescending(ph => ph.ChangedDate)
                                .Take(2)
                                .ToList();
                foreach (var history in histories)
                {
                    if (_userManager.PasswordHasher.VerifyHashedPassword(user, history.PasswordHash, model.NewPassword) == PasswordVerificationResult.Success)
                    {
                        ModelState.AddModelError("", "You cannot reuse your recent passwords.");
                        return View(model);
                    }
                }

                // Check minimum password age (e.g. cannot change within 5 minutes).
                if (user.LastPasswordChangedDate.HasValue && (DateTime.UtcNow - user.LastPasswordChangedDate.Value).TotalMinutes < 5)
                {
                    ModelState.AddModelError("", "You cannot change password within 5 minutes of your last password change.");
                    return View(model);
                }

                var result = await _userManager.ChangePasswordAsync(user, model.OldPassword, model.NewPassword);
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
                    return RedirectToAction("Index", "Home");
                }
                else
                {
                    foreach (var error in result.Errors)
                    {
                        ModelState.AddModelError("", error.Description);
                    }
                }
            }
            return View(model);
        }

        // GET: /Account/ForgotPassword
        [HttpGet]
        public IActionResult ForgotPassword()
        {
            return View();
        }

        // POST: /Account/ForgotPassword
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ForgotPassword(ForgotPasswordViewModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByEmailAsync(model.Email);
                if (user == null)
                {
                    // Do not reveal that the user does not exist.
                    return RedirectToAction("ForgotPasswordConfirmation");
                }

                var token = await _userManager.GeneratePasswordResetTokenAsync(user);
                var resetLink = Url.Action("ResetPassword", "Account", new { token = token, email = user.Email }, Request.Scheme);

                // In a production app, send the link via email/SMS.
                TempData["ResetLink"] = resetLink;

                await _auditLogger.LogAsync(user.Id, "Password Reset Requested");

                return RedirectToAction("ForgotPasswordConfirmation");
            }
            return View(model);
        }

        // GET: /Account/ForgotPasswordConfirmation
        [HttpGet]
        public IActionResult ForgotPasswordConfirmation()
        {
            return View();
        }

        // GET: /Account/ResetPassword
        [HttpGet]
        public IActionResult ResetPassword(string token, string email)
        {
            var model = new ResetPasswordViewModel { Token = token, Email = email };
            return View(model);
        }

        // POST: /Account/ResetPassword
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ResetPassword(ResetPasswordViewModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByEmailAsync(model.Email);
                if (user == null)
                {
                    return RedirectToAction("ResetPasswordConfirmation");
                }
                var result = await _userManager.ResetPasswordAsync(user, model.Token, model.Password);
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

                    return RedirectToAction("ResetPasswordConfirmation");
                }
                foreach (var error in result.Errors)
                {
                    ModelState.AddModelError("", error.Description);
                }
            }
            return View(model);
        }

        // GET: /Account/ResetPasswordConfirmation
        [HttpGet]
        public IActionResult ResetPasswordConfirmation()
        {
            return View();
        }

        // Verify reCAPTCHA v3 by calling Google's API.
        private async Task<bool> VerifyReCaptchaAsync(string token)
        {
            var secretKey = _configuration["GoogleReCaptcha:SecretKey"];
            var client = _httpClientFactory.CreateClient();
            var response = await client.PostAsJsonAsync($"https://www.google.com/recaptcha/api/siteverify?secret={secretKey}&response={token}", new { });
            var googleResponse = await response.Content.ReadFromJsonAsync<GoogleReCaptchaResponse>();
            return googleResponse != null && googleResponse.Success && googleResponse.Score >= 0.5;
        }
    }

    // Class to map Google's reCAPTCHA response.
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
