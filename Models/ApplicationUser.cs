using Microsoft.AspNetCore.Identity;

namespace BookwormsOnline.Models
{
    public class ApplicationUser : IdentityUser
    {
        public string? FirstName { get; set; }
        public string? LastName { get; set; }

        // Encrypted credit card number.
        public string? EncryptedCreditCard { get; set; }

        public string? MobileNo { get; set; }
        public string? BillingAddress { get; set; }

        // Shipping address can include special characters.
        public string? ShippingAddress { get; set; }

        public string? PhotoPath { get; set; }

        // To track the current session (for multiple‐login detection).
        public string? CurrentSessionId { get; set; }

        // For enforcing password age requirements.
        public DateTime? LastPasswordChangedDate { get; set; }
    }
}
