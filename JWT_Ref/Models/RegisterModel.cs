using System.ComponentModel.DataAnnotations;

namespace JWT_Ref.Models
{
    public class RegisterModel
    {
        [Required(ErrorMessage = "User Full Name is required")]
        public string? FullName { get; set; }

        [Required(ErrorMessage = "User Name is required")]
        public string? Username { get; set; }

        [EmailAddress]
        [Required(ErrorMessage = "Email is required")]
        public string? Email { get; set; }

        [Required(ErrorMessage = "Password is required")]
        public string? Password { get; set; }
    }
}
