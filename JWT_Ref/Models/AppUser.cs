using Microsoft.AspNetCore.Identity;
using System.ComponentModel.DataAnnotations;

namespace JWT_Ref.Models
{
    public class AppUser : IdentityUser
    {
        [MaxLength(150)]
        public string FullName { get; set; }

        [MaxLength(1000)]
        public string? RefreshToken { get; set; }
        public DateTime RefreshTokenExpiryTime { get; set; }
    }
}
