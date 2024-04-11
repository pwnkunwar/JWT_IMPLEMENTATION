using System.ComponentModel.DataAnnotations;
namespace JWT.Core.Dtos
{
    public class LoginDto
    {
        [Required(ErrorMessage = "Username is Required")]
        public string? UserName { get; set; }

        [Required(ErrorMessage = "Password is required")]
        public string? Passsword { get; set; }
    }

}