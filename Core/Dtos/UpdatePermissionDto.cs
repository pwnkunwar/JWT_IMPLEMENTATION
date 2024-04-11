using System.ComponentModel.DataAnnotations;

namespace JWT.Core.Dtos
{
    public class UpdatePermissionDto
    {
        [Required(ErrorMessage = "Username should be required")]
        public string? UserName { get; set; }
    }
}