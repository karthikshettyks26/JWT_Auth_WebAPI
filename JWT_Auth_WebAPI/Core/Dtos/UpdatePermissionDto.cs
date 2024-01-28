using System.ComponentModel.DataAnnotations;

namespace JWT_Auth_WebAPI.Core.Dtos
{
    public class UpdatePermissionDto
    {
        [Required(ErrorMessage = "UserName is required")]
        public string UserName { get; set; }

    }
}
