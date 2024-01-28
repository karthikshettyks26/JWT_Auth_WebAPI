using JWT_Auth_WebAPI.Core.Entities;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace JWT_Auth_WebAPI.Core.DbContext
{
    //<ApplicationUser> need to be added in IdentityDbContext<ApplicationUser> -> it s newly created class which implements IdentityUser
    public class ApplicationDbContext : IdentityDbContext<ApplicationUser>
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options) : base(options)
        {
            
        }
    }
}
