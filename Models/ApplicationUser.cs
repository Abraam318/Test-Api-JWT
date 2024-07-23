using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;

namespace Test_Api_JWT.Models
{
    public class ApplicationUser : IdentityUser
    {
        [Required]
        public string FirstName {get; set;}
        [Required]
        public string LastName {get; set;}
    }
}