using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace Test_Api_JWT.Models
{
    public class TokenRequestModel
    {
        [Required]
        public string Email {get; set;} = String.Empty;
        [Required]
        public string Password {get; set;} = string.Empty;
    }
}