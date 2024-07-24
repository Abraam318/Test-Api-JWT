using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace Test_Api_JWT.Models
{
    public class AddRoleModel
    {
        [Required]
        public string UserId {get; set;} = string.Empty;
        [Required]
        public string Role {get; set;} = string.Empty;

    }
}