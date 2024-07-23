using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.CodeAnalysis.Options;

namespace Test_Api_JWT.Helpers
{
    public class JWT
    {
        public string Key { get; set; } =null!;
        public string Issuer { get; set; } =null!;
        public string Audience { get; set; } =null!;
        public double Duration { get; set; }
        
    }
}