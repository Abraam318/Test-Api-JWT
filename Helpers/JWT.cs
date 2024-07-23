using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.CodeAnalysis.Options;

namespace Test_Api_JWT.Helpers
{
    public class JWT
    {
        public string key { get; set; }
        public string Issuer { get; set; }
        public string Audience { get; set; }
        public double Duration { get; set; }
        
    }
}