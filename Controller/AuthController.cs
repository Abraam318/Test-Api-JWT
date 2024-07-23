using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using NuGet.Protocol;
using Test_Api_JWT.Models;
using Test_Api_JWT.Services;

namespace Test_Api_JWT.Controller
{
    [Route("[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IAuthService _authService;

        public AuthController(IAuthService authService)
        {
            _authService = authService;
        }

        [HttpPost("register")]
        public async Task<IActionResult> RegisterAsync([FromBody] RegisterModel model)
        {
            return !ModelState.IsValid ? BadRequest(ModelState) : Ok(await _authService.RegisterAsync(model));
        }


        [HttpPost("token")]
        public async Task<IActionResult> GetTokenAsync([FromBody] TokenRequestModel model)
        {
            return !ModelState.IsValid ? BadRequest(ModelState) : Ok(await _authService.GetTokenAsync(model));
        }
    }
}
