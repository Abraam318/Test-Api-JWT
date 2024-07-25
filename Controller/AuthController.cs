using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Test_Api_JWT.Models;
using Test_Api_JWT.Services;

namespace Test_Api_JWT.Controller
{
    [Route("[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IAuthService _authService;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly IHttpContextAccessor _httpContextAccessor;

        public AuthController(IAuthService authService, UserManager<ApplicationUser> userManager, IHttpContextAccessor httpContextAccessor)
        {
            _authService = authService;
            _userManager = userManager;
            _httpContextAccessor = httpContextAccessor;
        }

        [HttpPost("register")]
        public async Task<IActionResult> RegisterAsync([FromBody] RegisterModel model)
        {
            if (!ModelState.IsValid) return BadRequest(ModelState);
            return Ok(await _authService.RegisterAsync(model));
        }

        [Authorize]
        [HttpPost("token")]
        public async Task<IActionResult> GetTokenAsync([FromBody] TokenRequestModel model)
        {
            if (!ModelState.IsValid) return BadRequest(ModelState);

            // Extract the current user's ID from the token
            var User = _httpContextAccessor.HttpContext?.User;

            if(User == null || model.Email != User.FindFirstValue(ClaimTypes.Email))
            {
                return BadRequest(error:"Cannot access");
            }
            return Ok(await _authService.GetTokenAsync(model));
        }

        [Authorize(Roles = "Admin")]
        [HttpPost("addrole")]
        public async Task<IActionResult> AddRoleAsync([FromBody] AddRoleModel model)
        {
            if (!ModelState.IsValid) return BadRequest(ModelState);

            var result = await _authService.AddRoleAsync(model);

            if (!string.IsNullOrEmpty(result))
                return BadRequest(result);

            return Ok(model);
        }
    }
}
