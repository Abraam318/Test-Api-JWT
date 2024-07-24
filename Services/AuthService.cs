using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Test_Api_JWT.Helpers;
using Test_Api_JWT.Models;

namespace Test_Api_JWT.Services
{
    public class AuthService : IAuthService
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly JWT _jwt;
        private readonly RoleManager<IdentityRole> _roleManager;

        public AuthService(UserManager<ApplicationUser> userManager, IOptions<JWT> jwt, RoleManager<IdentityRole> roleManager)
        {
            _userManager = userManager;
            _jwt = jwt.Value;
            _roleManager = roleManager;
        }

        public async Task<string> AddRoleAsync(AddRoleModel model)
        {
            var user = await _userManager.FindByIdAsync(model.UserId);
            if(user is null || !await _roleManager.RoleExistsAsync(model.Role))
                return "Invalid User Id or Role";
            if(await _userManager.IsInRoleAsync(user,model.Role))
            {
                return "User Already assigned to this role";
            }
            var result = await _userManager.AddToRoleAsync(user, model.Role);

            return result.Succeeded? string.Empty : "Something went wrong";
        }
        public async Task<AuthModel> GetTokenAsync(TokenRequestModel model)
        {
            var AuthModel = new AuthModel();
            var user = await _userManager.FindByEmailAsync(model.Email);
            if(user is null || !await _userManager.CheckPasswordAsync(user,model.Password)){
                AuthModel.Message = "Incorrect Email or Password";
                return AuthModel;
            }
            var jwtSecurityToken = await CreateJwtToken(user);
            var roleList = await _userManager.GetRolesAsync(user) ;

            AuthModel.IsAuthenticated = true;
            AuthModel.Email = user.Email;
            AuthModel.ExpiresOn = jwtSecurityToken.ValidTo;
            AuthModel.Roles = roleList.ToList();
            AuthModel.Token = new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken);
            AuthModel.Username = user.UserName;

            return AuthModel;
        }

        public async Task<AuthModel> RegisterAsync(RegisterModel model)
        {
            if (model.Email == null || model.Username == null || model.Password == null)
            {
                return new AuthModel { Message = "Invalid input data!" };
            }

            if(await _userManager.FindByEmailAsync(model.Email) is not null)
            {
                return new AuthModel { Message = "Email is already registered!" };
            }

            if(await _userManager.FindByNameAsync(model.Username) is not null)
            {
                return new AuthModel { Message = "Username is already registered!" };
            }

            var user = new ApplicationUser
            {
                UserName = model.Username,
                FirstName = model.FirstName,
                LastName = model.LastName,
                Email = model.Email
            };

            var result = await _userManager.CreateAsync(user, model.Password);

            if (!result.Succeeded)
            {
                var errors = string.Join(", ", result.Errors.Select(e => e.Description));
                return new AuthModel { Message = errors };
            }

            await _userManager.AddToRoleAsync(user, "User");

            var jwtSecurityToken = await CreateJwtToken(user);
            return new AuthModel
            {
                Email = user.Email,
                ExpiresOn = jwtSecurityToken.ValidTo,
                IsAuthenticated = true,
                Roles = new List<string> { "User" },
                Token = new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken),
                Username = user.UserName
            };
        }

        private async Task<JwtSecurityToken> CreateJwtToken(ApplicationUser user)
        {
            var userClaims = await _userManager.GetClaimsAsync(user);
            var roles = await _userManager.GetRolesAsync(user);
            var roleClaims = new List<Claim>();

            foreach (var role in roles)
                roleClaims.Add(new Claim("roles", role));

            var claims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.UserName ?? throw new ArgumentNullException(nameof(user.UserName))),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(JwtRegisteredClaimNames.Email, user.Email ?? throw new ArgumentNullException(nameof(user.Email))),
                new Claim("uid", user.Id ?? throw new ArgumentNullException(nameof(user.Id)))
            }
            .Union(userClaims)
            .Union(roleClaims);

            var symmetricSecurityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwt.Key));
            var signingCredentials = new SigningCredentials(symmetricSecurityKey, SecurityAlgorithms.HmacSha256);

            var jwtSecurityToken = new JwtSecurityToken(
                issuer: _jwt.Issuer,
                audience: _jwt.Audience,
                claims: claims,
                expires: DateTime.Now.AddHours(_jwt.Duration),
                signingCredentials: signingCredentials);

            return jwtSecurityToken;
        }
    }
}
