using System;
using System.Security.Claims;
using System.Collections.Generic;
using System.Text;
using API.Entities;
using API.Interfaces;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;

namespace API.Services
{
    public class TokenService : ITokenService
    {
        private readonly SymmetricSecurityKey _key;
        public TokenService(IConfiguration config)
        {
            _key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(config["TokenKey"]));
        }
        public string CreateToken(AppUser user)
        {
            // add claim
            var claims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.NameId, user.UserName)
            };

            //create credentials
            var creds = new SigningCredentials(_key, SecurityAlgorithms.HmacSha512Signature);

            //describe how token will look
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims),
                Expires = DateTime.Now.AddDays(7),
                SigningCredentials = creds
            };

            //token hanlder
            var tokenHandler = new JwtSecurityTokenHandler();

            //create the token
            var token = tokenHandler.CreateToken(tokenDescriptor);

            //return the written token
            return tokenHandler.WriteToken(token);
        }
    }
}