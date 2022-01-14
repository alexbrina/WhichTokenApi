using Microsoft.AspNetCore.Http;
using Microsoft.IdentityModel.Tokens;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Linq;

namespace WhichTokenApi
{
    public static class Jwt
    {
        public static string GenerateToken(string audience)
        {
            var mySecret = "asdv234234^&%&^%&^hjsdfb2%%%";
            var mySecurityKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(mySecret));

            var tokenHandler = new JwtSecurityTokenHandler();
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new Claim[]
                {
                    new Claim(ClaimTypes.NameIdentifier, ""),
                }),
                Expires = DateTime.UtcNow.AddDays(7),
                Issuer = "WhichTokenApi",
                Audience = audience,
                SigningCredentials = new SigningCredentials(mySecurityKey,
                    SecurityAlgorithms.HmacSha256Signature)
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }

        public static bool ValidateToken(HttpRequest request, string audience)
        {
            if (!request.Headers.TryGetValue("Authorization", out var authorization))
            {
                return false;
            }

            if (!authorization.Any())
            {
                return false;
            }

            var bearer = authorization.FirstOrDefault(i => 
                    i.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase));

            var token = bearer?["Bearer ".Length..].Trim();

            if (string.IsNullOrWhiteSpace(token))
            {
                return false;
            }

            try
            {
                var mySecret = "asdv234234^&%&^%&^hjsdfb2%%%";
                var mySecurityKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(mySecret));

                var tokenHandler = new JwtSecurityTokenHandler();
                var tokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    ValidateIssuer = true,
                    ValidateAudience = true,
                    ValidIssuer = "WhichTokenApi",
                    ValidAudience = audience,
                    IssuerSigningKey = mySecurityKey
                };

                tokenHandler.ValidateToken(token,
                    tokenValidationParameters,
                    out SecurityToken validatedToken);

                return true;
            }
            catch
            {
                return false;
            }
        }
    }
}
