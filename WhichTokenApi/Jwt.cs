using Microsoft.AspNetCore.Http;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace WhichTokenApi
{
    public static class Jwt
    {
        public static string Secret { get; set; }
        public static string ECDsaCertificateFileName { get; set; }

        private static X509Certificate2 _certificate;
        private static X509Certificate2 Certificate
        {
            get
            {
                if (_certificate == null)
                {
                    var file = Path.Combine(AppContext.BaseDirectory, ECDsaCertificateFileName);
                    _certificate = new X509Certificate2(file, Secret);
                }

                return _certificate;
            }
        }

        public static string GenerateToken(string audience)
        {
            var mySecurityKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(Secret));

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

            var tokenHandler = new JwtSecurityTokenHandler();
            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }

        public static string GenerateECDsaToken(string audience)
        {
            var mySecurityKey = new ECDsaSecurityKey(Certificate.GetECDsaPrivateKey());

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new Claim[]
                {
                    new Claim(ClaimTypes.NameIdentifier, ""),
                }),
                Expires = DateTime.UtcNow.AddDays(7),
                Issuer = "WhichTokenApi",
                Audience = audience,
                SigningCredentials = new SigningCredentials(mySecurityKey, SecurityAlgorithms.EcdsaSha256)
            };

            var tokenHandler = new JsonWebTokenHandler();
            var token = tokenHandler.CreateToken(tokenDescriptor);
            return token;
        }

        public static bool ValidateToken(HttpRequest request, string audience)
        {
            try
            {
                var mySecurityKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(Secret));

                var tokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    ValidateIssuer = true,
                    ValidateAudience = true,
                    ValidIssuer = "WhichTokenApi",
                    ValidAudience = audience,
                    IssuerSigningKey = mySecurityKey
                };

                if (!TryReadTokenFromHttpRequest(request, out var token))
                {
                    return false;
                }

                var tokenHandler = new JwtSecurityTokenHandler();
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

        public static bool ValidateECDsaToken(HttpRequest request, string audience)
        {
            try
            {
                var mySecurityKey = new ECDsaSecurityKey(Certificate.GetECDsaPrivateKey());

                var tokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    ValidateIssuer = true,
                    ValidateAudience = true,
                    ValidIssuer = "WhichTokenApi",
                    ValidAudience = audience,
                    IssuerSigningKey = mySecurityKey
                };

                if (!TryReadTokenFromHttpRequest(request, out var token))
                {
                    return false;
                }

                var tokenHandler = new JsonWebTokenHandler();
                var result = tokenHandler.ValidateToken(token, tokenValidationParameters);

                return result.IsValid;
            }
            catch
            {
                return false;
            }
        }

        private static bool TryReadTokenFromHttpRequest(HttpRequest request, out string token)
        {
            token = null;

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

            token = bearer?["Bearer ".Length..].Trim();

            if (string.IsNullOrWhiteSpace(token))
            {
                return false;
            }

            return true;
        }
    }
}
