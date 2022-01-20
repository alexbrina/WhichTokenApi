using Microsoft.AspNetCore.Http;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace WhichTokenApi
{
    public sealed class Jwt : IDisposable
    {
        private readonly string secret;
        private readonly ECDsa privateKey;
        private readonly ECDsa publicKey;

        public Jwt(string secret, string certificateFileName = null)
        {
            if (string.IsNullOrWhiteSpace(secret))
            {
                throw new ArgumentException($"'{nameof(secret)}' cannot be " +
                    $"null or whitespace.", nameof(secret));
            }

            this.secret = secret;

            if (certificateFileName != null)
            {
                var file = Path.Combine(AppContext.BaseDirectory, certificateFileName);
                if (!File.Exists(file))
                {
                    throw new ArgumentException($"Certificate file '{file}' not found.",
                        nameof(certificateFileName));
                }
                using var certificate = new X509Certificate2(file, secret);
                privateKey = certificate.GetECDsaPrivateKey();
                publicKey = certificate.GetECDsaPublicKey();
            }
        }

        public string GenerateToken(string audience)
        {
            var mySecurityKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(secret));

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

        public string GenerateECDsaToken(string audience)
        {
            if (privateKey == null)
            {
                throw new InvalidOperationException("Cannot generate " +
                    "token because required key was not informed.");
            }

            var mySecurityKey = new ECDsaSecurityKey(privateKey);
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

        public bool ValidateToken(HttpRequest request, string audience)
        {
            try
            {
                if (!TryReadTokenFromHttpRequest(request, out var token))
                {
                    return false;
                }

                var mySecurityKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(secret));
                var tokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    ValidateIssuer = true,
                    ValidateAudience = true,
                    ValidIssuer = "WhichTokenApi",
                    ValidAudience = audience,
                    IssuerSigningKey = mySecurityKey
                };

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

        public bool ValidateECDsaToken(HttpRequest request, string audience)
        {
            try
            {
                if (!TryReadTokenFromHttpRequest(request, out var token))
                {
                    return false;
                }

                if (publicKey == null)
                {
                    throw new InvalidOperationException("Cannot validate " +
                        "token because required key was not informed.");
                }

                var mySecurityKey = new ECDsaSecurityKey(publicKey);
                var tokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    ValidateIssuer = true,
                    ValidateAudience = true,
                    ValidIssuer = "WhichTokenApi",
                    ValidAudience = audience,
                    IssuerSigningKey = mySecurityKey
                };

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

        public void Dispose()
        {
            privateKey?.Dispose();
            publicKey?.Dispose();
        }
    }
}
