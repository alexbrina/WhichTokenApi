using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System;
using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Threading.Tasks;

namespace WhichTokenApi.Authentications
{
    public class CustomSchemeHandler : AuthenticationHandler<CustomSchemeOptions>
    {
        private readonly IHostEnvironment environment;

        public CustomSchemeHandler(
            IOptionsMonitor<CustomSchemeOptions> options,
            ILoggerFactory logger,
            UrlEncoder encoder,
            ISystemClock clock,
            IHostEnvironment environment)
            : base(options, logger, encoder, clock)
        {
            this.environment = environment
                ?? throw new System.ArgumentNullException(nameof(environment));
        }

        protected override Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            if (!TryAuthenticate())
            {
                return Task.FromResult(AuthenticateResult.NoResult());
            }

            var claims = new Claim[]
            {
                new Claim(ClaimTypes.NameIdentifier, "WebApi")
            };

            var claimsIdentity = new ClaimsIdentity(claims, nameof(CustomSchemeHandler));
            var claimsPrincipal = new ClaimsPrincipal(claimsIdentity);
            var authTicket = new AuthenticationTicket(claimsPrincipal, CustomSchemeOptions.Name);

            return Task.FromResult(AuthenticateResult.Success(authTicket));
        }

        private bool TryAuthenticate()
        {
            string secret = null;

            // env is Development consider authenticated!
            if (environment.IsDevelopment())
            {
                return true;
            }

            if (!Request.Headers.TryGetValue("Authorization", out var value))
            {
                return false;
            }

            var authorization = value.ToString();


            if (string.IsNullOrEmpty(authorization))
            {
                return false;
            }

            if (authorization.StartsWith("Bearer ", StringComparison.InvariantCulture))
            {
                secret = authorization["Bearer ".Length..].Trim();
            }

            if (string.IsNullOrEmpty(secret))
            {
                return false;
            }

            // It's just a naive example, right!
            return secret.Equals("secret!", StringComparison.InvariantCulture);
        }
    }
}
