using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using WhichTokenApi.Authentications;

namespace WhichTokenApi.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class WhateverController : ControllerBase
    {
        private readonly Jwt jwt;

        public WhateverController(Jwt jwt)
        {
            this.jwt = jwt;
        }

        [AllowAnonymous]
        [HttpPost("regular/login")]
        public IActionResult RegularLogin()
        {
            return Ok(jwt.GenerateToken("WhichTokenApiRegularClient"));
        }

        // here we use the default authorization policy
        [Authorize]
        [HttpGet("regular/endpoint")]
        public IActionResult RegularEndpoint()
        {
            return Ok("👍");
        }

        [AllowAnonymous]
        [HttpPost("alternative/login")]
        public IActionResult AlternativeLogin()
        {
            return Ok(jwt.GenerateToken("WhichTokenApiAlternativeClient"));
        }

        // here we use the alternative authorization policy
        [Authorize(Policy = "Alternative")]
        [HttpGet("alternative/endpoint")]
        public IActionResult AlternativeEndpoint()
        {
            return Ok("👍");
        }

        // here we validate alternative token manually
        [HttpGet("alternative/manualvalidation")]
        public IActionResult AlternativeManualEndpoint()
        {
            if (jwt.ValidateToken(HttpContext.Request, "WhichTokenApiAlternativeClient"))
            {
                return Ok("👍");
            }
            else
            {
                return Unauthorized();
            }
        }

        // here we generate ECDsa signed token
        [HttpPost("ecdsa/login")]
        public IActionResult ECDsaLogin()
        {
            return Ok(jwt.GenerateECDsaToken("WhichTokenApiECDsaClient"));
        }

        // here we validate ECDsa signed token manually
        [HttpGet("ecdsa/manualvalidation")]
        public IActionResult ECDsaManualEndpoint()
        {
            if (jwt.ValidateECDsaToken(HttpContext.Request, "WhichTokenApiECDsaClient"))
            {
                return Ok("👍");
            }
            else
            {
                return Unauthorized();
            }
        }

        // here we use the alternative authorization policy
        [Authorize(Policy = CustomSchemeOptions.Name)]
        [HttpGet("custom/endpoint")]
        public IActionResult CustomEndpoint()
        {
            return Ok("👍");
        }
    }
}
