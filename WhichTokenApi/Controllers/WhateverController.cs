using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;

namespace WhichTokenApi.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class WhateverController : ControllerBase
    {
        private readonly ILogger<WhateverController> _logger;

        public WhateverController(ILogger<WhateverController> logger)
        {
            _logger = logger;
        }

        [AllowAnonymous]
        [HttpPost("regular/login")]
        public IActionResult RegularLogin()
        {
            return Ok(Jwt.GenerateToken("WhichTokenApiRegularClient"));
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
            return Ok(Jwt.GenerateToken("WhichTokenApiAlternativeClient"));
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
            if (Jwt.ValidateToken(HttpContext.Request, "WhichTokenApiAlternativeClient"))
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
            return Ok(Jwt.GenerateECDsaToken("WhichTokenApiECDsaClient"));
        }

        // here we validate ECDsa signed token manually
        [HttpGet("ecdsa/manualvalidation")]
        public IActionResult ECDsaManualEndpoint()
        {
            if (Jwt.ValidateECDsaToken(HttpContext.Request, "WhichTokenApiECDsaClient"))
            {
                return Ok("👍");
            }
            else
            {
                return Unauthorized();
            }
        }
    }
}
