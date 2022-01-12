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
            return Ok(Jwt.GenerateRegularToken("WhichTokenApiRegularClient"));
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
            return Ok(Jwt.GenerateRegularToken("WhichTokenApiAlternativeClient"));
        }

        // here we use the alternative authorization policy
        [Authorize(Policy = "Alternative")]
        [HttpGet("alternative/endpoint")]
        public IActionResult AlternativeEndpoint()
        {
            return Ok("👍");
        }
    }
}
