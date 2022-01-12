using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;

namespace WhichTokenApi.Controllers
{
    [Authorize]
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
            return Ok(Jwt.GenerateRegularToken());
        }

        [HttpGet("regular/endpoint")]
        public IActionResult RegularEndpoint()
        {
            return Ok("👍");
        }
    }
}
