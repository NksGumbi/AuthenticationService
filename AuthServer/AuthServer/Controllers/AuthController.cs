using AuthServer.Models;
using AuthServer.Services;
using Microsoft.AspNetCore.Mvc;
using AuthServer.Authorization;
using Microsoft.AspNetCore.Cors;

namespace AuthServer.Controllers
{
    //[Authorize]
    [ApiController]
    [Route("[controller]")]
    [EnableCors("CorsPolicy")]
    public class AuthController : ControllerBase
    {
        private IUserService _userService;

        public AuthController(IUserService userService)
        {
            _userService = userService;
        }

        [AllowAnonymous]
        [HttpPost("Authenticate")]
        public async Task<IActionResult> Authenticate(AuthenticateRequest model)
        {
            var response = await _userService.Authenticate(model, ipAddress());
            return Ok(response);
        }

        [AllowAnonymous]
        [HttpPost("Refresh-Token")]
        public async Task<IActionResult> RefreshToken([FromBody] string token)
        {
            var response = await _userService.RefreshToken(token, ipAddress());
            return Ok(response);
        }

        [HttpPost("Revoke-Token")]
        public async Task<IActionResult> RevokeToken([FromBody] string token)
        {
            if (string.IsNullOrEmpty(token))
                return BadRequest(new { message = "Token is required" });

            await _userService.RevokeToken(token, ipAddress());
            return Ok(new { message = "Token revoked" });
        }

        [HttpGet("Get-all-Users")]
        public IActionResult GetAll()
        {
            var users = _userService.GetAll();
            return Ok(users);
        }

        [HttpGet("{PlayerId}")]
        public IActionResult GetById(int PlayerId)
        {
            var user = _userService.GetById(PlayerId);
            return Ok(user);
        }

        [HttpGet("{PlayerId}/Refresh-Tokens")]
        public IActionResult GetRefreshTokens(int PlayerId)
        {
            var user = _userService.GetById(PlayerId);
            return Ok(user.RefreshTokens);
        }

        private string ipAddress()
        {
            if (Request.Headers.ContainsKey("X-Forwarded-For"))
                return Request.Headers["X-Forwarded-For"];
            else
                return HttpContext.Connection.RemoteIpAddress.MapToIPv4().ToString();
        }
    }
}
