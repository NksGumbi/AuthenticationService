using AuthServer.Helpers;
using AuthServer.Services;
using Microsoft.Extensions.Options;

namespace AuthServer.Authorization
{
    public class JwtMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly JwtSettings _jwtSettings;

        public JwtMiddleware(RequestDelegate next, IOptions<JwtSettings> jwtSettings)
        {
            _next = next;
            _jwtSettings = jwtSettings.Value;
        }

        public async Task Invoke(HttpContext context, IUserService userService, IJwtUtils jwtUtils)
        {
            var token = context.Request.Headers["Authorization"].FirstOrDefault()?.Split(" ").Last();
            var userId = await jwtUtils.ValidateJwtToken(token);
            if (userId != null)
            {
                context.Items["Users"] = userService.GetById(userId.Value);
            }
            await _next(context);
        }
    }
}
