using AuthServer.Helpers;
using AuthServer.Entities;
using System.Security.Claims;
using Microsoft.Extensions.Options;
using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using StackExchange.Redis;

namespace AuthServer.Authorization
{
    public interface IJwtUtils
    {
        public Task<string> GenerateJwtToken(User user);
        public Task<int?> ValidateJwtToken(string token);
        public Task<RefreshToken> GenerateRefreshToken(string ipAddress);
    }

    public class JwtUtils : IJwtUtils
    {
        private readonly ConnectionMultiplexer _redisConnection;
        private readonly JwtSettings _jwtSettings;
        private readonly RsaSecurityKey _privateKey;
        private readonly RsaSecurityKey _publicKey;

        public JwtUtils(ConnectionMultiplexer redisConnection, IOptions<JwtSettings> jwtSettings)
        {
            _redisConnection = redisConnection;
            _jwtSettings = jwtSettings.Value;

            using RSA rsa = RSA.Create();
            byte[] privateKeyBytes = Convert.FromBase64String(_jwtSettings.RsaPrivateKey);
            rsa.ImportRSAPrivateKey(privateKeyBytes, out _);
            _privateKey = new RsaSecurityKey(rsa);

            byte[] publicKeyBytes = Convert.FromBase64String(_jwtSettings.RsaPublicKey);
            rsa.ImportSubjectPublicKeyInfo(publicKeyBytes, out _);
            _publicKey = new RsaSecurityKey(rsa);
        }

        public async Task<string> GenerateJwtToken(User user)
        {
            var tokenHandler = new JwtSecurityTokenHandler();

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[]
                {
                    new Claim("playerId", user.PlayerId.ToString())
                }),
                Expires = DateTime.Now.AddHours(24),
                SigningCredentials = new SigningCredentials(_privateKey, SecurityAlgorithms.RsaSha256)
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);
            return await Task.FromResult(tokenHandler.WriteToken(token));
        }

        public async Task<int?> ValidateJwtToken(string token)
        {
            if (token == null)
                return null;

            var tokenHandler = new JwtSecurityTokenHandler();

            try
            {
                tokenHandler.ValidateToken(token, new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = _publicKey,
                    ValidateIssuer = false,
                    ValidateAudience = false,
                    ClockSkew = TimeSpan.Zero
                }, out SecurityToken validatedToken);

                var jwtToken = (JwtSecurityToken)validatedToken;
                var userId = int.Parse(jwtToken.Claims.First(x => x.Type == "playerId").Value);

                return await Task.FromResult(userId);
            }
            catch
            {
                return null;
            }
        }

        public async Task<RefreshToken> GenerateRefreshToken(string ipAddress)
        {
            var refreshToken = new RefreshToken
            {
                Token = await getUniqueToken(),
                Created = DateTime.Now,
                Expires = DateTime.Now.AddHours(48),
                CreatedByIp = ipAddress
            };

            return refreshToken;

            async Task<string> getUniqueToken()
            {
                var token = Convert.ToBase64String(RandomNumberGenerator.GetBytes(64));

                var redisDb = _redisConnection.GetDatabase();
                var tokenExists = await redisDb.SetContainsAsync($"refreshTokens:tokens", token);

                if (tokenExists)
                    return await getUniqueToken();

                await redisDb.SetAddAsync($"refreshTokens:tokens", token);

                return token;
            }
        }        
    }
}