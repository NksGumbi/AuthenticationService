using BCrypt.Net;
using System.Text;
using System.Linq;
using System.Text.Json;
using AuthServer.Models;
using AuthServer.Helpers;
using AuthServer.Entities;
using StackExchange.Redis;
using AuthServer.Authorization;
using Microsoft.Extensions.Options;

namespace AuthServer.Services
{
    public interface IUserService
    {
        Task <AuthenticateResponse> Authenticate(AuthenticateRequest model, string ipAddress);
        Task <AuthenticateResponse> RefreshToken(string token, string ipAddress);
        Task RevokeToken(string token, string ipAddress);
        IEnumerable<User> GetAll();
        User GetById(int id);
    }

    public class UserService : IUserService
    {
        private readonly ILogger<UserService> _logger;
        private readonly IJwtUtils _jwtUtils;
        private readonly JwtSettings _jwtSettings;
        private readonly ConnectionMultiplexer _redisConnection;

        public UserService(ILogger<UserService> logger, IJwtUtils jwtUtils, IOptions<JwtSettings> jwtSettings, ConnectionMultiplexer redisConnection)
        {
            _logger = logger;
            _jwtUtils = jwtUtils;
            _jwtSettings = jwtSettings.Value;
            _redisConnection = redisConnection;
        }

        public async Task<AuthenticateResponse> Authenticate(AuthenticateRequest model, string ipAddress)
        {
            var user = GetAll().SingleOrDefault(x => x.Username == model.Username && x.PasswordHash == model.Password);
            if (user == null)
            {
                _logger.LogInformation("Authentication failed for username: {Username}", model.Username);
                throw new AppException("Username or password is incorrect");
            }

            var token = await _jwtUtils.GenerateJwtToken(user);
            var refreshToken = await _jwtUtils.GenerateRefreshToken(ipAddress);

            var redisDb = _redisConnection.GetDatabase();

            var refreshTokenKey = $"refreshTokens:{user.PlayerId}";
            await redisDb.HashSetAsync(refreshTokenKey, refreshToken.Token, JsonSerializer.Serialize(refreshToken));
            await redisDb.SetAddAsync($"refreshTokens:users", refreshTokenKey);

            RemoveOldRefreshTokens(user);

            StoreAllUsers(user);

            return new AuthenticateResponse(user, token, refreshToken.Token);
        }

        public async Task<AuthenticateResponse> RefreshToken(string token, string ipAddress)
        {
            var user = await GetUserByRefreshToken(token);
            var refreshTokenKey = $"refreshTokens:{user.PlayerId}";

            var redisDb = _redisConnection.GetDatabase();

            var refreshTokenData = await redisDb.HashGetAsync(refreshTokenKey, token);

            if (!refreshTokenData.IsNull)
            {
                var refreshToken = JsonSerializer.Deserialize<RefreshToken>(refreshTokenData);
                if (!refreshToken.IsRevoked && !refreshToken.IsExpired)
                {
                    refreshToken.Revoked = DateTime.Now;
                    refreshToken.RevokedByIp = ipAddress;

                    var newRefreshToken = await RotateRefreshToken(refreshToken, ipAddress);
                    refreshToken.Token = newRefreshToken.Token;
                    refreshToken.Expires = newRefreshToken.Expires;
                    refreshToken.Created = newRefreshToken.Created;
                    refreshToken.CreatedByIp = newRefreshToken.CreatedByIp;
                    refreshToken.ReplacedByToken = newRefreshToken.ReplacedByToken;
                    refreshToken.ReasonRevoked = newRefreshToken.ReasonRevoked;

                    await redisDb.HashSetAsync(refreshTokenKey, token, JsonSerializer.Serialize(refreshToken));
                    await redisDb.SetAddAsync(refreshTokenKey, newRefreshToken.Token);

                    RemoveOldRefreshTokens(user);

                    StoreAllUsers(user);

                    var newToken = await _jwtUtils.GenerateJwtToken(user);

                    return new AuthenticateResponse(user, newToken, newRefreshToken.Token);
                }

                if (refreshToken.IsRevoked) 
                {
                    RevokeDescendantRefreshTokens(refreshToken, user, ipAddress, $"Attempted reuse of revoked token: {token}");
                    await redisDb.HashDeleteAsync(refreshTokenKey, token);
                }

                if (!refreshToken.IsActive)
                {
                    throw new AppException("Invalid token");
                }
            }

            throw new AppException("Refresh token not found");
        }

        public async Task RevokeToken(string token, string ipAddress)
        {
            var user = await GetUserByRefreshToken(token);
            var refreshToken = user.RefreshTokens.Single(x => x.Token == token);

            if (!refreshToken.IsActive)
                throw new AppException("Invalid token");

            RevokeRefreshToken(refreshToken, ipAddress, "Revoked without replacement");
            var redisDb = _redisConnection.GetDatabase();
            await redisDb.HashDeleteAsync($"refreshtokens:{user.PlayerId}", token);
            
            StoreAllUsers(user);
        }

        public IEnumerable<User> GetAll()
        {
            var redisDb = _redisConnection.GetDatabase();

            var userKeys = redisDb.Multiplexer.GetServer(_redisConnection.GetEndPoints().First())
                                .Keys(pattern: "user:*")
                                .Select(key => (string)key)
                                .ToList();

            if (userKeys.Count == 0)
            {
                return Enumerable.Empty<User>();
            }

            var users = new List<User>();
            foreach (var userKey in userKeys)
            {
                var hashFields = redisDb.HashGetAll(userKey);
                var user = new User
                {
                    PlayerId = int.Parse(hashFields.FirstOrDefault(f => f.Name == "PlayerId").Value),
                    FirstName = hashFields.FirstOrDefault(f => f.Name == "FirstName").Value,
                    LastName = hashFields.FirstOrDefault(f => f.Name == "LastName").Value,
                    Username = hashFields.FirstOrDefault(f => f.Name == "Username").Value,
                    PasswordHash = hashFields.FirstOrDefault(f => f.Name == "PasswordHash").Value,
                    RefreshTokens = JsonSerializer.Deserialize<List<RefreshToken>>(hashFields.FirstOrDefault(f => f.Name == "RefreshTokens").Value)
                };
                users.Add(user);
            }
            return users;
        }

        public User GetById(int PlayerId)
        {
            var userById = _redisConnection.GetDatabase().HashGetAll($"user_{PlayerId}");
            if (userById == null)
            {
                throw new KeyNotFoundException("User not Found");
            }

            var userJson = userById.ToString();
            var user = JsonSerializer.Deserialize<User>(userJson);

            return user;
        }

        private void StoreAllUsers(User user)
        {
            var redisDb = _redisConnection.GetDatabase();

            var userHash = $"user:{user.PlayerId}";
            var userFields = new HashEntry[]
            {
                new HashEntry("PlayerId", user.PlayerId),
                new HashEntry("FirstName", user.FirstName),
                new HashEntry("LastName", user.LastName),
                new HashEntry("Username", user.Username),
                new HashEntry("PasswordHash", user.PasswordHash),
                new HashEntry("RefreshTokens", JsonSerializer.Serialize(user.RefreshTokens))
            };
            redisDb.HashSet(userHash, userFields);

            //var userJson = JsonSerializer.Serialize(user);
            redisDb.HashGetAll(userHash + ":json");
        }

        private async Task<User> GetUserByRefreshToken(string token)
        {
            var redisDb = _redisConnection.GetDatabase();
            var userKeys = await redisDb.SetMembersAsync("user");

            foreach (var userKey in userKeys)
            {
                var user = JsonSerializer.Deserialize<User>(userKey);

                var refreshTokenKey = $"refreshTokens:{user.PlayerId}";
                var refreshTokenData = await redisDb.HashGetAsync(refreshTokenKey, token);

                if (!refreshTokenData.IsNull)
                {
                    return user;
                }
            }

            throw new AppException("Invalid token");
        }

        private async Task<RefreshToken> RotateRefreshToken(RefreshToken refreshToken, string ipAddress)
        {
            var newRefreshToken = await _jwtUtils.GenerateRefreshToken(ipAddress);
            RevokeRefreshToken(refreshToken, ipAddress, "Replaced by new token", newRefreshToken.Token);
            return newRefreshToken;
        }

        private async Task RemoveOldRefreshTokens(User user)
        {
            var redisDb = _redisConnection.GetDatabase();
            var oldTokens = await redisDb.HashGetAllAsync($"refreshTokens:{user.PlayerId}");
            var expiredTokens = oldTokens.Where(t =>
            {
                var refreshToken = JsonSerializer.Deserialize<RefreshToken>(t.Value);
                return !refreshToken.IsActive && refreshToken.Created.AddDays(_jwtSettings.RefreshTokenTTL) < DateTime.Now;
            }).Select(t => t.Name).ToArray();

            if (expiredTokens.Any())
            {
                await redisDb.HashDeleteAsync($"refreshTokens:{user.PlayerId}", expiredTokens);
            }
        }

        private void RevokeDescendantRefreshTokens(RefreshToken refreshToken, User user, string ipAddress, string reason)
        {
            if (!string.IsNullOrEmpty(refreshToken.ReplacedByToken))
            {
                var childToken = user.RefreshTokens.SingleOrDefault(x => x.Token == refreshToken.ReplacedByToken);
                if (childToken.IsActive)
                    RevokeRefreshToken(childToken, ipAddress, reason);
                else
                    RevokeDescendantRefreshTokens(childToken, user, ipAddress, reason);
            }
        }

        private void RevokeRefreshToken(RefreshToken token, string ipAddress, string reason = null, string replacedByToken = null)
        {
            token.Revoked = DateTime.Now;
            token.RevokedByIp = ipAddress;
            token.ReasonRevoked = reason;
            token.ReplacedByToken = replacedByToken;
        }
    }
}
