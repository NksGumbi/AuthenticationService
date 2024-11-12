using AuthServer.Entities;
using System.Text.Json.Serialization;

namespace AuthServer.Models
{
    public class AuthenticateResponse
    {
        public int PlayerId { get; set; }
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public string Username { get; set; }
        public string Token { get; set; }

        [JsonIgnore]
        public string RefreshToken { get; set; }

        public AuthenticateResponse(User user, string token, string refreshToken)
        {
            PlayerId = user.PlayerId;
            FirstName = user.FirstName;
            LastName = user.LastName;
            Username = user.Username;
            Token = token;
            RefreshToken = refreshToken;
        }
    }
}
