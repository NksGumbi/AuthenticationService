namespace AuthServer.Helpers
{
    public class JwtSettings
    {
        public string RsaPrivateKey { get; set; }
        public string RsaPublicKey { get; set; }
        public int RefreshTokenTTL { get; set; }
    }
}
