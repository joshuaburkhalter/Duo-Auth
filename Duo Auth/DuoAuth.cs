using DuoSecurity.Auth.Http;

namespace Duo_Auth
{
    public class Duo
    {
        public ushort AuthStatus;
        public delegate void AuthCallback(ushort status);

        public AuthCallback AuthCall { get; set; }
        public async void Auth(string host, string ikey, string skey, string user)
        {
            var config = new DuoAuthConfig(host, ikey, skey);
            var client = new DuoAuthClient(config);
            var res = await client.AuthPushByUsernameAsync(user);
            var json = res.OriginalJson;

            if (json.Contains("allow"))
            {
                AuthStatus = 1;
            }
            else if (json.Contains("deny"))
            {
                AuthStatus = 2;
            }
            else if (json.Contains("username"))
            {
                AuthStatus = 3;
            }
            else
            {
                AuthStatus = 0;
            }

            AuthCall(AuthStatus);

        }
    }
}