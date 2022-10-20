using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Threading.Tasks;

namespace MYINFO_API.Configurations
{
    public static class JwtAuthentication
    {
        public static void ConfigureServices(IServiceCollection services, IConfiguration Configuration)
        {
            services.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                options.DefaultSignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = "OpenIdConnect";
            })
            .AddCookie()
            .AddOpenIdConnect(options =>
            {
                options.ClientId = Configuration.GetValue<string>("MyInfo:ClientId");
                options.ClientSecret = Configuration.GetValue<string>("MyInfo:ClientSecret");
                options.Authority = Configuration.GetValue<string>("MyInfo:AuthoriseUrl");
                options.CallbackPath = "/authorization-code/callback";
                options.ResponseType = "code";
                options.SaveTokens = true;
                options.UseTokenLifetime = false;
                options.GetClaimsFromUserInfoEndpoint = true;
                options.Scope.Add("openid");
                options.Scope.Add("profile");
                options.Scope.Add("email");

                options.TokenValidationParameters = new TokenValidationParameters
                {
                    NameClaimType = "name",
                    RoleClaimType = "role"
                };

                options.Events = new OpenIdConnectEvents()
                {
                    OnUserInformationReceived = context =>
                    {
                        string rawAccessToken = context.ProtocolMessage.AccessToken;
                        string rawIdToken = context.ProtocolMessage.IdToken;
                        var handler = new JwtSecurityTokenHandler();
                        var accessToken = handler.ReadJwtToken(rawAccessToken);
                        var idToken = handler.ReadJwtToken(rawIdToken);

                        // do something with the JWTs

                        return Task.CompletedTask;
                    },
                };
            });
        }
    }
}
