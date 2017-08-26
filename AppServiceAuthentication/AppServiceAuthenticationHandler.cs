using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Security.Principal;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Newtonsoft.Json.Linq;

namespace AppServiceAuthentication
{
    public class AppServiceAuthenticationHandler : AuthenticationHandler<AppServiceAuthenticationOptions>
    {
        protected AppServiceAuthenticationHandler(IOptionsMonitor<AppServiceAuthenticationOptions> options, ILoggerFactory logger, UrlEncoder encoder, ISystemClock clock)
            : base(options, logger, encoder, clock)
        {
        }

        protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            var cookieContainer = new CookieContainer();
            var handler = new HttpClientHandler
            {
                CookieContainer = cookieContainer
            };

            var uriString = $"{Context.Request.Scheme}://{Context.Request.Host}";

            foreach (var cookie in Context.Request.Cookies)
            {
                cookieContainer.Add(new Uri(uriString), new Cookie(cookie.Key, cookie.Value));
            }

            var request = new HttpRequestMessage(HttpMethod.Get, $"{uriString}/.auth/me");

            foreach (var header in Context.Request.Headers)
            {
                if (header.Key.StartsWith("X-ZUMO-"))
                {
                    request.Headers.Add(header.Key, header.Value[0]);
                }
            }

            JArray payload = null;

            using (HttpClient client = new HttpClient(handler))
            {
                try
                {
                    var response = await client.SendAsync(request);
                    if (!response.IsSuccessStatusCode)
                    {
                        return AuthenticateResult.Fail("Unable to fetch user information from auth endpoint.");
                    }

                    var content = await response.Content.ReadAsStringAsync();

                    payload = JArray.Parse(content);
                }
                catch (Exception ex)
                {
                    Logger.LogError(ex.Message);
                }
            }

            if (payload == null)
            {
                return AuthenticateResult.Fail("Could not retrieve JSON from /me endpoint");
            }

            var id = payload[0]["user_id"].Value<string>();
            var idToken = payload[0]["id_token"].Value<string>();
            var providerName = payload[0]["provider_name"].Value<string>();

            Logger.LogDebug("payload was fetched from endpoint. id: {0}", id);

            var identity = new GenericIdentity(id);

            Logger.LogInformation("building claims from payload...");

            List<Claim> claims = new List<Claim>();
            foreach (var claim in payload[0]["user_claims"])
            {
                claims.Add(new Claim(claim["typ"].ToString(), claim["val"].ToString()));
            }

            Logger.LogInformation("Add claims to new identity");

            identity.AddClaims(claims);
            identity.AddClaim(new Claim("id_token", idToken));
            identity.AddClaim(new Claim("provider_name", providerName));

            ClaimsPrincipal p = new GenericPrincipal(identity, null); //todo add roles?

            var ticket = new AuthenticationTicket(p,
                new AuthenticationProperties(),
                Scheme.Name);

            Logger.LogInformation("Set identity to user context object.");
            this.Context.User = p;

            Logger.LogInformation("identity build was a success, returning ticket");
            return AuthenticateResult.Success(ticket);
        }
    }
}
