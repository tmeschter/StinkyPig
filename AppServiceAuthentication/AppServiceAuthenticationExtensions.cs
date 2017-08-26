using System;
using System.Collections.Generic;
using System.Text;
using Microsoft.AspNetCore.Authentication;

namespace AppServiceAuthentication
{
    public static class AppServiceAuthenticationExtensions
    {
        public static AuthenticationBuilder AddAppServiceAuth(this AuthenticationBuilder builder)
        {
            return builder.AddScheme<AppServiceAuthenticationOptions, AppServiceAuthenticationHandler>(
                AppServiceAuthenticationDefaults.AuthenticationScheme,
                displayName: null,
                configureOptions: null);
        }
    }
}
