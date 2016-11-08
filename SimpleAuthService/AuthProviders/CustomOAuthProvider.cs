using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.OAuth;
using SimpleAuthService.AuthInfra;
using SimpleAuthService.Models;
using SimpleAuthService.Repositories;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web;
using Microsoft.AspNet.Identity.Owin;

namespace SimpleAuthService.AuthProviders
{
    public class CustomOAuthProvider : OAuthAuthorizationServerProvider
    {
        public CustomOAuthProvider()
        {

        }

        /// <summary>
        /// validating client id with DB
        /// </summary>
        /// <param name="context"></param>
        /// <returns></returns>
        public override Task ValidateClientAuthentication(OAuthValidateClientAuthenticationContext context)
        {
            context.Validated();
            return Task.FromResult<object>(null);
        }

        /// <summary>
        /// The method “GrantResourceOwnerCredentials” is responsible for receiving the username and password from the request and validate them against our ASP.NET 2.1 Identity system, 
        /// if the credentials are valid and the email is confirmed we are building an identity for the logged in user, 
        /// this identity will contain all the roles and claims for the authenticated user, until now we didn’t cover roles and claims part of the tutorial,
        /// but for the mean time you can consider all users registered in our system without any roles or claims mapped to them.
        /// </summary>
        /// <param name="context"></param>
        /// <returns></returns>
        public override async Task GrantResourceOwnerCredentials(OAuthGrantResourceOwnerCredentialsContext context)
        {

            var allowedOrigin = context.OwinContext.Get<string>("clientAllowedOrigin");

            if (allowedOrigin == null) allowedOrigin = "*";

            context.OwinContext.Response.Headers.Add("Access-Control-Allow-Origin", new[] { allowedOrigin });

            var userManager = context.OwinContext.GetUserManager<ApplicationUserManager>();

            ApplicationUser user = await userManager.FindAsync(context.UserName.ToLower(), context.Password);

            if (user == null)
            {
                context.SetError("invalid_grant", "The user name or password is incorrect.");
                return;
            }

            if (!user.EmailConfirmed)
            {
                context.SetError("invalid_grant", "Your account is created, please check your email and confirm your email address");
                return;
            }

            //Generating access token SPA,Mobile apps
            ClaimsIdentity oAuthIdentity = await user.GenerateUserIdentityAsync(userManager, "JWT");
            var props = new AuthenticationProperties(new Dictionary<string, string>
                {
                    { 
                        "client_id", (context.ClientId == null) ? string.Empty : context.ClientId
                    },
                    { 
                        "userName", context.UserName
                    }
                });
            var ticket = new AuthenticationTicket(oAuthIdentity, props);

            context.Validated(ticket);

            //Generating cookie for web clients
            ClaimsIdentity cookiesIdentity = await user.GenerateUserIdentityAsync(userManager,
                CookieAuthenticationDefaults.AuthenticationType);
            context.Request.Context.Authentication.SignIn(props, cookiesIdentity);

        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="context"></param>
        /// <returns></returns>
        public override Task TokenEndpoint(OAuthTokenEndpointContext context)
        {
            foreach (KeyValuePair<string, string> property in context.Properties.Dictionary)
            {
                context.AdditionalResponseParameters.Add(property.Key, property.Value);
            }

            return Task.FromResult<object>(null);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="context"></param>
        /// <returns></returns>
        public override async Task GrantRefreshToken(OAuthGrantRefreshTokenContext context)
        {
            var originalClient = context.Ticket.Properties.Dictionary["client_id"];
            var currentClient = context.ClientId;

            if (originalClient != currentClient)
            {
                context.SetError("invalid_clientId", "Refresh token is issued to a different clientId.");
                return;
            }

            // Change auth ticket for refresh token requests
            var newIdentity = new ClaimsIdentity(context.Ticket.Identity.Claims, "JWT");

            ////access token
            //var newTicket = new AuthenticationTicket(newIdentity, context.Ticket.Properties);
            //context.Validated(newTicket);
            ////Cookie       
            //newIdentity = new ClaimsIdentity(context.Ticket.Identity.Claims , CookieAuthenticationDefaults.AuthenticationType);
            //context.Request.Context.Authentication.SignIn(context.Ticket.Properties, newIdentity);


            var userManager = context.OwinContext.GetUserManager<ApplicationUserManager>();

            ApplicationUser user = await userManager.FindByEmailAsync(context.Ticket.Identity.Name);
            //Generating access token SPA,Mobile apps
            ClaimsIdentity oAuthIdentity = await user.GenerateUserIdentityAsync(userManager, "JWT");

            var ticket = new AuthenticationTicket(oAuthIdentity, context.Ticket.Properties);

            context.Validated(ticket);

            //Generating cookie for web clients
            ClaimsIdentity cookiesIdentity = await user.GenerateUserIdentityAsync(userManager,
                CookieAuthenticationDefaults.AuthenticationType);
            context.Request.Context.Authentication.SignIn(context.Ticket.Properties, cookiesIdentity);

            //return Task.FromResult<object>(null);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="context"></param>
        /// <returns></returns>
        public override Task AuthorizationEndpointResponse(OAuthAuthorizationEndpointResponseContext context)
        {
            var refreshToken = context.OwinContext.Authentication.AuthenticationResponseGrant.Properties.Dictionary["refresh_token"];
            if (!string.IsNullOrEmpty(refreshToken))
            {
                context.AdditionalResponseParameters.Add("refresh_token", refreshToken);
            }
            return base.AuthorizationEndpointResponse(context);
        }
    }
}