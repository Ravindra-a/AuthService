using System;
using System.Threading.Tasks;
using Microsoft.Owin;
using Owin;
using System.Web.Http;
using System.Web.Mvc;
using System.Web.Routing;
using Microsoft.Owin.Security.OAuth;
using Microsoft.Owin.Security.Google;
using Microsoft.Owin.Security.Facebook;
using SimpleAuthService.AuthInfra;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security;
using Microsoft.AspNet.Identity;
using SimpleAuthService.AuthProviders;
using System.Configuration;
using Microsoft.Owin.Security.DataHandler.Encoder;
using Microsoft.Owin.Security.Jwt;
using Microsoft.Owin.Cors;

[assembly: OwinStartup(typeof(SimpleAuthService.Startup))]

namespace SimpleAuthService
{
    public class Startup
    {

        public static OAuthAuthorizationServerOptions OAuthServerOptions { get; private set; }

        //social providers
        public static GoogleOAuth2AuthenticationOptions googleAuthOptions { get; private set; }
        public static FacebookAuthenticationOptions facebookAuthOptions { get; private set; }

        public void Configuration(IAppBuilder app)
        {
            ConfigureOAuthTokenGeneration(app);

            ConfigureOAuthTokenConsumption(app);

            // For more information on how to configure your application, visit http://go.microsoft.com/fwlink/?LinkID=316888
            ConfigureWebApi();

            app.UseCors(CorsOptions.AllowAll);            
        }

        /// <summary>
        /// All registrations from application_start of global.asax.cs
        /// </summary>
        /// <param name="config"></param>
        private void ConfigureWebApi()
        {
            AreaRegistration.RegisterAllAreas();
            GlobalConfiguration.Configure(WebApiConfig.Register);
            RouteConfig.RegisterRoutes(RouteTable.Routes);            
        }

        /// <summary>
        /// Configures cookie auth for web apps and JWT for SPA,Mobile apps
        /// </summary>
        /// <param name="app"></param>
        private void ConfigureOAuthTokenGeneration(IAppBuilder app)
        {
            // Configure the db context, user manager and role manager to use a single instance per request
            app.CreatePerOwinContext(ApplicationDbContext.Create);
            app.CreatePerOwinContext<ApplicationUserManager>(ApplicationUserManager.Create);
            app.CreatePerOwinContext<ApplicationRoleManager>(ApplicationRoleManager.Create);
            
            //Cookie for old school MVC application
            var cookieOptions = new CookieAuthenticationOptions
            {
                AuthenticationMode = AuthenticationMode.Active,
                CookieHttpOnly = true, // JavaScript should use the Bearer
                AuthenticationType = DefaultAuthenticationTypes.ApplicationCookie,
                LoginPath = new PathString("/api/Account/Login"),
                CookieName = "AuthCookie"
            };
            // Plugin the OAuth bearer JSON Web Token tokens generation and Consumption will be here
            app.UseCookieAuthentication(new CookieAuthenticationOptions());
            app.UseExternalSignInCookie(DefaultAuthenticationTypes.ExternalCookie);

            OAuthServerOptions = new OAuthAuthorizationServerOptions()
            {
                //For Dev enviroment only (on production should be AllowInsecureHttp = false)
                AllowInsecureHttp = true,
                TokenEndpointPath = new PathString("/oauth/token"),
                AccessTokenExpireTimeSpan = TimeSpan.FromDays(30),
                Provider = new CustomOAuthProvider(),
                RefreshTokenProvider = new RefreshTokenProvider(),
                AccessTokenFormat = new CustomJwtFormat(ConfigurationManager.AppSettings["JWTPath"])
            };

            // OAuth 2.0 Bearer Access Token Generation
            app.UseOAuthAuthorizationServer(OAuthServerOptions);

            facebookAuthOptions = new FacebookAuthenticationOptions()
            {
                AppId = ConfigurationManager.AppSettings["FacebookAppId"],
                AppSecret = ConfigurationManager.AppSettings["FacebookAppSecret"],
                Scope = { "email" },
                Provider = new FacebookAuthProvider()
                //Provider = new FacebookAuthenticationProvider
                //{
                //    OnAuthenticated = context =>
                //    {
                //        context.Identity.AddClaim(new System.Security.Claims.Claim("ExternalAccessToken", context.AccessToken));
                //        return Task.FromResult(true);
                //    }
                //}
            };

            //facebook external login
            app.UseFacebookAuthentication(facebookAuthOptions);
            googleAuthOptions = new GoogleOAuth2AuthenticationOptions()
            {
                ClientId = ConfigurationManager.AppSettings["GoogleClientId"],
                ClientSecret = ConfigurationManager.AppSettings["GoogleClientSecret"],
                Provider = new GoogleAuthProvider()
            };

            app.UseGoogleAuthentication(googleAuthOptions);
        }

        /// <summary>
        /// Consuming token for webAPI [Authorize] tag
        /// </summary>
        /// <param name="app"></param>
        private void ConfigureOAuthTokenConsumption(IAppBuilder app)
        {
            app.UseCookieAuthentication(new CookieAuthenticationOptions { CookieName = "AuthCookie", AuthenticationType = DefaultAuthenticationTypes.ApplicationCookie, CookieDomain = ConfigurationManager.AppSettings["CookieDomain"] });

            var issuer = ConfigurationManager.AppSettings["JWTPath"];
            string audienceId = ConfigurationManager.AppSettings["as:AudienceId"];
            byte[] audienceSecret = TextEncodings.Base64Url.Decode(ConfigurationManager.AppSettings["as:AudienceSecret"]);

            // Api controllers with an [Authorize] attribute will be validated with JWT
            app.UseJwtBearerAuthentication(
                new JwtBearerAuthenticationOptions
                {
                    AuthenticationMode = AuthenticationMode.Active,
                    AllowedAudiences = new[] { audienceId },
                    IssuerSecurityTokenProviders = new IIssuerSecurityTokenProvider[]
                    {
                        new SymmetricKeyIssuerSecurityTokenProvider(issuer, audienceSecret)
                    }
                });
        }
    }
}
