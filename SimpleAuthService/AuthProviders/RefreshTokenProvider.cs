using Microsoft.Owin.Security.Infrastructure;
using SimpleAuthService.AuthInfra;
using SimpleAuthService.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Web;

namespace SimpleAuthService.AuthProviders
{
    public class RefreshTokenProvider : IAuthenticationTokenProvider
    {
        /// <summary>
        /// 
        /// </summary>
        /// <param name="context"></param>
        public async Task CreateAsync(AuthenticationTokenCreateContext context)
        {
            throw new NotImplementedException();
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="context"></param>
        public async Task ReceiveAsync(AuthenticationTokenReceiveContext context)
        {

            throw new NotImplementedException();
        }


        public void Create(AuthenticationTokenCreateContext context)
        {
            var clientid = context.Ticket.Properties.Dictionary["client_id"];

            if (string.IsNullOrEmpty(clientid))
            {
                return;
            }

            var refreshTokenId = Guid.NewGuid().ToString("n");

            var refreshTokenLifeTime = context.OwinContext.Get<string>("clientRefreshTokenLifeTime");

            var token = new RefreshToken()
            {
                RefreshTokenId = Helper.GetHash(refreshTokenId),
                ClientId = clientid,
                Subject = context.Ticket.Identity.Name,
                IssuedUtc = DateTime.UtcNow,
                ExpiresUtc = DateTime.UtcNow.AddMinutes(Convert.ToDouble(refreshTokenLifeTime))
            };

            context.Ticket.Properties.IssuedUtc = token.IssuedUtc;
            context.Ticket.Properties.ExpiresUtc = token.ExpiresUtc;

            //token.ProtectedTicket = context.SerializeTicket();            
            Microsoft.Owin.Security.DataHandler.Serializer.TicketSerializer serializer
                = new Microsoft.Owin.Security.DataHandler.Serializer.TicketSerializer();

            token.ProtectedTicket = System.Text.Encoding.Default.GetString(serializer.Serialize(context.Ticket));

            context.SetToken(refreshTokenId);
        }

        public void Receive(AuthenticationTokenReceiveContext context)
        {
            throw new NotImplementedException();
        }

    }
}