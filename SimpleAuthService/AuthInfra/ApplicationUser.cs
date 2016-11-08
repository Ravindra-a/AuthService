using AspNet.Identity.MongoDB;
using Microsoft.AspNet.Identity;
using MongoDB.Bson.Serialization.Attributes;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web;

namespace SimpleAuthService.AuthInfra
{
    [BsonIgnoreExtraElements]
    public class ApplicationUser : IdentityUser
    {
        public bool IsExternalLogin { get; set; }

        public async Task<ClaimsIdentity> GenerateUserIdentityAsync(UserManager<ApplicationUser> manager, string authenticationType = DefaultAuthenticationTypes.ApplicationCookie)
        {
            var userIdentity = await manager.CreateIdentityAsync(this, authenticationType);
            // Add custom user claims here
            userIdentity.AddClaim(new Claim("PhoneNumber", this.PhoneNumber));
            userIdentity.AddClaim(new Claim("ProfileName", string.IsNullOrEmpty(this.ProfileName) ? "" : this.ProfileName));
            userIdentity.AddClaim(new Claim("ProfileName", this.ProfileName));
            userIdentity.AddClaim(new Claim("IsExternalLogin", this.IsExternalLogin.ToString().ToLower()));
            return userIdentity;
        }
    }

    public enum emailTemplates
    {
        ResetPassword,
        InviteFriends,
        SignUpEmail
    }

}