using AspNet.Identity.MongoDB;
using SimpleAuthService.Models.Auth;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace SimpleAuthService.AuthInfra
{
    /// <summary>
    /// this class will contain all the functions needed to shape the response object and control the object graph returned to the client
    /// Factory pattern will help us in shaping and controlling the response returned to the client, so we will create a simplified model for
    /// some of our domain object model (Users, Roles, Claims, etc..) we have in the database. Shaping the response and building customized object
    /// graph is very important here; because we do not want to leak sensitive data such as “PasswordHash” to the client.
    /// </summary>
    public class ModelFactory
    {
        private ApplicationUserManager _AppUserManager;
        private ApplicationRoleManager _AppRoleManager;

        public ModelFactory(ApplicationUserManager appUserManager, ApplicationRoleManager appRoleManager)
        {
            _AppUserManager = appUserManager;
            _AppRoleManager = appRoleManager;
        }

        public ProfileViewModel Create(ApplicationUser appUser)
        {
            return new ProfileViewModel
            {
                ProfileName = appUser.ProfileName,
                RegisteredEmail = appUser.Email,
                RegisteredPhoneNumber = appUser.PhoneNumber,
                IsExternalLogin = appUser.IsExternalLogin,
                EmailConfirmed = appUser.EmailConfirmed,
                PhoneNumberConfirmed = appUser.PhoneNumberConfirmed,
                CreatedTime = appUser.CreatedTime
            };
        }

        public RoleReturnModel Create(IdentityRole appRole)
        {

            return new RoleReturnModel
            {
                Id = appRole.Id,
                Name = appRole.Name,
                PermissionList = appRole.PermissionList
            };
        }
    }
}