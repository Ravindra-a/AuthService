using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Security.Principal;
using System.Web;

namespace SimpleAuthService.AuthInfra
{
    public static class IdentityExtensions
    {
        /// <summary>
        /// retun any claim of string type
        /// </summary>
        /// <param name="identity"></param>
        /// <param name="userDetailType"></param>
        /// <returns></returns>
        public static string GetUserDetail(this IIdentity identity, string userDetailType)
        {
            return ((ClaimsIdentity)identity).FindFirst(userDetailType).Value;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="identity"></param>
        /// <returns></returns>
        public static Boolean GetIsExternalLogin(this IIdentity identity)
        {
            if (bool.Parse(((ClaimsIdentity)identity).FindFirst("IsExternalLogin").Value))
            {
                return true;
            }
            else
            {
                return false;
            }
        }
    }
}