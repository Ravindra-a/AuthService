using Microsoft.AspNet.Identity;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AspNet.Identity.MongoDB
{
    // Summary:
    //     Stores a user's phone number
    //
    // Type parameters:
    //   TUser:
    public interface IUserCustomStore<TUser> : IUserStore<TUser, string>, IDisposable where TUser : class, Microsoft.AspNet.Identity.IUser<string>
    {
        // Summary:
        //     Returns the user associated with this phonenumber
        //
        // Parameters:
        //   phonenumber:
        Task<TUser> FindByPhoneNumberAsync(string phoneNumber);

        /// <summary>
        /// returns user associated with this referralCode - async
        /// </summary>
        /// <param name="referralCode"></param>
        /// <returns></returns>
        Task<TUser> FindByReferralCodeAsync(string referralCode);

        /// <summary>
        /// search user by registration number
        /// </summary>
        /// <param name="registrationNumber"></param>
        /// <returns></returns>
        Task<TUser> FindByRegistrationNumberAsync(string registrationNumber);

        /// <summary>
        /// search user by registration number
        /// </summary>
        /// <param name="registrationNumber"></param>
        /// <returns></returns>
        Task<TUser> FindByProfileNameAsync(string profileName);
    }
}
