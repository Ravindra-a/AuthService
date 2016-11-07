using Microsoft.AspNet.Identity;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net.Mail;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Web;

namespace SimpleAuthService.AuthInfra
{
    public class ApplicationCustomValidator : CustomUserValidator<ApplicationUser>
    {
        public bool RequireUniquePhoneNumber { get; set; }
        private ApplicationUserManager Manager { get; set; }
        public ApplicationCustomValidator(ApplicationUserManager customValidator)
            : base(customValidator)
        {
            this.Manager = customValidator;
        }

        /// <summary>
        ///     Validates a user before saving
        /// </summary>
        /// <param name="item"></param>
        /// <returns></returns>
        public override async Task<IdentityResult> ValidateAsync(ApplicationUser item)
        {
            if (item == null)
            {
                throw new ArgumentNullException("item");
            }
            var errors = new List<string>();
            await ValidateUserName(item, errors);
            if (RequireUniqueEmail)
            {
                await ValidateEmail(item, errors);
            }
            if (RequireUniquePhoneNumber)
            {
                await ValidatePhoneNumber(item, errors);
            }
            if (errors.Count > 0)
            {
                return IdentityResult.Failed(errors.ToArray());
            }
            return IdentityResult.Success;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="user"></param>
        /// <param name="errors"></param>
        /// <returns></returns>
        private async Task ValidateUserName(ApplicationUser user, List<string> errors)
        {
            if (string.IsNullOrWhiteSpace(user.UserName))
            {
                errors.Add(String.Format(CultureInfo.CurrentCulture, "{0} cannot be null or empty", "Name"));
            }
            else if (AllowOnlyAlphanumericUserNames && !Regex.IsMatch(user.UserName, @"^[A-Za-z0-9@_\.]+$"))
            {
                // If any characters are not letters or digits, its an illegal user name
                errors.Add(String.Format(CultureInfo.CurrentCulture, "User name {0} is invalid, can only contain letters or digits.", user.UserName));
            }
            else
            {
                var owner = await Manager.FindByNameAsync(user.UserName);
                if (owner != null && !EqualityComparer<string>.Default.Equals(owner.Id, user.Id))
                {
                    errors.Add(String.Format(CultureInfo.CurrentCulture, "User name {0} already exists.", user.UserName));
                }
            }
        }

        // make sure email is not empty, valid, and unique
        private async Task ValidateEmail(ApplicationUser user, List<string> errors)
        {
            if (!string.IsNullOrEmpty(user.Email))
            {
                if (string.IsNullOrWhiteSpace(user.Email))
                {
                    errors.Add(String.Format(CultureInfo.CurrentCulture, "{0}  cannot be null or empty.", "Email"));
                    return;
                }
                try
                {
                    var m = new MailAddress(user.Email);
                }
                catch (FormatException)
                {
                    errors.Add(String.Format(CultureInfo.CurrentCulture, "Email '{0}' is invalid.", user.Email));
                    return;
                }
            }
            var owner = await Manager.FindByEmailAsync(user.Email);
            if (owner != null && !EqualityComparer<string>.Default.Equals(owner.Id, user.Id))
            {
                errors.Add(String.Format(CultureInfo.CurrentCulture, "Email '{0}' is already taken.", user.Email));
            }
        }

        private async Task ValidatePhoneNumber(ApplicationUser user, List<string> errors)
        {
            if (!string.IsNullOrEmpty(user.PhoneNumber))
            {
                if (string.IsNullOrWhiteSpace(user.PhoneNumber))
                {
                    errors.Add(String.Format(CultureInfo.CurrentCulture, "{0}  cannot be null or empty.", "PhoneNumber"));
                    return;
                }
            }
            var owner = await Manager.FindByPhoneNumberUserManagerAsync(user.PhoneNumber);
            if (owner != null && !EqualityComparer<string>.Default.Equals(owner.Id, user.Id))
            {
                errors.Add(String.Format(CultureInfo.CurrentCulture, "Phone Number '{0}' already exists", user.PhoneNumber));
            }
        }
    }

    /// <summary>
    ///     Validates users before they are saved to an IUserStore
    /// </summary>
    /// <typeparam name="TUser"></typeparam>
    public class CustomUserValidator<TUser> : UserValidator<TUser, string>
        where TUser : ApplicationUser
    {
        /// <summary>
        ///     Constructor
        /// </summary>
        /// <param name="manager"></param>
        public CustomUserValidator(UserManager<TUser, string> manager)
            : base(manager)
        {
        }


    }
}