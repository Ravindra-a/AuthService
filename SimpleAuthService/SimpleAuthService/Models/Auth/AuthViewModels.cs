using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Web;

namespace SimpleAuthService.Models.Auth
{
    public class ExternalLoginConfirmationViewModel
    {
        [Required]
        [Display(Name = "Email")]
        public string ExtenalLoginEmail { get; set; }

        [Required]
        [Phone]
        [Display(Name = "Phone Number")]
        [RegularExpression(@"^[789]\d{9}$", ErrorMessage = "Not a valid Phone number")]
        public string ExternalLoginRegisterPhoneNumber { get; set; }

        [Required]
        [StringLength(200, ErrorMessage = "The {0} must be at least {2} characters long.", MinimumLength = 2)]
        [Display(Name = "Full Name")]
        public string ExternalLoginFullName { get; set; }

        [Required]
        public string Provider { get; set; }

        [Required]
        public string ExternalAccessToken { get; set; }

        public string ClientId { get; set; }

        public string SecurityStamp { get; set; }

        public int Code { get; set; }

    }

    public class RegisterViewModel
    {
        [Required]
        [StringLength(200, ErrorMessage = "The {0} must be at least {2} characters long.", MinimumLength = 2)]
        [Display(Name = "Full Name")]
        public string RegisterFullName { get; set; }

        [Required]
        [EmailAddress]
        [Display(Name = "Email")]
        public string RegisterEmail { get; set; }

        [Required]
        [Phone]
        [Display(Name = "Phone Number")]
        [RegularExpression(@"^[789]\d{9}$", ErrorMessage = "Not a valid Phone number")]
        public string RegisterPhoneNumber { get; set; }

        [Required]
        [StringLength(100, ErrorMessage = "The {0} must be at least {2} characters long.", MinimumLength = 6)]
        [DataType(DataType.Password)]
        [Display(Name = "Password")]
        public string RegisterPassword { get; set; }
        public string SecurityStamp { get; set; }

        public int Code { get; set; }
    }

    public class ResetPasswordViewModel
    {
        [Required]
        [EmailAddress]
        [Display(Name = "Email")]
        public string ResetPasswordEmail { get; set; }

        [Required]
        [StringLength(100, ErrorMessage = "The {0} must be at least {2} characters long.", MinimumLength = 6)]
        [DataType(DataType.Password)]
        [Display(Name = "Password")]
        public string ResetPasswordPassword { get; set; }

        [DataType(DataType.Password)]
        [Display(Name = "Confirm password")]
        [Compare("ResetPasswordPassword", ErrorMessage = "The password and confirmation password do not match.")]
        public string ResetPasswordConfirmPassword { get; set; }

        public string ResetPasswordCode { get; set; }
    }

    public class ForgotPasswordViewModel
    {
        [Required]
        [EmailAddress]
        [Display(Name = "Email")]
        public string ForgotPasswordEmail { get; set; }

        public string ForgotPasswordClientURL { get; set; }
    }

    public class ParsedExternalAccessToken
    {
        public string user_id { get; set; }
        public string app_id { get; set; }
    }

    public class CreateRoleBindingModel
    {
        [Required]
        [StringLength(256, ErrorMessage = "The {0} must be at least {2} characters long.", MinimumLength = 2)]
        [Display(Name = "Role Name")]
        public string Name { get; set; }

    }

    public class ProfileViewModel
    {
        [Required]
        [EmailAddress]
        [Display(Name = "Email")]
        public string RegisteredEmail { get; set; }

        [Required]
        [Phone]
        [Display(Name = "Phone Number")]
        [RegularExpression(@"^[789]\d{9}$", ErrorMessage = "Not a valid Phone number")]
        public string RegisteredPhoneNumber { get; set; }

        [StringLength(100, ErrorMessage = "The {0} must be at least {2} characters long.", MinimumLength = 3)]
        [Display(Name = "Name")]
        public string ProfileName { get; set; }
        public string Url { get; set; }
        public string ProfileId { get; set; }
        public IList<string> ProfileRoles { get; set; }
        public IList<System.Security.Claims.Claim> ProfileClaims { get; set; }
        public bool IsExternalLogin { get; set; }
        public bool EmailConfirmed { get; set; }
        public bool PhoneNumberConfirmed { get; set; }
        public DateTime CreatedTime { get; set; }
    }

    public class ChangePasswordViewModel
    {
        [Required]
        [DataType(DataType.Password)]
        [Display(Name = "Current password")]
        public string OldPassword { get; set; }

        [Required]
        [StringLength(100, ErrorMessage = "The {0} must be at least {2} characters long.", MinimumLength = 6)]
        [DataType(DataType.Password)]
        [Display(Name = "New password")]
        public string NewPassword { get; set; }

        [DataType(DataType.Password)]
        [Display(Name = "Confirm new password")]
        [Compare("NewPassword", ErrorMessage = "The new password and confirmation password do not match.")]
        public string ConfirmPassword { get; set; }
    }

    public class RoleReturnModel
    {
        public string Url { get; set; }
        public string Id { get; set; }
        public string Name { get; set; }
        public List<string> PermissionList { get; set; }
    }

    public class UsersInRoleModel
    {

        public string Id { get; set; }
        public List<string> EnrolledUsers { get; set; }
        public List<string> RemovedUsers { get; set; }
    }
}