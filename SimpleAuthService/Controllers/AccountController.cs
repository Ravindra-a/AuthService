using Microsoft.AspNet.Identity;
using Microsoft.Owin.Security;
using SimpleAuthService.AuthInfra;
using SimpleAuthService.Models.Auth;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using System.Web.Http;

namespace SimpleAuthService.Controllers
{
    /// <summary>
    /// Auth service Class that has methods for all Authentication purpose i.e. local logins, social logins, Roles, change password , reset password, add user details 
    /// </summary>
    [RoutePrefix("api/account")]
    public class AccountController : BaseAPIController
    {

        public AccountController()
        {
            
        }

        private IAuthenticationManager Authentication
        {
            get { return Request.GetOwinContext().Authentication; }
        }



        #region Profile info CRUD

        /// <summary>
        /// Method will be called to register a user in local DB
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        [AllowAnonymous]
        [HttpPost]
        [Route("Register")]
        public async Task<IHttpActionResult> Register(RegisterViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            //for corporate sign up that are associated with DrivoJoy manual confirmation of email is required.
            Boolean isEmailConfirmed = true;

            string[] host = (model.RegisterEmail.Split('@'));
            string hostname = host[1];
            try
            {
                IPHostEntry IPhst = Dns.GetHostEntry(hostname);
            }
            catch
            {
                return BadRequest("invalid Email");
            }
           
            
            var user = new ApplicationUser { UserName = model.RegisterEmail.ToLower(), ProfileName = model.RegisterFullName, Email = model.RegisterEmail.ToLower(), PhoneNumber = model.RegisterPhoneNumber, EmailConfirmed = isEmailConfirmed, ReferralCode = GenerateReferralCode(8), PhoneNumberConfirmed = true };
            var addUserResult = await this.UserManager.CreateAsync(user, model.RegisterPassword);

            if (!addUserResult.Succeeded)
            {
                AddErrors(addUserResult);
                return BadRequest(addUserResult.Errors.FirstOrDefault());
            }

            return Ok();
        }

        /// <summary>
        /// To confirm email if we want to send a email link as part of confirmation. Did this for redbus.
        /// </summary>
        /// <param name="userId"></param>
        /// <param name="code"></param>
        /// <returns></returns>
        [Route("ConfirmEmail")]
        [AllowAnonymous]
        public async Task<IHttpActionResult> ConfirmEmail(string userId, string code)
        {
            IdentityResult confirmEmailResult;
            if (userId == null || code == null)
            {
                return BadRequest("Field cannot be null");
            }
            try
            {
                confirmEmailResult = await UserManager.ConfirmEmailAsync(userId, code);
            }
            catch (Exception ex)
            {
                return InternalServerError(ex);
            }
            if (confirmEmailResult.Succeeded)
            {
                return Ok();
            }

            //reached this far something went wrong
            GetErrorResult(confirmEmailResult);
            return BadRequest(ModelState);
        }


        /// <summary>
        /// Get all Users - for dashboard and only admin role
        /// </summary>
        /// <returns></returns>
        [Authorize(Roles = "Admin,hubmanager,customercare,serviceadvisor")]
        [Route("users")]
        public IHttpActionResult GetUsers()
        {
            return Ok(this.UserManager.Users.ToList().Select(u => this.TheModelFactory.Create(u)));
        }


        /// <summary>
        /// fetch user details by email for dashboard and only admin role
        /// </summary>
        /// <param name="email"></param>
        /// <returns></returns>
        [Authorize(Roles = "Admin,hubmanager,customercare,serviceadvisor")]
        [Route("GetUserByEmail")]
        public async Task<IHttpActionResult> GetUserByEmail(string email)
        {
            var user = await this.UserManager.FindByEmailAsync(email);

            if (user != null)
            {
                return Ok(this.TheModelFactory.Create(user));
                //return Ok(user);
            }

            return NotFound();

        }

        /// <summary>
        /// fetch user details by email for dashboard and only admin role
        /// </summary>
        /// <param name="email"></param>
        /// <returns></returns>
        [Authorize(Roles = "Admin,hubmanager,customercare,serviceadvisor")]
        [Route("GetUserByPhoneNumber")]
        public async Task<IHttpActionResult> GetUserByPhoneNumber(string phoneNumber)
        {
            var user = await this.UserManager.FindByPhoneNumberUserManagerAsync(phoneNumber);

            if (user != null)
            {
                return Ok(this.TheModelFactory.Create(user));
                //return Ok(user);
            }

            return NotFound();

        }

        /// <summary>
        /// fetch user details by email for dashboard and only admin role
        /// </summary>
        /// <param name="email"></param>
        /// <returns></returns>
        [Authorize(Roles = "Admin,hubmanager,customercare,serviceadvisor")]
        [Route("GetUserByName")]
        public async Task<IHttpActionResult> GetUserByName(string profileName)
        {
            var user = await this.UserManager.FindByProfileNameAsync(profileName);

            if (user != null)
            {
                return Ok(this.TheModelFactory.Create(user));
                //return Ok(user);
            }

            return NotFound();

        }

        /// <summary>
        /// Change Password after logging in. This shouldn't allow anonymous
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        [Authorize]
        [HttpPost]
        [Route("ChangePassword")]
        [ApiExplorerSettings(IgnoreApi = false)]
        public IHttpActionResult ChangePassword(ChangePasswordViewModel model)
        {
            try
            {
                if (!ModelState.IsValid)
                {
                    return BadRequest(ModelState);
                }
                var changePasswordResult = UserManager.ChangePassword(User.Identity.GetUserId(), model.OldPassword, model.NewPassword);
                if (changePasswordResult.Succeeded)
                {
                    var user = UserManager.FindById(User.Identity.GetUserId());

                    return Ok();
                }

                //reached this far something went wrong
                GetErrorResult(changePasswordResult);
                return BadRequest(ModelState);

            }
            catch (Exception ex)
            {
                ModelState.AddModelError("", ex.Message);
                return BadRequest(ModelState);
            }
        }

        /// <summary>
        /// Forgot Password call, will trigger an email and should allow anonymous
        /// </summary>
        /// <param name="model"></param>
        /// <param name="forgotPasswordSubmit"></param>
        /// <returns></returns>
        [HttpPost]
        [Route("forgotpassword")]
        [ApiExplorerSettings(IgnoreApi = false)]
        [AllowAnonymous]
        public async Task<IHttpActionResult> ForgotPassword(ForgotPasswordViewModel model)
        {
            var user = await UserManager.FindByNameAsync(model.ForgotPasswordEmail);
            if (user == null || !(await UserManager.IsEmailConfirmedAsync(user.Id)))
            {
                // Don't reveal that the user does not exist or is not confirmed
                return BadRequest("Invalid Email");
            }

            var code = await UserManager.GeneratePasswordResetTokenAsync(user.Id);
            //var callbackUrl = Url.Action("ResetPassword", "Account", new { userId = user.Id, ResetPasswordCode = code }, protocol: Request.Url.Scheme);
            var callbackUrl = new Uri(model.ForgotPasswordClientURL + "/Account/ResetPassword?userId=" + user.Id + "&ResetPasswordCode=" + HttpUtility.UrlEncode(code));
            //var callbackUrl = new Uri(Url.Link("ResetPassword", new { userId = user.Id, code = code }));
            await UserManager.SendEmailAsync(user.Id, emailTemplates.ResetPassword.ToString(), "Please reset your password by clicking here: <a href=\"" + callbackUrl + "\">link</a>");

            return Ok("Please check your mail to reset password.");
        }

        /// <summary>
        /// This is the submit call post email link
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        [HttpPost]
        [Route("resetpassword")]
        [ApiExplorerSettings(IgnoreApi = false)]
        [AllowAnonymous]
        public async Task<IHttpActionResult> ResetPassword(ResetPasswordViewModel model)
        {
            var user = await UserManager.FindByNameAsync(model.ResetPasswordEmail);
            if (user == null)
            {
                // Don't reveal that the user does not exist
                return BadRequest("Something went wrong.Please try again.");
            }
            var result = await UserManager.ResetPasswordAsync(user.Id, model.ResetPasswordCode, model.ResetPasswordPassword);
            if (result.Succeeded)
            {
                return Ok();
            }

            return BadRequest(result.Errors.FirstOrDefault());
        }


        /// <summary>
        /// Update user's name
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        [HttpPost]
        [Route("UpdateUser")]
        [ApiExplorerSettings(IgnoreApi = false)]
        [Authorize]
        public IHttpActionResult UpdateUser(ProfileViewModel model)
        {
            ApplicationUser user = UserManager.FindById(HttpContext.Current.User.Identity.GetUserId());
            user.ProfileName = model.ProfileName;
            var result = UserManager.Update(user);
            if (result.Succeeded)
            {
                return Ok();
            }
            else
            {
                return BadRequest(result.Errors.FirstOrDefault());
            }
        }

        /// <summary>
        /// GEt profile information of authenticated user
        /// </summary>
        /// <returns></returns>
        [HttpGet]
        [Route("GetProfileDetails")]
        [ApiExplorerSettings(IgnoreApi = false)]
        [Authorize]
        public IHttpActionResult GetProfileDetails()
        {
            ApplicationUser user = UserManager.FindById(HttpContext.Current.User.Identity.GetUserId());

            if (user != null)
            {
                //JObject response = new JObject(
                //new JProperty("Email", user.Email),
                //new JProperty("PhoneNumber", user.PhoneNumber),
                //new JProperty("ReferralCode", user.ReferralCode),
                //new JProperty("ReferralCredits", user.ReferralCredits),
                //new JProperty("ProfileName", user.ProfileName),
                //new JProperty("Referrals", user.Referrals),
                //new JProperty("Vehicles", user.Vehicles),
                //new JProperty("Addresses", user.Addresses)
                // );
                PartialApplicationUser response = new PartialApplicationUser();
                response.Email = user.Email;
                response.PhoneNumber = user.PhoneNumber;
                response.ReferralCode = user.ReferralCode;
                response.ReferralCredits = user.ReferralCredits;
                response.ProfileName = user.ProfileName;
                response.Referrals = user.Referrals;
                response.Vehicles = user.Vehicles;
                response.Addresses = user.Addresses;
                response.ReferreCode = user.ReferreCode;
                return Ok(response);
            }
            else
            {
                return NotFound();
            }
        }

        //GET api/RepairAgents/sendcode/9900014075
        /// <summary>
        /// Send OTP, else sends 400/500
        /// </summary>
        /// <param name="phoneNumber"></param>
        /// <returns></returns>
        [AllowAnonymous]
        [HttpGet]
        [Route("SendCode")]
        [ApiExplorerSettings(IgnoreApi = false)]
        public IHttpActionResult SendCode(string phoneNumber)
        {
            try
            {
                string securityStamp = Guid.NewGuid().ToString("D");
                Regex regex = new Regex(@"^[789]\d{9}$");
                Match match = regex.Match(phoneNumber);
                ApplicationUser user = new ApplicationUser() { PhoneNumber = phoneNumber };
                if (match.Success)
                {
                    //generate Code using class Rfc6238AuthenticationService
                    int code = Rfc6238AuthenticationService.GenerateCode(Encoding.Unicode.GetBytes(securityStamp), phoneNumber);
                    _smsService.SendSMS(phoneNumber, string.Format("One Time Password for completing the registration is {0}. Thanks.", code));
                    var message = new { SecurityStamp = securityStamp };
                    return Ok(message);
                }
                else
                {
                    return BadRequest("Invalid Phone Number");
                }

            }
            catch (Exception ex)
            {
                _logger.Error(ex);
                return InternalServerError(ex);
            }

        }

        /// <summary>
        /// all this method does is verify if OTP is valid or not.
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        [HttpPost]
        [Route("verifycode")]
        [ApiExplorerSettings(IgnoreApi = false)]
        [AllowAnonymous]
        [CheckModelForNullAttribute]
        public Boolean VerifyCode(RegisterViewModel model)
        {
            try
            {
                IEnumerable<string> headerValues;
                if (Request.Headers.Contains("user-origin"))
                {
                    headerValues = Request.Headers.GetValues("user-origin");
                    var id = headerValues.FirstOrDefault();
                }
                else
                {
                    return true;
                }

                Regex regex = new Regex(@"^[789]\d{9}$");
                Match match = regex.Match(model.RegisterPhoneNumber);
                if (match.Success)
                {
                    if (Rfc6238AuthenticationService.ValidateCode(Encoding.Unicode.GetBytes(model.SecurityStamp), model.Code, model.RegisterPhoneNumber))
                    {
                        return true;
                    }
                    else
                    {
                        return false;
                    }

                }
                else
                {
                    return false;
                }
            }
            catch (Exception ex)
            {
                _logger.Error(ex);
                return false;
            }
        }

        #endregion

        #region roles
        /// <summary>
        /// Assign a role to user
        /// </summary>
        /// <param name="id">user id</param>
        /// <param name="rolesToAssign">role to assign</param>
        /// <returns></returns>
        [Authorize(Roles = "Admin")]
        [Route("user/{id:guid}/roles")]
        [HttpPut]
        public async Task<IHttpActionResult> AssignRolesToUser([FromUri] string id, [FromBody] string[] rolesToAssign)
        {

            var appUser = await this.UserManager.FindByIdAsync(id);

            if (appUser == null)
            {
                return NotFound();
            }

            var currentRoles = await this.UserManager.GetRolesAsync(appUser.Id);

            var rolesNotExists = rolesToAssign.Except(this.AppRoleManager.Roles.Select(x => x.Name)).ToArray();

            if (rolesNotExists.Count() > 0)
            {

                ModelState.AddModelError("", string.Format("Roles '{0}' does not exixts in the system", string.Join(",", rolesNotExists)));
                return BadRequest(ModelState);
            }

            IdentityResult removeResult = await this.UserManager.RemoveFromRolesAsync(appUser.Id, currentRoles.ToArray());

            if (!removeResult.Succeeded)
            {
                ModelState.AddModelError("", "Failed to remove user roles");
                return BadRequest(ModelState);
            }

            IdentityResult addResult = await this.UserManager.AddToRolesAsync(appUser.Id, rolesToAssign);

            if (!addResult.Succeeded)
            {
                ModelState.AddModelError("", "Failed to add user roles");
                return BadRequest(ModelState);
            }

            return Ok();
        }
        #endregion

        #region Vehicle CRUD

        /// <summary>
        /// Add vehicle to user profile
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        [HttpPost]
        [Route("Vehicle")]
        [ApiExplorerSettings(IgnoreApi = false)]
        [Authorize]
        [CheckModelForNull]
        public async Task<IHttpActionResult> AddVehicle(VehicleViewModel model)
        {
            model.RegistrationNo = model.RegistrationNo.ToLower();
            if (model.InsuranceValid.Ticks > 0)
                model.IsInsured = true;
            ApplicationUser userDetails = await UserManager.FindByRegistrationNumberAsync(model.RegistrationNo);

            if (userDetails != null)
            {
                //ModelState.AddModelError("Error", "Vehicle Already Exists");
                return BadRequest("Vehicle Already Exists");
            }

            userDetails = UserManager.FindById(HttpContext.Current.User.Identity.GetUserId());
            //If vehicle is not present add it
            if (!(Enum.IsDefined(typeof(VehicleCategory), model.VehicleCategory)))
                model.VehicleCategory = VehicleCategory.bike;
            userDetails.Vehicles.Add(model);
            var result = await UserManager.UpdateAsync(userDetails);

            if (result.Succeeded)
            {
                return Ok();
            }
            else
            {
                return BadRequest(result.Errors.FirstOrDefault());
            }

        }

        /// <summary>
        /// Update vehicle details
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        [HttpPut]
        [Route("Vehicle")]
        [ApiExplorerSettings(IgnoreApi = false)]
        [Authorize]
        public async Task<IHttpActionResult> UpdateVehicle(VehicleViewModel model)
        {
            Boolean bikeExists = false;
            ApplicationUser userDetails = UserManager.FindById(HttpContext.Current.User.Identity.GetUserId());

            if (userDetails == null)
            {
                return NotFound();
            }

            //looping thru vehicles and fetching the selected vehicle
            foreach (VehicleViewModel vehicle in userDetails.Vehicles)
            {
                if (vehicle.RegistrationNo.ToLower() == model.RegistrationNo.ToLower())
                {
                    bikeExists = true;
                    if (model.InsuranceValid.Ticks > 0)
                        vehicle.IsInsured = true;
                    userDetails.Vehicles.Remove(vehicle);
                    userDetails.Vehicles.Add(model);
                    break;
                }
            }
            if (bikeExists)
            {
                var result = await UserManager.UpdateAsync(userDetails);

                if (result.Succeeded)
                {
                    return Ok();
                }
                else
                {
                    return BadRequest(result.Errors.FirstOrDefault());
                }
            }
            else
                return BadRequest("Invalid registration number");
        }

        /// <summary>
        /// get vehicle by user ID. Id is picked from token
        /// </summary>
        /// <returns></returns>
        [HttpGet]
        [Route("GetVehiclesByUser")]
        [ApiExplorerSettings(IgnoreApi = false)]
        [Authorize]
        public IHttpActionResult GetVehiclesByUser()
        {
            ApplicationUser userDetails = UserManager.FindById(HttpContext.Current.User.Identity.GetUserId());
            if (userDetails != null)
                return Ok(userDetails.Vehicles);
            else
                return NotFound();
        }

        #endregion

        #region Address CRUD
        /// <summary>
        /// Add address to user
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        [HttpPost]
        [Route("AddAddress")]
        [ApiExplorerSettings(IgnoreApi = false)]
        [Authorize]
        public async Task<IHttpActionResult> AddAddress(AddressViewModel model)
        {
            ApplicationUser userDetails = UserManager.FindById(HttpContext.Current.User.Identity.GetUserId());

            if (userDetails == null)
            {
                return NotFound();
            }

            //If addresss is not present add it (validated using address tag like home, work etc)
            foreach (AddressViewModel address in userDetails.Addresses)
            {
                if (address.AddressTag == model.AddressTag)
                {
                    return BadRequest(string.Format("Address {0} already exists", model.AddressTag)); //if tag is present return
                }
            }

            //If vehicle is not present add it
            userDetails.Addresses.Add(model);
            var result = await UserManager.UpdateAsync(userDetails);

            if (result.Succeeded)
            {
                return Ok();
            }
            else
            {
                return BadRequest(result.Errors.FirstOrDefault());
            }

        }

        /// <summary>
        /// update user address
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        [HttpPost]
        [Route("UpdateAddress")]
        [ApiExplorerSettings(IgnoreApi = false)]
        [Authorize]
        public async Task<IHttpActionResult> UpdateAddress(AddressViewModel model)
        {
            bool ifAddressTagExists = false;
            ApplicationUser userDetails = UserManager.FindById(HttpContext.Current.User.Identity.GetUserId());

            if (userDetails == null)
            {
                return NotFound();
            }

            //If addresss is not present add it (validated using address tag like home, work etc)
            foreach (AddressViewModel address in userDetails.Addresses)
            {
                if (address.AddressTag == model.AddressTag)
                {
                    userDetails.Addresses.Remove(address);
                    userDetails.Addresses.Add(model);
                    ifAddressTagExists = true;
                    break;
                }
            }

            if (!ifAddressTagExists)
                return BadRequest("Invalid address tag");

            var result = await UserManager.UpdateAsync(userDetails);

            if (result.Succeeded)
            {
                return Ok();
            }
            else
            {
                return BadRequest(result.Errors.FirstOrDefault());
            }

        }

        /// <summary>
        /// get lis of address for specific user.
        /// </summary>
        /// <returns></returns>
        [HttpGet]
        [Route("GetAddressByUser")]
        [ApiExplorerSettings(IgnoreApi = false)]
        [Authorize]
        public IHttpActionResult GetAddressByUser()
        {
            ApplicationUser userDetails = UserManager.FindById(HttpContext.Current.User.Identity.GetUserId());
            if (userDetails != null)
                return Ok(userDetails.Addresses);
            else
                return NotFound();
        }

        /// <summary>
        /// can be used to fetch details of specific address while editing specific address or something
        /// </summary>
        /// <param name="addressTag"></param>
        /// <returns></returns>
        [HttpGet]
        [Route("GetAddressByAddressTag")]
        [ApiExplorerSettings(IgnoreApi = false)]
        [Authorize]
        public IHttpActionResult GetAddressByAddressTag(AddressTags addressTag)
        {
            ApplicationUser userDetails = UserManager.FindById(HttpContext.Current.User.Identity.GetUserId());

            if (userDetails == null)
            {
                return NotFound();
            }

            foreach (AddressViewModel address in userDetails.Addresses)
            {
                if (address.AddressTag == addressTag)
                {
                    return Ok(address);
                }
            }
            return NotFound();
        }

        /// <summary>
        /// delete address for user.
        /// </summary>
        /// <param name="addressTag"></param>
        /// <returns></returns>
        [HttpPost]
        [Route("DeleteAddress")]
        [ApiExplorerSettings(IgnoreApi = false)]
        [Authorize]
        public async Task<IHttpActionResult> DeleteAddress([FromUri]AddressTags addressTag)
        {
            bool ifAddressTagExists = false;
            ApplicationUser userDetails = UserManager.FindById(HttpContext.Current.User.Identity.GetUserId());

            if (userDetails == null)
            {
                return NotFound();
            }

            //If addresss is not present add it (validated using address tag like home, work etc)
            foreach (AddressViewModel address in userDetails.Addresses)
            {
                if (address.AddressTag == addressTag)
                {
                    userDetails.Addresses.Remove(address);
                    ifAddressTagExists = true;
                    break;
                }
            }

            if (!ifAddressTagExists)
                return BadRequest("Invalid address tag");

            var result = await UserManager.UpdateAsync(userDetails);

            if (result.Succeeded)
            {
                return Ok();
            }
            else
            {
                return BadRequest(result.Errors.FirstOrDefault());
            }

        }

        #endregion

        #region Referral CRUD

        /// <summary>
        /// get all the emails referred by user.
        /// </summary>
        /// <returns></returns>
        [HttpGet]
        [Route("GetRefferalsByUser")]
        [ApiExplorerSettings(IgnoreApi = false)]
        [Authorize]
        public IHttpActionResult GetRefferalsByUser()
        {
            ApplicationUser userDetails = UserManager.FindById(HttpContext.Current.User.Identity.GetUserId());
            if (userDetails != null)
                return Ok(userDetails.Referrals);
            else
                return NotFound();
        }

        /// <summary>
        /// add the email reffered by user to user profile.
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        [HttpPost]
        [Route("AddReferralsForUser")]
        [ApiExplorerSettings(IgnoreApi = false)]
        [Authorize]
        public async Task<IHttpActionResult> AddReferralsForUser(InviteFriends model)
        {
            List<string> listofEmails = new List<string>();
            listofEmails.AddRange(model.ReferralEmails.Split(',').ToList());
            ApplicationUser referrer = UserManager.FindById(HttpContext.Current.User.Identity.GetUserId());
            int referralAmount = int.Parse(ConfigurationManager.AppSettings["ReferralAmount"]); //taking the referral amount from config

            foreach (string refereeEmailWithoutCasing in listofEmails)
            {
                string refereeEmail = refereeEmailWithoutCasing.ToLower();
                //validating if user is already refeffered
                var newReferral = (from refer in referrer.Referrals
                                   where refer.ReffaralEmail == refereeEmail
                                   orderby refer.InvitationDate
                                   select refer).FirstOrDefault();

                if (newReferral == null && !refereeEmail.Equals(referrer.Email))
                {
                    //Adding it to current user
                    ReferralViewModel referral = new ReferralViewModel();
                    referral.InvitationDate = DateTime.Now;
                    referral.ReferralAmountTobeCredited = referralAmount;
                    referral.ReferralCredited = false; //Referee will get credit only if this is false. This will be set to true after first booking
                    referral.ReffaralEmail = refereeEmail;

                    try
                    {
                        //TO DO: Logic to change the provider
                        referral.CreditAccount = (Wallet)Enum.Parse(typeof(Wallet), ConfigurationManager.AppSettings["ActivePartner"]);
                    }
                    catch (Exception ex)
                    {
                        Console.Write(ex);
                    }


                    referrer.Referrals.Add(referral);

                    //triggering email - The default identity can send only email to currently logged in user
                    EmailService emailService = new EmailService();
                    IdentityMessage message = new IdentityMessage();
                    message.Destination = refereeEmail;
                    message.Subject = emailTemplates.InviteFriends.ToString();
                    //message.Body = "Your buddy " + user.Email + " has given you the opportunity to shower your ride with some DrivoJoy love, by referring you as a friend. <a href=\"" + Url.Action("Index", "Home", new { referralCode = user.ReferralCode, returnurl = RedirectTo.SignUp }, protocol: Request.Url.Scheme) + "\">Here’s ₹ " + referralAmount + " credit to be used towards the first DrivoJoy service of your ride</a>.To sweeten the deal even further, we’re also offering your friend ₹ " + referralAmount + " credit to be used towards their ride’s next DrivoJoy service.";
                    List<KeyValuePair<string, string>> replacementValues = new List<KeyValuePair<string, string>>();
                    replacementValues.Add(new KeyValuePair<string, string>("FullName", refereeEmail));
                    replacementValues.Add(new KeyValuePair<string, string>("Referrer", referrer.ProfileName));
                    replacementValues.Add(new KeyValuePair<string, string>("ReferralAmount", referralAmount.ToString()));
                    replacementValues.Add(new KeyValuePair<string, string>("ReferralCode", referrer.ReferralCode));
                    var callbackUrl = new Uri(model.InviteFriendsClientURL + "/Home/Index?referralCode=" + referrer.ReferralCode + "&Email=" + refereeEmail + "&returnurl=SignUp");
                    replacementValues.Add(new KeyValuePair<string, string>("SignUpLink", callbackUrl.ToString()));
                    await emailService.sendEmailasync(message, replacementValues);
                }
            }

            var result = await UserManager.UpdateAsync(referrer);

            if (result.Succeeded)
            {
                return Ok("Invite mail sent");
            }
            else
            {
                return BadRequest(result.Errors.FirstOrDefault());
            }
        }

        #endregion

        #region External Login


        // GET api/Account/ExternalLogin?provider=Google&response_type=token&client_id=DrivoJoyConsumerApp&redirect_uri=http://drivojoy.com/authcomplete
        /// <summary>
        /// Step 1 of external login where user is redirected to specific social provider page and is sent back from social login to check in the DB and redirect back to client application.
        /// </summary>
        /// <param name="provider"></param>
        /// <param name="error"></param>
        /// <returns></returns>
        [OverrideAuthentication]
        [HostAuthentication(DefaultAuthenticationTypes.ExternalCookie)]
        [AllowAnonymous]
        [Route("ExternalLogin", Name = "ExternalLogin")]
        public async Task<IHttpActionResult> GetExternalLogin(string provider, string error = null)
        {
            string redirectUri = string.Empty;
            string redirectUriIfRegistered = string.Empty;

            if (error != null)
            {
                return BadRequest(Uri.EscapeDataString(error));
            }

            if (!User.Identity.IsAuthenticated)
            {
                //http://stackoverflow.com/questions/20180562/mvc5-null-reference-with-facebook-login/20948631#20948631
                // to fix the mysterious after 24 hrs failure issue
                //ControllerContext.HttpContext.Session.RemoveAll();
                // Request a redirect to the external login provider
                return new ChallengeResult(provider, this);
            }

            var redirectUriValidationResult = ValidateClientAndRedirectUri(this.Request, ref redirectUri, ref redirectUriIfRegistered);

            if (!string.IsNullOrWhiteSpace(redirectUriValidationResult))
            {
                return BadRequest(redirectUriValidationResult);
            }

            ExternalLoginData externalLogin = ExternalLoginData.FromIdentity(User.Identity as ClaimsIdentity);

            if (externalLogin == null)
            {
                return InternalServerError();
            }

            if (externalLogin.LoginProvider != provider)
            {
                Authentication.SignOut(DefaultAuthenticationTypes.ExternalCookie);
                return new ChallengeResult(provider, this);
            }

            //ApplicationUser user = await UserManager.FindAsync(new UserLoginInfo(externalLogin.LoginProvider, externalLogin.ProviderKey));
            ApplicationUser user = await UserManager.FindByEmailAsync(externalLogin.ExternalLoginEmail.ToLower()); //since couldn't figure out logic to handle registering from consumer app and web

            bool hasRegistered = user != null;

            if (!hasRegistered)
            {
                redirectUri = string.Format("{0}?&returnurl=externallogin&external_access_token={1}&provider={2}&FullName={3}&Email={4}",
                                                redirectUri,
                                                externalLogin.ExternalAccessToken,
                                                externalLogin.LoginProvider,
                                                externalLogin.FullName,
                                                externalLogin.ExternalLoginEmail);
            }
            else
            {
                var returnUrl = GetQueryString(Request, "returnUrl");
                if (string.IsNullOrWhiteSpace(returnUrl))
                {
                    return BadRequest("return URL is required");
                }
                redirectUri = string.Format("{0}?&returnurl={1}&external_access_token={2}&provider={3}&email={4}",
                                redirectUriIfRegistered,
                                returnUrl,
                                externalLogin.ExternalAccessToken,
                                externalLogin.LoginProvider,
                                externalLogin.ExternalLoginEmail);

                redirectUri = redirectUri.Replace("#", "%23");
            }

            return Redirect(redirectUri);

        }


        /// <summary>
        /// validate client against the social provider.
        /// </summary>
        /// <param name="request"></param>
        /// <param name="redirectUriOutput"></param>
        /// <returns></returns>
        private string ValidateClientAndRedirectUri(HttpRequestMessage request, ref string redirectUriOutput, ref string redirectUriOutPutIfRegistered)
        {
            IAuthClientRepository _iAuthClientRepository = new AuthClientRepository();
            Uri redirectUri, redirectUriIfRegistered;

            var redirectUriString = GetQueryString(Request, "redirect_uri");

            var redirectUriIfRegisteredString = GetQueryString(Request, "redirect_uri_If_Registered");

            if (string.IsNullOrWhiteSpace(redirectUriString) || string.IsNullOrWhiteSpace(redirectUriIfRegisteredString))
            {
                return "redirect_uri is required";
            }

            bool validUri = Uri.TryCreate(redirectUriString, UriKind.Absolute, out redirectUri);

            if (!validUri)
            {
                return "redirect_uri is invalid";
            }

            validUri = Uri.TryCreate(redirectUriIfRegisteredString, UriKind.Absolute, out redirectUriIfRegistered);


            if (!validUri)
            {
                return "redirect_uri is invalid";
            }

            var clientId = GetQueryString(Request, "client_id");

            if (string.IsNullOrWhiteSpace(clientId))
            {
                return "client_Id is required";
            }

            var client = _iAuthClientRepository.FindClient(clientId);

            if (client == null)
            {
                return string.Format("Client_id '{0}' is not registered in the system.", clientId);
            }

            //CORS check
            //if (!string.Equals(client.AllowedOrigin, redirectUri.GetLeftPart(UriPartial.Authority), StringComparison.OrdinalIgnoreCase))
            //{
            //    return string.Format("The given URL is not allowed by Client_id '{0}' configuration.", clientId);
            //}

            redirectUriOutput = redirectUri.AbsoluteUri;

            redirectUriOutPutIfRegistered = redirectUriIfRegistered.AbsoluteUri;

            return string.Empty;

        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="request"></param>
        /// <param name="key"></param>
        /// <returns></returns>
        private string GetQueryString(HttpRequestMessage request, string key)
        {
            var queryStrings = request.GetQueryNameValuePairs();

            if (queryStrings == null) return null;

            var match = queryStrings.FirstOrDefault(keyValue => string.Compare(keyValue.Key, key, true) == 0);

            if (string.IsNullOrEmpty(match.Value)) return null;

            return match.Value;
        }

        /// <summary>
        /// validate if external token is generated using the respective social apps.
        /// </summary>
        /// <param name="provider"></param>
        /// <param name="accessToken"></param>
        /// <returns></returns>
        private async Task<ParsedExternalAccessToken> VerifyExternalAccessToken(string provider, string accessToken, string clientId)
        {
            ParsedExternalAccessToken parsedToken = null;

            var verifyTokenEndPoint = "";

            if (provider == "Facebook")
            {
                //You can get it from here: https://developers.facebook.com/tools/accesstoken/
                //More about debug_tokn here: http://stackoverflow.com/questions/16641083/how-does-one-get-the-app-access-token-for-debug-token-inspection-on-facebook
                if (clientId.ToLower() == "drivojoyconsumerapp")
                {
                    var appToken = ConfigurationManager.AppSettings["FaceBookAccessTokenForConsumerApp"];
                    verifyTokenEndPoint = string.Format("https://graph.facebook.com/debug_token?input_token={0}&access_token={1}", accessToken, appToken);
                }
                else
                {
                    var appToken = ConfigurationManager.AppSettings["FaceBookAccessToken"];
                    verifyTokenEndPoint = string.Format("https://graph.facebook.com/debug_token?input_token={0}&access_token={1}", accessToken, appToken);
                }
            }
            else if (provider == "Google")
            {
                if (clientId.ToLower() == "drivojoyconsumerapp")
                {
                    verifyTokenEndPoint = string.Format("https://www.googleapis.com/oauth2/v1/tokeninfo?id_token={0}", accessToken);
                }
                else
                {
                    verifyTokenEndPoint = string.Format("https://www.googleapis.com/oauth2/v1/tokeninfo?access_token={0}", accessToken);
                }
            }
            else
            {
                return null;
            }

            var client = new HttpClient();
            var uri = new Uri(verifyTokenEndPoint);
            var response = await client.GetAsync(uri);

            if (response.IsSuccessStatusCode)
            {
                var content = await response.Content.ReadAsStringAsync();

                dynamic jObj = (JObject)Newtonsoft.Json.JsonConvert.DeserializeObject(content);

                parsedToken = new ParsedExternalAccessToken();

                if (provider == "Facebook")
                {
                    if (clientId.ToLower() == "drivojoyconsumerapp")
                    {
                        parsedToken.user_id = jObj["data"]["user_id"];
                        parsedToken.app_id = jObj["data"]["app_id"];

                        if (!string.Equals(ConfigurationManager.AppSettings["FaceBookAppIdForConsumerApp"], parsedToken.app_id, StringComparison.OrdinalIgnoreCase))
                        {
                            return null;
                        }
                    }
                    else
                    {
                        parsedToken.user_id = jObj["data"]["user_id"];
                        parsedToken.app_id = jObj["data"]["app_id"];

                        if (!string.Equals(Startup.facebookAuthOptions.AppId, parsedToken.app_id, StringComparison.OrdinalIgnoreCase))
                        {
                            return null;
                        }
                    }
                }
                else if (provider == "Google")
                {
                    if (clientId.ToLower() == "drivojoyconsumerapp")
                    {
                        parsedToken.user_id = jObj["email"];
                        parsedToken.app_id = jObj["audience"];

                        if (!string.Equals(ConfigurationManager.AppSettings["GoogleClientIdForApp"], parsedToken.app_id, StringComparison.OrdinalIgnoreCase))
                        {
                            return null;
                        }
                    }
                    else
                    {
                        parsedToken.user_id = jObj["user_id"];
                        parsedToken.app_id = jObj["audience"];

                        if (!string.Equals(Startup.googleAuthOptions.ClientId, parsedToken.app_id, StringComparison.OrdinalIgnoreCase))
                        {
                            return null;
                        }
                    }
                }

            }

            return parsedToken;
        }


        // POST api/Account/RegisterExternal
        /// <summary>
        /// Register external user i.e. insert into DB user details and the social provider.
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        [AllowAnonymous]
        [Route("RegisterExternal")]
        public async Task<IHttpActionResult> RegisterExternal(ExternalLoginConfirmationViewModel model)
        {

            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            //validating if user alreay exists
            ApplicationUser user = await UserManager.FindByEmailAsync(model.ExtenalLoginEmail.ToLower());

            bool hasRegistered = user != null;

            if (hasRegistered)
            {
                return BadRequest("External user is already registered");
            }

            //Validate OTP
            RegisterViewModel otpModel = new RegisterViewModel();
            otpModel.Code = model.Code;
            otpModel.SecurityStamp = model.SecurityStamp;
            otpModel.RegisterPhoneNumber = model.ExternalLoginRegisterPhoneNumber;
            if (!VerifyCode(otpModel))
            {
                return BadRequest("OTP validation failed");
            }

            var verifiedAccessToken = await VerifyExternalAccessToken(model.Provider, model.ExternalAccessToken, model.ClientId);
            if (verifiedAccessToken == null)
            {
                return BadRequest("Invalid Provider or External Access Token");
            }

            int referralCredits = 0;

            //Validating referre code
            if (!string.IsNullOrEmpty(model.ExternalLoginRegisterReferreCode))
            {
                var referre = await UserManager.FindByReferralCodeAsync(model.ExternalLoginRegisterReferreCode);
                if (referre == null)
                {
                    return BadRequest("Invalid referral code");
                }

                var referralCreditDetails = (from refer in referre.Referrals
                                             where refer.ReffaralEmail == model.ExtenalLoginEmail.ToLower()
                                             orderby refer.InvitationDate
                                             select refer).FirstOrDefault();

                //handling if somebody entered referral code directly, which is still a valid case but DB will return null
                if (referralCreditDetails == null)
                {
                    ////validating if somebody trying to use referral for a existing user.
                    //var userForEmail = await UserManager.FindByEmailAsync(model.ExtenalLoginEmail.ToLower());
                    //if (userForEmail != null)
                    //{
                    //    return BadRequest("Email " + model.ExtenalLoginEmail + " is already taken.");

                    //}
                    referralCredits = int.Parse(ConfigurationManager.AppSettings["ReferralAmount"]);
                    //adding the user to the referee who used code directly
                    ReferralViewModel referral = new ReferralViewModel();
                    referral.InvitationDate = DateTime.Now;
                    referral.ReferralAmountTobeCredited = int.Parse(ConfigurationManager.AppSettings["ReferralAmount"]); ;
                    referral.ReferralCredited = false; //Referee will get credit only if this is false. This will be set to true after first booking
                    referral.ReffaralEmail = model.ExtenalLoginEmail.ToLower();

                    //TO DO: Logic to change the provider
                    referral.CreditAccount = (Wallet)int.Parse(ConfigurationManager.AppSettings["ActivePartner"]);

                    referre.Referrals.Add(referral);
                    var referreUpdateResult = await UserManager.UpdateAsync(referre);
                    if (!referreUpdateResult.Succeeded) // on failure
                    {
                        AddErrors(referreUpdateResult);
                        return BadRequest(referreUpdateResult.Errors.FirstOrDefault());
                    }
                }
                else
                {
                    referralCredits = referralCreditDetails.ReferralAmountTobeCredited;
                }
            }

            //ApplicationUser user = await UserManager.FindAsync(new UserLoginInfo(model.Provider, verifiedAccessToken.user_id));

            user = new ApplicationUser { UserName = model.ExtenalLoginEmail, Email = model.ExtenalLoginEmail, PhoneNumber = model.ExternalLoginRegisterPhoneNumber, EmailConfirmed = true, ReferralCode = GenerateReferralCode(8), IsExternalLogin = true, ProfileName = model.ExternalLoginFullName, ReferreCode = string.IsNullOrEmpty(model.ExternalLoginRegisterReferreCode) ? "" : model.ExternalLoginRegisterReferreCode, ReferralCredits = referralCredits, PhoneNumberConfirmed = true };

            IdentityResult result = await UserManager.CreateAsync(user);
            if (!result.Succeeded)
            {
                _logger.Error(DateTime.Now + " - registerexternal " + result.Errors.FirstOrDefault());
                AddErrors(result);
                return BadRequest(result.Errors.FirstOrDefault());
                //return GetErrorResult(result);
            }

            //Send email starts
            //triggering email - The default identity can send only email to currently logged in user
            EmailService emailService = new EmailService();
            IdentityMessage message = new IdentityMessage();
            message.Destination = model.ExtenalLoginEmail.ToLower();
            message.Subject = emailTemplates.SignUpEmail.ToString();
            List<KeyValuePair<string, string>> replacementValues = new List<KeyValuePair<string, string>>();
            replacementValues.Add(new KeyValuePair<string, string>("FullName", model.ExternalLoginFullName));
            replacementValues.Add(new KeyValuePair<string, string>("EmailConfirmationLink", ""));
            await emailService.sendEmailasync(message, replacementValues);
            //Send email ends

            var info = new ExternalLoginInfo()
            {
                DefaultUserName = model.ExtenalLoginEmail,
                Login = new UserLoginInfo(model.Provider, verifiedAccessToken.user_id)
            };

            result = await UserManager.AddLoginAsync(user.Id, info.Login);
            if (!result.Succeeded)
            {
                return GetErrorResult(result);
            }

            //generate access token response
            var accessTokenResponse = GenerateLocalAccessTokenResponse(model.ExtenalLoginEmail, user, model.ClientId);

            return Ok(accessTokenResponse.Result);
        }


        /// <summary>
        /// generate the corrsponding local access token from the social token.
        /// </summary>
        /// <param name="userName"></param>
        /// <param name="info"></param>
        /// <returns></returns>
        private async Task<JObject> GenerateLocalAccessTokenResponse(string userName, ApplicationUser user, string clientId = null)
        {
            var tokenExpiration = TimeSpan.FromDays(1);
            ClaimsIdentity userIdentity = new ClaimsIdentity("JWT");
            userIdentity.AddClaim(new Claim(ClaimTypes.NameIdentifier, user.Id));
            userIdentity.AddClaim(new Claim(ClaimTypes.Name, user.Email));
            userIdentity.AddClaim(new Claim("PhoneNumber", user.PhoneNumber));
            userIdentity.AddClaim(new Claim("ProfileName", string.IsNullOrEmpty(user.ProfileName) ? "" : user.ProfileName));
            userIdentity.AddClaim(new Claim("ReferralCode", user.ReferralCode));
            userIdentity.AddClaim(new Claim("ReferreCode", (user.ReferreCode != null) ? user.ReferreCode : ""));
            userIdentity.AddClaim(new Claim("ReferralCredits", user.ReferralCredits.ToString()));
            userIdentity.AddClaim(new Claim("ProfileName", user.ProfileName));
            userIdentity.AddClaim(new Claim("IsExternalLogin", user.IsExternalLogin.ToString().ToLower()));
            userIdentity.AddClaim(new Claim(ClaimTypes.Role, user.Roles.Contains("Admin") ? "Admin" : ""));
            Client client = null;
            IAuthClientRepository iauthClientRepository = new AuthClientRepository();
            client = iauthClientRepository.FindClient(clientId);

            var props = new AuthenticationProperties()
            {
                IssuedUtc = DateTime.UtcNow,
                ExpiresUtc = DateTime.UtcNow.Add(tokenExpiration),
            };

            var ticket = new AuthenticationTicket(userIdentity, props);

            //Refresh token generation Starts
            CustomJwtFormat accessTokenFormat = new CustomJwtFormat(ConfigurationManager.AppSettings["JWTPath"]);

            var context = new Microsoft.Owin.Security.Infrastructure.AuthenticationTokenCreateContext(
                    Request.GetOwinContext(), accessTokenFormat, ticket);
            context.Ticket.Properties.Dictionary.Add(new KeyValuePair<string, string>("client_id", clientId));

            context.OwinContext.Set<string>("clientAllowedOrigin", client.AllowedOrigin);
            context.OwinContext.Set<string>("clientRefreshTokenLifeTime", client.RefreshTokenLifeTime.ToString());

            await Startup.OAuthServerOptions.RefreshTokenProvider.CreateAsync((context));
            //Refresh token generation ends

            var accessToken = accessTokenFormat.Protect(ticket);

            JObject tokenResponse = new JObject(
                            new JProperty("userName", userName),
                            new JProperty("access_token", accessToken),
                            new JProperty("token_type", "bearer"),
                            new JProperty("expires_in", tokenExpiration.TotalSeconds.ToString()),
                            new JProperty(".issued", ticket.Properties.IssuedUtc.ToString()),
                            new JProperty(".expires", ticket.Properties.ExpiresUtc.ToString()),
                            new JProperty("refresh_token", context.Token),
                            new JProperty("client_Id", clientId)
                    );

            return tokenResponse;
        }

        /// <summary>
        /// Used to generate token for already registered external users(facebook/google).Internally calls GenerateLocalAccessTokenResponse after validation.
        /// </summary>
        /// <param name="email"></param>
        /// <param name="provider"></param>
        /// <param name="externalAccessToken"></param>
        /// <returns></returns>
        [ApiExplorerSettings(IgnoreApi = false)]
        [AllowAnonymous]
        [HttpGet]
        [Route("ObtainLocalAccessToken")]
        public async Task<IHttpActionResult> ObtainLocalAccessToken(string provider, string email, string externalAccessToken, string clientId)
        {
            if (string.IsNullOrWhiteSpace(provider) || string.IsNullOrWhiteSpace(externalAccessToken))
            {
                return BadRequest("Provider or external access token is not sent");
            }

            var verifiedAccessToken = await VerifyExternalAccessToken(provider, externalAccessToken, clientId);
            if (verifiedAccessToken == null)
            {
                return BadRequest("Invalid Provider or External Access Token");
            }

            //ApplicationUser user = await UserManager.FindAsync(new UserLoginInfo(provider, verifiedAccessToken.user_id));

            ApplicationUser user = await UserManager.FindByEmailAsync(email.ToLower());

            bool hasRegistered = user != null;

            if (!hasRegistered)
            {
                return BadRequest("External user is not registered");
            }

            //var info = new ExternalLoginInfo()
            //{
            //    DefaultUserName = email,
            //    Login = new UserLoginInfo(provider, verifiedAccessToken.user_id)
            //};
            //if (info == null)
            //{
            //    ModelState.AddModelError("", "Login failed");

            //    return Json(new
            //    {
            //        Valid = false,
            //        Errors = GetErrorsFromModelState()
            //    });
            //}

            //generate access token response
            var accessTokenResponse = GenerateLocalAccessTokenResponse(user.UserName, user, clientId);

            return Ok(accessTokenResponse.Result);
        }

        #endregion

        #region helper


        private void AddErrors(IdentityResult result)
        {
            foreach (var error in result.Errors)
            {
                ModelState.AddModelError("", error);
            }
        }

        private string GenerateReferralCode(int lengthOfVoucher)
        {
            char[] keys = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789".ToCharArray();
            var random = new Random();
            return Enumerable
                  .Range(1, lengthOfVoucher) // for(i.. ) 
                  .Select(k => keys[random.Next(0, keys.Length - 1)])  // generate a new random char 
                  .Aggregate("", (e, c) => e + c); // join into a string
        }

        #endregion

    }

    class ExternalLoginData
    {
        public string LoginProvider { get; set; }
        public string ProviderKey { get; set; }
        public string FullName { get; set; }
        public string ExternalAccessToken { get; set; }

        public string ExternalLoginEmail { get; set; }

        public static ExternalLoginData FromIdentity(ClaimsIdentity identity)
        {
            if (identity == null)
            {
                return null;
            }

            Claim providerKeyClaim = identity.FindFirst(ClaimTypes.NameIdentifier);

            if (providerKeyClaim == null || String.IsNullOrEmpty(providerKeyClaim.Issuer) || String.IsNullOrEmpty(providerKeyClaim.Value))
            {
                return null;
            }

            if (providerKeyClaim.Issuer == ClaimsIdentity.DefaultIssuer)
            {
                return null;
            }
            string email = string.Empty;
            if (providerKeyClaim.Issuer.ToLower() == "facebook")
            {
                var access_token = identity.FindFirstValue("ExternalAccessToken");
                var fb = new FacebookClient(access_token);
                dynamic myInfo = fb.Get("/me?fields=email"); // specify the email field
                email = myInfo.email;
            }
            else if (providerKeyClaim.Issuer.ToLower() == "google")
            {
                email = identity.FindFirstValue(ClaimTypes.Email);
            }

            return new ExternalLoginData
            {
                LoginProvider = providerKeyClaim.Issuer,
                ProviderKey = providerKeyClaim.Value,
                FullName = identity.FindFirstValue(ClaimTypes.Name),
                ExternalAccessToken = identity.FindFirstValue("ExternalAccessToken"),
                ExternalLoginEmail = email
            };
        }
    }

}
