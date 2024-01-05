using Microsoft.AspNetCore.Mvc;
using System.Net.Mail;
using Umbraco.Cms.Core.Cache;
using Umbraco.Cms.Core.Logging;
using Umbraco.Cms.Core.Routing;
using Umbraco.Cms.Core.Security;
using Umbraco.Cms.Core.Services;
using Umbraco.Cms.Core.Web;
using Umbraco.Cms.Infrastructure.Persistence;
using Umbraco.Cms.Web.Common.Security;
using Umbraco.Cms.Web.Website.Controllers;

namespace HowToChangeAMembersEmail.Web
{
    public sealed class AuthenticationSurfaceController : SurfaceController
    {
        IMemberService _memberService;
        IMemberManager _memberManager;
        IMemberSignInManager _memberSignInManager;
        IHttpContextAccessor _httpContextAccessor;

        public AuthenticationSurfaceController(
            IUmbracoContextAccessor umbracoContextAccessor,
            IUmbracoDatabaseFactory databaseFactory,
            ServiceContext services,
            AppCaches appCaches,
            IProfilingLogger profilingLogger,
            IPublishedUrlProvider publishedUrlProvider,

            IMemberService memberService,
            IMemberManager memberManager,
            IMemberSignInManager memberSignInManager,
            IHttpContextAccessor httpContextAccessor
            ) : base(umbracoContextAccessor, databaseFactory, services, appCaches, profilingLogger, publishedUrlProvider)
        {
            _memberService = memberService;
            _memberManager = memberManager;
            _memberSignInManager = memberSignInManager;
            _httpContextAccessor = httpContextAccessor;
        }

        [HttpPost]
        public IActionResult Login(string member_email, string member_password, string redirect_url = "/")
        {
            MailAddress mailAddress = new(member_email);
            var email = mailAddress.ToString().ToLower();
            var member = _memberService.GetByEmail(email);

            if (member == null)
            {
                // Create a new member if not exists
                var memberIdentityUser = MemberIdentityUser.CreateNew(
                        username: email,
                        email: email,
                        memberTypeAlias: "Member",
                        isApproved: true,
                        name: mailAddress.User);

                if (_memberManager.CreateAsync(
                    user: memberIdentityUser,
                    password: member_password).Result.Succeeded)
                {
                    _memberManager.AddToRolesAsync(
                    user: memberIdentityUser,
                    roles: new List<string>() { "Everyone" }).Wait();

                    return Login(member_email, member_password, redirect_url);
                }
            }
            else if (_memberManager.ValidateCredentialsAsync(username: member.Username, password: member_password).Result)
            {
                // Validate member credentials
                var memberIdentityUser = _memberManager.FindByNameAsync(member.Username).Result;
                _memberSignInManager.SignInAsync(user: memberIdentityUser, isPersistent: true).Wait();
            }

            return Redirect(redirect_url);
        }

        [HttpPost]
        public IActionResult Logout()
        {
            _memberSignInManager.SignOutAsync();
            _httpContextAccessor.HttpContext.Session.Clear();
            return RedirectToCurrentUmbracoPage();
        }



        [HttpPost]
        public IActionResult ChangeEmail(string new_member_email, string member_password)
        {
            MailAddress mailAddress = new(new_member_email);
            var email = mailAddress.ToString().ToLower();
            var existingMember = _memberService.GetByEmail(email);
            var currentMember = _memberService.GetByUsername(_memberManager.GetCurrentMemberAsync().Result.UserName);

            if (_memberManager.ValidateCredentialsAsync(username: currentMember.Username, password: member_password).Result
                && existingMember?.Username != currentMember.Username)
            {
                if (existingMember != null)
                {
                    existingMember.Username = $"{existingMember.Username}.{currentMember.Id}";
                    existingMember.Email = $"{existingMember.Email}.{currentMember.Id}";
                    existingMember.DeleteDate = DateTime.Now;
                    existingMember.IsLockedOut = true;
                    existingMember.IsApproved = false;
                    _memberService.Save(existingMember);
                    // lock the existingMember
                }
                currentMember.Username = email;
                currentMember.Email = email;
                _memberService.Save(currentMember);
            }


            return RedirectToCurrentUmbracoPage();
        }
    }
}
