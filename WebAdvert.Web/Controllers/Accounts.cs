using Amazon.AspNetCore.Identity.Cognito;
using Amazon.Extensions.CognitoAuthentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using WebAdvert.Web.Models.Accounts;

namespace WebAdvert.Web.Controllers
{
    public class Accounts : Controller
    {
        private readonly SignInManager<CognitoUser> _signInManager;
        private readonly UserManager<CognitoUser> _userManager;
        private readonly CognitoUserPool _pool;

        public Accounts(SignInManager<CognitoUser> signInManager, UserManager<CognitoUser> userManager, CognitoUserPool pool) 
        {
            _signInManager = signInManager;
            _userManager = userManager;
            _pool = pool;
        }

        public IActionResult Index()
        {
            return RedirectToAction("SignUp");
        }

        public async Task<IActionResult> Signup()
        {
            var model = new SignupModel();
            return View(model);
        }

        [HttpPost]
        public async Task<IActionResult> Signup(SignupModel model)
        {
            if (ModelState.IsValid) 
            {
                CognitoUser user = _pool.GetUser(model.Email);
                if (user.Status != null)
                {
                    ModelState.AddModelError("User Exists", "User with this email already exists");
                    return View(model);
                }

                user.Attributes.Add(CognitoAttribute.Name.AttributeName, model.Email);
                IdentityResult createdUserResult = await _userManager.CreateAsync(user, model.Password);

                if (createdUserResult.Succeeded)
                {
                    return RedirectToAction("Confirm");
                }
                else 
                {
                    ModelState.AddModelError("Can not create the User", "Some error while tryimg to create the user");
                    return View(model);
                }
            }

            return View();
        }


        public async Task<IActionResult> Confirm() 
        {
            var model = new ConfirmModel();
            return View(model);
        }

        [HttpPost]
        public async Task<IActionResult> Confirm(ConfirmModel model)
        {
            if (ModelState.IsValid)
            {
                CognitoUser user = await _userManager.FindByEmailAsync(model.Email);

                if (user == null) 
                {
                    ModelState.AddModelError("NotFound", "User not found");
                    return View(model);
                }

                IdentityResult confirmUserResult = await (_userManager as CognitoUserManager<CognitoUser>).ConfirmSignUpAsync(user, model.Code, true);
                if (confirmUserResult.Succeeded)
                {
                    return RedirectToAction("Index", "Home");
                }
                else 
                {
                    foreach (var item in confirmUserResult.Errors) 
                    {
                        ModelState.AddModelError(item.Code, item.Description);
                    }

                    return View(model);
                }

            }

            return View(model);
        }

        public async Task<IActionResult> Login() 
        {
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> Login(LoginModel model) 
        {
            if (ModelState.IsValid) 
            {
                var result = await _signInManager.PasswordSignInAsync(model.Email, model.Password, model.RememberMe, false);

                if (result.Succeeded)
                {
                    return RedirectToAction("Index", "Home");
                }
                else 
                {
                    ModelState.AddModelError("Login Error", "Email and password do not match");
                }
            }

            return View("Login" ,model);
        }
    }
}
