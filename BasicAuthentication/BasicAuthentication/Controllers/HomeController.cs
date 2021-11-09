using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace BasicAuthentication.Controllers
{
    public class HomeController : Controller
    {
        public IActionResult Index()
        {
            return View();
        }

        [Authorize]
        public IActionResult Secret()
        {
            return View();
        }

        public IActionResult Authenticate()
        {
            var rabbiClaims = new List<Claim>()
            {
                new Claim(ClaimTypes.Name, "rabbi"),
                new Claim(ClaimTypes.Email, "mushfikur1123@gmail.com")
            };

            var rabbiIdentity = new ClaimsIdentity(rabbiClaims, "rabbi");
            var rabbiPrinciple = new ClaimsPrincipal(new[] { rabbiIdentity });

            HttpContext.SignInAsync(rabbiPrinciple);

            return RedirectToAction("Index");
        }
    }
}
