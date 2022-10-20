using Microsoft.AspNetCore.Mvc;

namespace MYINFO_API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class MyInfoController : ControllerBase
    {
        [HttpGet("getPersonData")]
        public IActionResult RequestInfo()
        {
            var res = "getPersonData";
            return Ok(res);
        }

        [HttpPost("token")]
        public IActionResult GetIdTokenPayload()
        {
            IActionResult response = Unauthorized();
            var res = getIdTokenPayload();

            return response;
        }

        private string getIdTokenPayload()
        {
            return "";
        }
    }
}
