using Microsoft.AspNetCore.Mvc;
using MYINFO_SERVICE.Services;
using System;

namespace MYINFO_API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class TokenController : ControllerBase
    {
        [HttpGet]
        public IActionResult GetIdTokenPayload()
        {
            string id_token = "eyJjdHkiOiJKV1QiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiYWxnIjoiUlNBLU9BRVAiLCJraWQiOiJiemEwZFhmNkZqbGExRlFyVkttQVR1WmI5LTRNOTBMeER1ZjN1akxZYnFnIn0.kjkd8-TBE1z9Ltd8V075EHNF-7GPD8RwkwjVtnzWrTQwJzqTtACMUSoTn_FBirwvCvyZxfzhiXNzOqXOrKlKO6x8wNbg45P5wXFrMinG2-Ljudipr1OdwBfWr3FCs2-LoSyEuy2hGPCLZ02ny9nHjHDtzebkE91Ek5xWPflP2MEUuoBgUbE2yGHtbnk_NlyI1T2UJobydDnpkschTaOs2TD7NVrpu8S2JB0CJ2AMzWzaCeeBoThzsQouK_jT2GR-AMGHQJnRFpqnpBFdt1YCIiMsbVU07g54bJCRLLdDnkdBnQ2grZUXAZUftjGDsaM-LmrwYXmgrgeukubSPzhTAw.xURtuOb_aF59G6bcUW8Qvg.xBTjRnZF0YcQC3GA1s5-uC5wp029cYIwFbCwx_Cad6zPQTLVk5Gjb4a6H9Kp_LeEl5xPUjibnrIstrqMjkWZt7Vs0vG0ltbL0qa2HZW-2MCxdMjV_QG80FWe60Se-9tKqq7Xc_4olepQGc08NLKXz2tYk7HFIqILGX_N9BX00tUuPZusnhsGQEWxxs_63bcHtfJtvprQR-Z87sRgE8gWJ6em477-QewngIR1aK6dnfsKDEpP9I9LL5If4o6SXY347X_02uwuxax6Sf2vvjLEeTA-iWD6YtdvUYGLJ41tu282O4MGssys-hxLVIIMsWIj11br22fDpvqEAu4-mWRrYHoDj2MZY5v9rmSmphq3J_Rq6_BhzGD5DP6kQFuhCGobyqKbBp4XGPWDgLyXykXA3Md0rIw4vaeFu6iRf8B9CY34b3mUZXgi0xkueP-9RVZOibAYAdQP5SP9S4y0LOsbzmM7RqqRsY6yHeUTCrp-TwCcT9puyfl4_dK2kMuF4vXSMWHwP_0sgoJSqlW3kzby5VlMkg-d2dpZleoj4vxyuFkL2b92fIOaEhPOSHfje5_K_-AfPoS18f8IfdMRQOG4gG9R6nUpZ-QeU5BOKiJgDX17voav2rgzC-SxahSKIO5S9pwadECtr1HhU8pjpEARpwY31w-SjbacJE0rxl1z66pRn-FhCuP7pjn2NR9gSbzUggoDtuREzaLQ3mXrPplgwB0bLEPR3lgul2TWfz6jqNN50fF0sH4Qu7IAef-657MZhBDiP1vp29Lwa4DCcSeA_lh7Bwuimq7hD5Ip1C1Ssgr3gQTviCls1MuhyZF2ublctbFUnt3ptbIMc7BE-9cvPGijBlI6DEpQor_oUly7wdrf59OIXa4qz4jtIIFRL-nUVrz0pt6qEeYsxtuiWDEm067n98xrU6K6-pIt78G-Uljo7VL_OOjrnwIdnCnYtyAsaoSeBDqy1tiB7aW1ovNZe3bMYv08DwkqwJZTGN8ch4y21CVXY0pVuP9kS5uJK7gw.sfWkQ8n9-_lzBGha1YweTw";
            var tokens = GetIdTokenPayload(id_token);

            return Ok(tokens);
        }

        protected string GetIdTokenPayload(String id_token)
        {
            string decryptedJwe;
            try
            {
                decryptedJwe = MyInfoSecurityHelper.decryptJWE(id_token);
            }
            catch (Exception ex)
            {
                throw ex;
            }

            return decryptedJwe;
        }
    }
}
