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
            string id_token = "eyJjdHkiOiJKV1QiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiYWxnIjoiUlNBLU9BRVAiLCJraWQiOiJiemEwZFhmNkZqbGExRlFyVkttQVR1WmI5LTRNOTBMeER1ZjN1akxZYnFnIn0.CiVJ5OyNNOLDcDdGYGf8jmytTxndZgKYl3osN0tLL6-R9TPZsoxuI1gltGMjlJJHN4nzAgluhOtzlV2Ou6Mq9L7eP78iwWJ_2v7Fqa5ekrFbRYC1X1jvu1eiGMusJMXwSo0xLmiN5hzCW88vwkl55XWVDkyF4LsDGLu803mU8ZuP_CWWsm0UXOqwSsolNI31-vicbTiAbcRfXiHJNdeJIDgtFPlgvcNXlO77-oxV_SzkOCbcG_4rHOvf5mG5jRnumgenE5FQiujc6XMpMbWr8uuLjkspeeH4Wk8JnwB8DXlOCSzm_gt7eaTqLkVdE9KtX4t49Pdg5JSrVraxlS9pYQ.AhDWGNCeo7MWzm0oso_4mQ.lrBeNbPQMSPqtwy7VTtVQPPIqSjeeOCTs3SplJYLlG3CLaz4fvoO5nzZTsZ058RDFb7g4qVlWkLAqXo5uWyVCXE9pkwnPJHvh2uMuI2SWjeeiEHenDTlu1KWtvAS0-LWpSRmzWgtNq9LksDiT1bW0hZEhvrrAVLgi-fPxdCk9iY0MVwFB76bWJWeSZ-jmztlUjco5KZTz4X9rOOBi9-O8y9CKlgWo0wxiBpm9v5hiMdYelcN3TODRfXobwwhmUqs7TmOHsr89vkAgrGNkNhPfdHSXSg3_FsWLzMOTWTankOGSZDkkksU7tmo_BgTxBd2TOEefgWFlij0jmKuOcrCoJSt5mhBTTTFpx2lNa4NksHX_5xjYrekxEhXcU5ZqixXonlyhaL-6wQykYjXwnpYF8dZJSCyWkXm5V5_OAk2wO8y6Hz9hdFBLZWW6Q1bnfu1PkFp3JkJ5AHkcbPpoLijpqyhzeJDI1G-0zOhKUCBye8s4eNnk0TPFxgXdhdqfvKWPXEpaoMSdw4x9b1rIPKFCBcX2rS7GKgeVyvekzqf_QMkltANDPU-o6ZrhNh_VKYTl2QxS3i-epHwThAJZrrCQ0RPRdmb4U2u6VrChiSa93douqZC6sIprdGWxpp2PzwWH93BG_X4-mRWlDt1taX2jEXNMMSDTwhH00UOQjeIZReDcLMzJlj_Q6-9OBzjyxGX78tYh7iOTlOT1uAjG5Fw9W3J38MQxj_Xf6qpcaltbe-_RotRfiB57UL0rJ7Ly95VNdkVczE2WQ60AugjOj79p_OmDBZSW63mAhLGSNBDgf6fYz0cLloOkJB7cqiKm6RGQ90RIeGPuleZuGeZ4HAQoi0QL93qq-o1cTFWG-y_GnApE2BcEWxmN9v1vYooMW7GinnI72VNrlYInHwOsEfGot8pRsOBOO9SdUMBCAXehcibHPGLOnTKr1YedXIzF5V45J6u8nRTO8lsbAKILsx3eugCAeyHQkQDmFsstrJTxTB4yz58ehrsRuhQKZOZTRgG.0tKZqfeJ1fJ5wV7sYMEoWA";
            GetIdTokenPayload(id_token);

            return Ok(id_token);
        }

        protected void GetIdTokenPayload(string id_token)
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
        }
    }
}
