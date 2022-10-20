using Newtonsoft.Json;
using System.Collections.Generic;

namespace MYINFO_API.Models
{
    public class JWKKeys
    {
        [JsonProperty("keys")]
        private List<JWK> keys;
    }
}
