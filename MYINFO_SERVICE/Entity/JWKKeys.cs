using Newtonsoft.Json;
using System.Collections.Generic;

namespace MYINFO_SERVICE.Entity
{
    public class JWKKeys
    {
        [JsonProperty("keys")]
        private List<JWK> keys;
    }
}
