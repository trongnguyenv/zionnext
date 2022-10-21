using Newtonsoft.Json;

namespace MYINFO_SERVICE.Entity
{
    public class JWK
    {
        [JsonProperty("kty")]
        public string kty { get; set; }

        [JsonProperty("d")]
        public string d { get; set; }

        [JsonProperty("use")]
        public string use { get; set; }

        [JsonProperty("crv")]
        public string crv { get; set; }

        [JsonProperty("kid")]
        public string kid { get; set; }

        [JsonProperty("x")]
        public string x { get; set; }

        [JsonProperty("y")]
        public string y { get; set; }

        [JsonProperty("alg")]
        public string alg { get; set; }
    }
}
