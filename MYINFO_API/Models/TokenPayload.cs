using System.Collections.Generic;

namespace MYINFO_API.Models
{
    public class TokenPayload
    {
        public string rt_hash { get; set; }
        public string nonce { get; set; }
        public int iat { get; set; }
        public string iss { get; set; }
        public string at_hash { get; set; }
        public string sub { get; set; }
        public int exp { get; set; }
        public string aud { get; set; }
        public List<string> amr { get; set; }
    }
}
