using MYINFO_SERVICE.Exceptions;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace MYINFO_SERVICE.Services
{
    public class MyInfoSecurityHelper
    {
        private static RandomGenerator _randomGenerator = new RandomGenerator();

        /// <summary>
        /// Used for nonce. Cryptographically random
        /// </summary>
        public static int GetRandomInteger()
        {
            var randomValue = _randomGenerator.Next(0, int.MaxValue);
            return randomValue;
        }

        public static string GenerateAuthorizationHeader(string defaultHeader, string bearer)
        {
            string authHeader;

            if (bearer != null)
            {
                authHeader = ApplicationConstant.PKI_SIGN + " " + defaultHeader + "," + bearer;
            }
            else
            {
                authHeader = ApplicationConstant.PKI_SIGN + " " + defaultHeader;
            }

            return authHeader;
        }

        public static string GenerateBaseString(string method, string url, string baseParams)
        {
            string basestring = method.ToUpper() + "&" + url + "&" + baseParams;
            return basestring;
        }

        public static string GenerateSignature(string input, string privateKeyXml)
        {
            string hashSignatureBase64;

            var rsaProvider = new RSACryptoServiceProvider();
            rsaProvider.FromXmlString(privateKeyXml);
            var rsaFormatter = new RSAPKCS1SignatureFormatter(rsaProvider);
            rsaFormatter.SetHashAlgorithm("SHA256");
            var sha256 = new SHA256Managed();
            var hashSignatureBytes = rsaFormatter.CreateSignature(sha256.ComputeHash(Encoding.UTF8.GetBytes(input)));
            hashSignatureBase64 = Convert.ToBase64String(hashSignatureBytes);

            return hashSignatureBase64;
        }

        public static object DecodeToken(string token)
        {
            string encodedPayload = token.Split('.')[1];
            string decodedPayload = Encoding.ASCII.GetString(FromBase64Url(encodedPayload));
            object jsonObject = JsonConvert.DeserializeObject(decodedPayload);
            return jsonObject;
        }

        public static bool VerifyToken(string token, AsymmetricAlgorithm rsaService)
        {
            bool signVerified = false;
            string[] tokenParts = token.TrimStart('"').TrimEnd('"').Split('.');

            var sha256 = SHA256.Create();
            byte[] hash = sha256.ComputeHash(Encoding.UTF8.GetBytes(tokenParts[0] + '.' + tokenParts[1]));

            var rsaDeformatter = new RSAPKCS1SignatureDeformatter(rsaService);
            rsaDeformatter.SetHashAlgorithm("SHA256");
            var signature = FromBase64Url(tokenParts[2]);

            if (rsaDeformatter.VerifySignature(hash, signature))
            {
                signVerified = true;
            }

            return signVerified;
        }

        private static byte[] FromBase64Url(string base64Url)
        {
            string padded = base64Url.Length % 4 == 0
                ? base64Url : base64Url + "====".Substring(base64Url.Length % 4);
            string base64 = padded.Replace("_", "/")
                                  .Replace("-", "+");
            return Convert.FromBase64String(base64);
        }

        public static string decryptJWE(string jweTokenBase64Url)
        {
            if (string.IsNullOrEmpty(jweTokenBase64Url))
            {
                // Not authorised or something - either way cannot continue
                throw new SingpassException("Missing JWE data.");
            }

            var pathPrivateKey = Path.Combine(Directory.GetCurrentDirectory(), "Resources/private-key.pem");
            var pathPublicKey = Path.Combine(Directory.GetCurrentDirectory(), "Resources/public-cert.pem");

            string rsaPrivateKey = File.ReadAllText(pathPrivateKey);
            string rsaPublicKey = File.ReadAllText(pathPublicKey);

            if (string.IsNullOrEmpty(rsaPrivateKey))
            {
                // Not authorised or something - either way cannot continue
                throw new SingpassException("Missing key to decrypt JWE payload.");
            }

            // decode JWE and Private key https://dotnetfiddle.net/30JFo0
            string jweDecryptedPayload = jweRsaDecryptFromBase64UrlToken(rsaPrivateKey, jweTokenBase64Url);
            Console.WriteLine("jweDecryptedPayload: " + jweDecryptedPayload);

            // verify Public key
            //var rsaPublic = Decode(jweDecryptedPayload, rsaPublicKey);
            var decodedJwt = Jose.JWT.Decode(jweDecryptedPayload, rsaPublicKey, Jose.JweAlgorithm.RSA_OAEP_256, Jose.JweEncryption.A128CBC_HS256);

            // check for expired
            Console.WriteLine("\ncheck for expired token");
            Console.WriteLine("actual time: " + DateTime.Now);

            var tokenInfo = GetTokenInfo(jweDecryptedPayload);

            return jweDecryptedPayload;
        }
        public static string jweRsaDecryptFromBase64UrlToken(string rsaPrivateKey, string jweTokenBase64Url)
        {
            RSA rsaAlg = RSA.Create();
            byte[] privateKeyByte = getRsaPrivateKeyEncodedFromPem(rsaPrivateKey);
            int _out;
            rsaAlg.ImportPkcs8PrivateKey(privateKeyByte, out _out);
            string json = "";
            try
            {
                json = Jose.JWT.Decode(jweTokenBase64Url, rsaAlg);
            }
            catch (Jose.EncryptionException)
            {
                Console.WriteLine("*** Error: payload corrupted or wrong private key ***");
                // throws: Jose.EncryptionException: Unable to decrypt content or authentication tag do not match.
            }
            return json;
        }

        private static byte[] getRsaPrivateKeyEncodedFromPem(string rsaPrivateKeyPem)
        {
            string rsaPrivateKeyHeaderPem = "-----BEGIN PRIVATE KEY-----\n";
            string rsaPrivateKeyFooterPem = "-----END PRIVATE KEY-----";
            string rsaPrivateKeyDataPem = rsaPrivateKeyPem.Replace(rsaPrivateKeyHeaderPem, "").Replace(rsaPrivateKeyFooterPem, "").Replace("\n", "");
            return FromBase64Url(rsaPrivateKeyDataPem);
        }

        //public static string Decode(string token, string key, bool verify = true)
        //{
        //    string[] parts = token.Split('.');
        //    string header = parts[0];
        //    string payload = parts[1];
        //    byte[] crypto = FromBase64Url(parts[2]);

        //    string headerJson = Encoding.UTF8.GetString(FromBase64Url(header));
        //    JObject headerData = JObject.Parse(headerJson);

        //    string payloadJson = Encoding.UTF8.GetString(FromBase64Url(payload));
        //    JObject payloadData = JObject.Parse(payloadJson);

        //    if (verify)
        //    {
        //        key = key.Replace("-----BEGIN CERTIFICATE-----", "");
        //        key = key.Replace("-----END CERTIFICATE-----", "");
        //        var keyBytes = Convert.FromBase64String(key);

        //        AsymmetricKeyParameter asymmetricKeyParameter = PublicKeyFactory.CreateKey(keyBytes);
        //        RsaKeyParameters rsaKeyParameters = (RsaKeyParameters)asymmetricKeyParameter;
        //        RSAParameters rsaParameters = new RSAParameters();
        //        rsaParameters.Modulus = rsaKeyParameters.Modulus.ToByteArrayUnsigned();
        //        rsaParameters.Exponent = rsaKeyParameters.Exponent.ToByteArrayUnsigned();
        //        RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
        //        rsa.ImportParameters(rsaParameters);

        //        SHA256 sha256 = SHA256.Create();
        //        byte[] hash = sha256.ComputeHash(Encoding.UTF8.GetBytes(parts[0] + '.' + parts[1]));

        //        RSAPKCS1SignatureDeformatter rsaDeformatter = new RSAPKCS1SignatureDeformatter(rsa);
        //        rsaDeformatter.SetHashAlgorithm("SHA256");
        //        if (!rsaDeformatter.VerifySignature(hash, FromBase64Url(parts[2])))
        //            throw new ApplicationException(string.Format("Invalid signature"));
        //    }

        //    return payloadData.ToString();
        //}

        protected static Dictionary<string, string> GetTokenInfo(string token)
        {
            var TokenInfo = new Dictionary<string, string>();

            var handler = new JwtSecurityTokenHandler();
            var jwtSecurityToken = handler.ReadJwtToken(token);
            var claims = jwtSecurityToken.Claims.ToList();

            foreach (var claim in claims)
            {
                TokenInfo.Add(claim.Type, claim.Value);
            }

            return TokenInfo;
        }
    }
}
