using Jose;
using Microsoft.IdentityModel.Tokens;
using MYINFO_SERVICE.Exceptions;
using Newtonsoft.Json;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
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

        public static string decryptJWE(string jwe)
        {
            string jweDecryptKey;
            if (string.IsNullOrEmpty(jwe))
            {
                // Not authorised or something - either way cannot continue
                throw new SingpassException("Missing JWE data.");
            }

            var jwtSecToken = new JwtSecurityTokenHandler().ReadJwtToken(jwe);

            var file = Path.Combine(Directory.GetCurrentDirectory(), "Resources/private-key.pem");
            jweDecryptKey = File.ReadAllText(file);

            if (string.IsNullOrEmpty(jweDecryptKey))
            {
                // Not authorised or something - either way cannot continue
                throw new SingpassException("Missing key to decrypt JWE payload.");
            }

            // keeping only the payload of the key 
            jweDecryptKey = jweDecryptKey.Replace("-----BEGIN PRIVATE KEY-----", "");
            jweDecryptKey = jweDecryptKey.Replace("-----END PRIVATE KEY-----", "");
            byte[] privateKeyRaw = Convert.FromBase64String(jweDecryptKey);
            // creating the RSA key 
            RSACryptoServiceProvider provider = new RSACryptoServiceProvider();
            provider.ImportPkcs8PrivateKey(new ReadOnlySpan<byte>(privateKeyRaw), out _);
            RsaSecurityKey rsaSecurityKey = new RsaSecurityKey(provider);

            //var jwtDecrypt = JWT.Decode(jwe, rsaSecurityKey, JweAlgorithm.RSA_OAEP, JweEncryption.A128CBC_HS256);

            var key = PemToJwk(jweDecryptKey);
            return key;
        }

        public static string PemToJwk(string key)
        {
            string jwk;

            using (var textReader = new StringReader(key))
            {
                var pubkeyReader = new PemReader(textReader);
                RsaKeyParameters KeyParameters = (RsaKeyParameters)pubkeyReader.ReadObject();
                var e = Base64UrlEncoder.Encode(KeyParameters.Exponent.ToByteArrayUnsigned());
                var n = Base64UrlEncoder.Encode(KeyParameters.Modulus.ToByteArrayUnsigned());
                var dict = new Dictionary<string, string>() {
                        {"e", e},
                        {"kty", "RSA"},
                        {"n", n}
                    };
                var hash = SHA256.Create();
                Byte[] hashBytes = hash.ComputeHash(Encoding.ASCII.GetBytes(JsonConvert.SerializeObject(dict)));
                JsonWebKey jsonWebKey = new JsonWebKey()
                {
                    Kid = Base64UrlEncoder.Encode(hashBytes),
                    Kty = "RSA",
                    E = e,
                    N = n
                };
                JsonWebKeySet jsonWebKeySet = new JsonWebKeySet();
                jsonWebKeySet.Keys.Add(jsonWebKey);
                jwk = JsonConvert.SerializeObject(jsonWebKeySet);
            }

            return jwk;
        }
    }
}
