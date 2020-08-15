using System;
using System.Security.Cryptography;
using System.Text;
using IdentityModel;
using IdentityModel.Jwk;

namespace CryptoBE
{
    class Program
    {
        public static void Main(string[] args)
        {
            Console.WriteLine("Hello Crypto!");

            Console.WriteLine("Public key (JWK)?");
            var jwkString = Console.ReadLine();
            var jwk = new JsonWebKey(jwkString);

            Console.WriteLine("");
            Console.WriteLine("Signature (base64)?");
            var signBase64 = Console.ReadLine();
            var sign = Convert.FromBase64String(signBase64 ?? string.Empty);

            Console.WriteLine("");
            Console.WriteLine("Payload?");
            var payload = Console.ReadLine();
            var encodedPayload = Encoding.UTF8.GetBytes(payload ?? string.Empty);

            var rsa = GetPublicRsaKeyFromJwk(jwk);
            var result = rsa.VerifyData(encodedPayload, sign, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);

            Console.WriteLine("");
            if (result)
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("The provided signature is VALID");
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("The provided signature is INVALID");
            }

            Console.ReadLine();
        }

        private static RSA GetPublicRsaKeyFromJwk(JsonWebKey jwk)
        {
            var e = Base64Url.Decode(jwk.E);
            var n = Base64Url.Decode(jwk.N);

            var rsaKey = RSA.Create();
            var keyParams = new RSAParameters
            {
                Exponent = e,
                Modulus = n,
            };

            rsaKey.ImportParameters(keyParams);
            return rsaKey;
        }
    }
}