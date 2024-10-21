using CryptoDrive.Cryptography.Aes;
using CryptoDrive.Utils;
using System;
using System.Text;

namespace CryptoDrive.Cryptography
{
    internal static class SimpleCrypt
    {
        internal static byte[] Reverse(byte[] input, byte key)
        {
            if (input.Length == 0) return input;
            var result = new byte[input.Length];
            for (var i = 0; i < input.Length; i++)
            {
                var v = input[i];
                result[i] = (byte)~((v << 4 | v >> 4) ^ key);
            }
            return result;
        }

        internal static byte[] Origin(byte[] input, byte key)
        {
            var result = new byte[input.Length];
            for(var i = 0; i < input.Length; i++)
            {
                var v = (byte)~input[i] ^ key;
                result[i] = (byte)(v << 4 | v >> 4);
            }
            return result;
        }

        internal static AesCipher GetCipher(byte[] cryptoKey, byte key)
        {
            var k = new byte[16];
            var v = new byte[16];
            if(key < 128)
            {
                Buffer.BlockCopy(cryptoKey, 0, k, 0, 16);
                Buffer.BlockCopy(cryptoKey, 16, v, 0, 16);
                v[key & 0xF] = key;
            }else
            {
                Buffer.BlockCopy(cryptoKey, 32, k, 0, 16);
                Buffer.BlockCopy(cryptoKey, 48, v, 0, 16);
                v[key & 0xF] = (byte)(key >> 4);
            }
            return new AesCipher(k, v);
        }

        internal static byte[] GetCryptoKey(string key)
        {
            byte[] result = new byte[64];
            var keyBytes = Encoding.UTF8.GetBytes(key);
            var sha = HexAlgorithm.Sha256(keyBytes);
            var md5 = HexAlgorithm.Md5(keyBytes);
            Buffer.BlockCopy(md5, 0, result, 0, 16);
            Buffer.BlockCopy(HexAlgorithm.Md5(sha), 0, result, 16, 16);
            Buffer.BlockCopy(sha, 0, result, 32, 32);
            return result;
        }
    }
}
