using System.Security.Cryptography;
using System.Text;

namespace CryptoDrive.Utils
{
    internal static class HexAlgorithm
    {
        public static byte[] Sha256(byte[] data) => SHA256.HashData(data);
        public static byte[] Md5(byte[] data) => MD5.HashData(data);
        
        public static string ByteArrayToHex(byte[] data, bool upperCase = true)
        {
            if (data.Length == 0) return "";
            var builder = new StringBuilder(data.Length << 1);
            foreach(var b in data)
            {
                builder.Append(ComputeHex(b >> 4, upperCase));
                builder.Append(ComputeHex(b & 0xF, upperCase));
            }
            return builder.ToString();
        }

        public static byte[] HexToByteArray(string hex)
        {
            if (hex.Length == 0) return [];
            if(hex.Length % 2 != 0) return Encoding.UTF8.GetBytes(hex);
            var result = new byte[hex.Length >> 1];
            for(var i = 0; i < result.Length; i++)
            {
                result[i] = (byte)(ComputeHex(hex[i << 1]) << 4 | ComputeHex(hex[(i << 1) + 1]));
            }
            return result;
        }

        private static char ComputeHex(int b, bool upperCase)
        {
            if (b < 10) return (char)('0' + b);
            return (char)((upperCase ? 'A' : 'a') + b - 10);
        }

        private static int ComputeHex(char c)
        {
            if (c <= '9') return c & 15;
            if (c <= 'Z') return c - 'A' + 10;
            if (c <= 'z') return c - 'a' + 10;
            return 0;
        }
    }
}
