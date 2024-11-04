using System.Text;

namespace CryptoDrive.Utils
{
    internal static class StringAlgorithm
    {
        public static byte[] ToBytes(string s)
        {
            var buf = new ByteBuf();
            foreach (char c in s)
            {
                buf.WriteVarInt(c);
            }
            return buf.GetBytes();
        }

        public static string ToString(byte[] data)
        {
            var buf = new ByteBuf(data);
            var builder = new StringBuilder(data.Length);
            while(buf.Length > 0)
            {
                builder.Append((char)buf.TryReadVarInt());
            }
            return builder.ToString();
        }
    }
}
