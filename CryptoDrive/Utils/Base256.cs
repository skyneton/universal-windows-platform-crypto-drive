using System.Text;

namespace CryptoDrive.Utils
{
    internal static class Base256
    {
        private const string preStr = " !#$%&'()+,-.0123456789;=@ABCDEFGHIJKLMNOPQRSTUVWXYZ[]^_`abcdefghijklmnopqrstuvwxyz{}~";

        public static string ToString(this byte[] data)
        {
            var builder = new StringBuilder(data.Length);
            foreach (byte b in data)
            {
                builder.Append(b < preStr.Length ? preStr[b] : (char)(b - preStr.Length + 0xA0));
            }
            return builder.ToString();
        }

        public static byte[] ToBytes(this string data)
        {
            var bytes = new byte[data.Length];
            for (var i = 0; i < bytes.Length; i++)
            {
                bytes[i] = data[i] >= 0xA0 ? (byte)(data[i] - 0xA0 + preStr.Length) : Inverse(data[i]);
            }
            return bytes;
        }

        private static byte Inverse(char c)
        {
            return c switch
            {
                ' ' => 0,
                '!' => 1,
                '#' => 2,
                '$' => 3,
                '%' => 4,
                '&' => 5,
                '\'' => 6,
                '(' => 7,
                ')' => 8,
                '+' => 9,
                ',' => 10,
                '-' => 11,
                '.' => 12,
                '0' => 13,
                '1' => 14,
                '2' => 15,
                '3' => 16,
                '4' => 17,
                '5' => 18,
                '6' => 19,
                '7' => 20,
                '8' => 21,
                '9' => 22,
                ';' => 23,
                '=' => 24,
                '@' => 25,
                'A' => 26,
                'B' => 27,
                'C' => 28,
                'D' => 29,
                'E' => 30,
                'F' => 31,
                'G' => 32,
                'H' => 33,
                'I' => 34,
                'J' => 35,
                'K' => 36,
                'L' => 37,
                'M' => 38,
                'N' => 39,
                'O' => 40,
                'P' => 41,
                'Q' => 42,
                'R' => 43,
                'S' => 44,
                'T' => 45,
                'U' => 46,
                'V' => 47,
                'W' => 48,
                'X' => 49,
                'Y' => 50,
                'Z' => 51,
                '[' => 52,
                ']' => 53,
                '^' => 54,
                '_' => 55,
                '`' => 56,
                'a' => 57,
                'b' => 58,
                'c' => 59,
                'd' => 60,
                'e' => 61,
                'f' => 62,
                'g' => 63,
                'h' => 64,
                'i' => 65,
                'j' => 66,
                'k' => 67,
                'l' => 68,
                'm' => 69,
                'n' => 70,
                'o' => 71,
                'p' => 72,
                'q' => 73,
                'r' => 74,
                's' => 75,
                't' => 76,
                'u' => 77,
                'v' => 78,
                'w' => 79,
                'x' => 80,
                'y' => 81,
                'z' => 82,
                '{' => 83,
                '}' => 84,
                '~' => 85,
                _ => 0,
            };
        }
    }
}
