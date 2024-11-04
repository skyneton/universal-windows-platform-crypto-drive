using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Text;

namespace CryptoDrive.Utils
{
    internal static class Base256
    {
        private const string preStr = " !#$%&'()+,-.0123456789;=@ABCDEFGHIJKLMNOPQRSTUVWXYZ[]^_`{}~ ¡¢£¤¥¦§¨©ª«¬®¯°±²³´µ¶·¸¹º»¼½¾¿ÀÁÂÃÄÅÆÇÈÉÊËÌÍÎÏÐÑÒÓÔÕÖ×ØÙÚÛÜÝÞßĀĂĄĆĈĊČĎĐĒĔĖĘĚĜĞĠĢĤĦĨĪĬĮİĲĴĶĸĹĻĽĿŁŃŅŇŉŊŌŎŐŒŔŖŘŚŜŞŠŢŤŦŨŪŬŮŰŲŴŶŸŹŻŽƀƁƂƄƆƇƉƊƋƍƎƏƐƑƓƔƕƖƗƘƚƛƜƝƞƟƠƢƤƦƧƩƪƫƬƮƯƱƲƳƵƷƸƺƻƼƾƿǀǁǂǃǄǇǊǍǏǑǓǕǗǙǛǞǰǴǸǺ";
        private static readonly ReadOnlyDictionary<char, byte> reverseMap;
        static Base256()
        {
            var dict = new Dictionary<char, byte>();
            for (var i = 0; i < preStr.Length; i++)
            {
                dict[preStr[i]] = (byte)i;
            }
            reverseMap = new ReadOnlyDictionary<char, byte>(dict);
        }

        public static string ToString(this byte[] data)
        {
            var builder = new StringBuilder(data.Length);
            foreach (byte b in data)
            {
                builder.Append(preStr[b]);
            }
            return builder.ToString();
        }

        public static byte[] ToBytes(this string data)
        {
            var bytes = new byte[data.Length];
            for (var i = 0; i < bytes.Length; i++)
            {
                bytes[i] = reverseMap.GetValueOrDefault(data[i]);
            }
            return bytes;
        }
    }
}
