using System.Collections;
using System.Collections.Generic;

namespace CryptoDrive.FS
{
    internal class DirectoryEntryComparer : IComparer<DictionaryEntry>
    {
        public int Compare(DictionaryEntry x, DictionaryEntry y)
        {
            return string.Compare((string)x.Key, (string)y.Key);
        }
        
        public static readonly DirectoryEntryComparer Instance = new DirectoryEntryComparer();
    }
}
