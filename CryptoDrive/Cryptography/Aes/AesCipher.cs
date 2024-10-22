using System;

namespace CryptoDrive.Cryptography.Aes
{
    internal class AesCipher
    {
        private const int RoundCount = 10;
        private byte[] cV = new byte[16];
        private byte[] iV = new byte[16];
        private uint[] roundKey = new uint[(RoundCount + 1) << 2];
        public AesCipher(byte[] key, byte[] iv)
        {
            SetIV(iv);
            AesModule.GenerateRoundKey(roundKey, key);
        }

        public void Reset()
        {
            Buffer.BlockCopy(iV, 0, cV, 0, 16);
        }

        internal void SetIV(byte[] newIV)
        {
            Buffer.BlockCopy(newIV, 0, iV, 0, 16);
            Reset();
        }

        internal byte[] GetIV() => iV;

        public void EncryptBlock(byte[] input, int inOff, byte[] output, int outOff, int length)
        {
            for (var i = 0; i < length; i++)
            {
                var v = AesEncryptBlock(cV);
                output[outOff + i] = (byte)(v ^ input[inOff + i]);
                Buffer.BlockCopy(cV, 1, cV, 0, 15);
                cV[15] = output[outOff + i];
            }
        }

        public byte Encrypt(byte input)
        {
            var v = (byte)(AesEncryptBlock(cV) ^ input);
            Buffer.BlockCopy(cV, 1, cV, 0, 15);
            cV[15] = v;
            return v;
        }

        public void DecryptBlock(byte[] input, int inOff, byte[] output, int outOff, int length)
        {
            for (var i = 0; i < length; i++)
            {
                var v = (byte)(AesEncryptBlock(cV) ^ input[inOff + i]);
                Buffer.BlockCopy(cV, 1, cV, 0, 15);
                cV[15] = input[inOff + i];
                output[outOff + i] = v;
            }
        }

        public byte Decrypt(byte input)
        {
            var v = (byte)(AesEncryptBlock(cV) ^ input);
            Buffer.BlockCopy(cV, 1, cV, 0, 15);
            cV[15] = input;
            return v;
        }

        private byte AesEncryptBlock(byte[] block)
        {
            var ptr = 0;
            var c0 = AesModule.ColumnToUInt(block, 0) ^ roundKey[ptr++];
            var c1 = AesModule.ColumnToUInt(block, 1) ^ roundKey[ptr++];
            var c2 = AesModule.ColumnToUInt(block, 2) ^ roundKey[ptr++];
            var c3 = AesModule.ColumnToUInt(block, 3) ^ roundKey[ptr++];
            var round = 1;
            while (round < RoundCount - 1)
            {
                var a = AesModule.SubMixColumnHelper(c0, c1 >> 8, c2 >> 16, c3 >> 24) ^ roundKey[ptr++];
                var b = AesModule.SubMixColumnHelper(c1, c2 >> 8, c3 >> 16, c0 >> 24) ^ roundKey[ptr++];
                var c = AesModule.SubMixColumnHelper(c2, c3 >> 8, c0 >> 16, c1 >> 24) ^ roundKey[ptr++];
                var d = AesModule.SubMixColumnHelper(c3, c0 >> 8, c1 >> 16, c2 >> 24) ^ roundKey[ptr++];
                round++;

                c0 = AesModule.SubMixColumnHelper(a, b >> 8, c >> 16, d >> 24) ^ roundKey[ptr++];
                c1 = AesModule.SubMixColumnHelper(b, c >> 8, d >> 16, a >> 24) ^ roundKey[ptr++];
                c2 = AesModule.SubMixColumnHelper(c, d >> 8, a >> 16, b >> 24) ^ roundKey[ptr++];
                c3 = AesModule.SubMixColumnHelper(d, a >> 8, b >> 16, c >> 24) ^ roundKey[ptr++];
                round++;
            }

            var r0 = AesModule.SubMixColumnHelper(c0, c1 >> 8, c2 >> 16, c3 >> 24) ^ roundKey[ptr++];
            //var r1 = AesModule.SubMixColumnHelper(c1, c2 >> 8, c3 >> 16, c0 >> 24) ^ roundKey[ptr++];
            //var r2 = AesModule.SubMixColumnHelper(c2, c3 >> 8, c0 >> 16, c1 >> 24) ^ roundKey[ptr++];
            //var r3 = AesModule.SubMixColumnHelper(c3, c0 >> 8, c1 >> 16, c2 >> 24) ^ roundKey[ptr++];

            //c0 = AesModule.SubAndShift(r0, r1 >> 8, r2 >> 16, r3 >> 24) ^ roundKey[ptr++];
            //c1 = AesModule.SubAndShift(r1, r2 >> 8, r3 >> 16, r0 >> 24) ^ roundKey[ptr++];
            //c2 = AesModule.SubAndShift(r2, r3 >> 8, r0 >> 16, r1 >> 24) ^ roundKey[ptr++];
            //c3 = AesModule.SubAndShift(r3, r0 >> 8, r1 >> 16, r2 >> 24) ^ roundKey[ptr++];
            ptr += 3;
            //return AesModule.ColumnsToBytes(c0, c1, c2, c3)[0];
            return (byte)(AesModule.SubSingle((byte)r0) ^ roundKey[ptr]);
        }
    }
}
