using CryptoDrive.Cryptography.Aes;
using Microsoft.Win32.SafeHandles;
using System;
using System.IO;
using System.Security.AccessControl;
using System.Security.Cryptography;

namespace CryptoDrive.Cryptography
{
    internal class CryptoFileStream : Stream
    {
        private static readonly int ChunkSize = 1024 * 8;
        private AesCipher cipher;
        private byte[] cryptoKey;
        private readonly FileStream stream;
        internal int pos = -1;

        public SafeFileHandle SafeFileHandle => stream.SafeFileHandle;

        public override bool CanRead => stream.CanRead;

        public override bool CanSeek => stream.CanSeek;

        public override bool CanWrite => stream.CanWrite;

        public override long Length => Math.Max(0, stream.Length - 1);

        public override long Position
        {
            get => Math.Max(0, stream.Position - 1);
            set => SetPosition(value);
        }
        public CryptoFileStream(byte[] cryptoKey, FileStream origin)
        {
            stream = origin;
            if (origin.Length > 0)
            {
                var key = origin.ReadByte();
                if (key > 0)
                {
                    cipher = SimpleCrypt.GetCipher(cryptoKey, (byte)key);
                    cryptoKey = null;
                    pos = 0;
                }
            }
            this.cryptoKey = cryptoKey;
        }

        public override void Flush()
        {
            stream.Flush();
        }

        public void Flush(bool flushToDisk)
        {
            stream.Flush(flushToDisk);
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
                stream.Dispose();
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            CipherInit();
            if (Length <= Position) return -1;
            if (pos < 0) return 0;
            var amount = 0;
            while (amount < count)
            {
                var size = Math.Min(count - amount, ChunkSize - pos);
                var readAmount = stream.Read(buffer, offset + amount, size);
                if (readAmount < 0) break;
                cipher.DecryptBlock(buffer, offset + amount, buffer, offset + amount, readAmount);
                amount += readAmount;
                pos += readAmount;
                if (pos >= ChunkSize)
                {
                    cipher.Reset();
                    pos = 0;
                }
                if (readAmount != size) break;
            }
            return amount;
        }

        public override int ReadByte()
        {
            CipherInit();
            if (pos < 0) return -1;
            var v = stream.ReadByte();
            if (v < 0) return -1;
            v = cipher.Decrypt((byte)v);
            if (pos >= ChunkSize)
            {
                cipher.Reset();
                pos = 0;
            }
            return v;
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            if (count <= 0 || !CanWrite) return;
            if (pos < 0)
            {
                var key = (byte)RandomNumberGenerator.GetInt32(256);
                cipher = SimpleCrypt.GetCipher(cryptoKey, key);
                stream.WriteByte(key);
                cryptoKey = null;
                pos = 0;
            }

            var amount = 0;
            while (amount < count && CanWrite)
            {
                var size = Math.Min(count - amount, ChunkSize - pos);
                cipher.EncryptBlock(buffer, offset + amount, buffer, offset + amount, size);
                stream.Write(buffer, offset + amount, size);
                amount += size;
                pos += size;
                if (pos >= ChunkSize)
                {
                    cipher.Reset();
                    pos = 0;
                }
            }
            Refresh();
        }

        public override void WriteByte(byte value)
        {
            if (!CanWrite) return;
            if (pos < 0)
            {
                var key = (byte)RandomNumberGenerator.GetInt32(256);
                cipher = SimpleCrypt.GetCipher(cryptoKey, key);
                stream.WriteByte(key);
                cryptoKey = null;
                pos = 0;
            }
            value = cipher.Encrypt(value);
            if (++pos >= ChunkSize)
            {
                cipher.Reset();
                pos = 0;
            }
            stream.WriteByte(value);
            Refresh();
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            switch (origin)
            {
                case SeekOrigin.Begin:
                    SetPosition(offset);
                    break;
                case SeekOrigin.Current:
                    SetPosition(Position + offset);
                    break;
                case SeekOrigin.End:
                    SetPosition(offset + Length);
                    break;
            }
            return Position;
        }

        public override void SetLength(long value)
        {
            stream.SetLength(value + 1);
            SetPosition(stream.Position - 1);
        }

        private long SetPosition(long value)
        {
            if (value >= stream.Length) value = stream.Length - 1;
            if (value < 0) value = 0;
            if (pos < 0)
            {
                var key = (byte)RandomNumberGenerator.GetInt32(256);
                cipher = SimpleCrypt.GetCipher(cryptoKey, key);
                stream.WriteByte(key);
                cryptoKey = null;
                pos = 0;
            }
            if (stream.Position == value + 1) return 0;
            var delta = value % ChunkSize;
            stream.Position = value - delta + 1;
            cipher.Reset();
            pos = 0;
            return Skip(delta);
        }

        public long Skip(long count)
        {
            if (stream.Position + count > stream.Length)
                count = stream.Length - stream.Position;
            if (count <= 0 || pos < 0) return 0;
            if (count + pos < ChunkSize)
            {
                var buffer = new byte[count];
                var readAmount = stream.Read(buffer, 0, (int)count);
                cipher.DecryptBlock(buffer, 0, buffer, 0, readAmount);
                pos += readAmount;
                return readAmount;
            }
            return SetPosition(Position + count);
        }

        public FileSecurity GetAccessControl() => stream.GetAccessControl();
        public void SetAccessControl(FileSecurity security) => stream.SetAccessControl(security);

        private void Refresh()
        {
            // TODO: After write refresh crypto, if possible to write middle of file.
        }

        private void CipherInit()
        {
            if (pos >= 0) return;
            var v = stream.ReadByte();
            if (v < 0) return;
            cipher = SimpleCrypt.GetCipher(cryptoKey, (byte)v);
            cryptoKey = null;
            pos = 0;
        }
    }
}
