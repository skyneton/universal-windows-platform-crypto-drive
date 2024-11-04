using CryptoDrive.Cryptography;
using CryptoDrive.Utils;
using System;
using System.Collections;
using System.Diagnostics;
using System.IO;
using System.Security.AccessControl;
using System.Text;

namespace CryptoDrive.FS
{
    internal class FileItem
    {
        public string Path { get; private set; }
        public CryptoFileStream Stream { get; private set; }
        public DirectoryInfo DirInfo { get; private set; }
        public DictionaryEntry[] FileSystemInfos { get; internal set; }

        public FileItem(string path, CryptoFileStream stream, FileSecurity security)
        {
            Path = path;
            Stream = stream;
            //Stream.SetAccessControl(security);
        }

        public FileItem(string path, CryptoFileStream stream, FileSystemRights fileSystemRights, FileSecurity security)
        {
            Path = path;
            Stream = stream;
            //security.AddAccessRule(new FileSystemAccessRule("", fileSystemRights, AccessControlType.Allow));
            //Stream.SetAccessControl(security);
        }

        public FileItem(string path, CryptoFileStream stream, FileSystemRights fileSystemRights)
        {
            Path = path;
            Stream = stream;
            //var security = new FileSecurity();
            //security.AddAccessRule(new FileSystemAccessRule("", fileSystemRights, AccessControlType.Allow));
            //Stream.SetAccessControl(security);
        }

        public FileItem(DirectoryInfo dirInfo)
        {
            DirInfo = dirInfo;
        }

        public FileItem(DirectoryInfo dirInfo, DirectorySecurity security)
        {
            DirInfo = dirInfo;
            //dirInfo.SetAccessControl(security);
        }

        public int GetFileInfo(out Fsp.Interop.FileInfo fileInfo)
        {
            if (Stream != null)
            {
                fileInfo.FileAttributes = (uint)File.GetAttributes(Stream.SafeFileHandle);
                fileInfo.ReparseTag = 0;
                fileInfo.FileSize = (uint)Stream.Length;
                fileInfo.AllocationSize = (fileInfo.FileSize + CryptoFileSystem.ALLOCATION_UNIT - 1) / CryptoFileSystem.ALLOCATION_UNIT * CryptoFileSystem.ALLOCATION_UNIT;
                fileInfo.CreationTime = (ulong)File.GetCreationTimeUtc(Stream.SafeFileHandle).ToFileTimeUtc();
                fileInfo.LastAccessTime = (ulong)File.GetLastAccessTimeUtc(Stream.SafeFileHandle).ToFileTimeUtc();
                fileInfo.LastWriteTime = (ulong)File.GetLastWriteTimeUtc(Stream.SafeFileHandle).ToFileTimeUtc();
                fileInfo.ChangeTime = fileInfo.LastWriteTime;
                fileInfo.IndexNumber = 0;
                fileInfo.HardLinks = 0;
            }
            else
                GetFileInfoFromSystemInfo(DirInfo, out fileInfo);
            return CryptoFileSystem.STATUS_SUCCESS;
        }

        public void SetFileAttributes(uint fileAttributes)
        {
            SetBasicInfo(fileAttributes, 0, 0, 0);
        }

        public uint GetFileAttributes()
        {
            Fsp.Interop.FileInfo fileInfo;
            GetFileInfo(out fileInfo);
            return fileInfo.FileAttributes;
        }

        public void SetBasicInfo(uint fileAttributes, ulong creationTime, ulong lastAccessTime, ulong lastWriteTime)
        {
            if (fileAttributes == 0) fileAttributes = (uint)FileAttributes.Normal;
            if (Stream != null)
            {
                File.SetCreationTimeUtc(Stream.SafeFileHandle, DateTime.FromFileTimeUtc((long)creationTime));
                File.SetLastAccessTimeUtc(Stream.SafeFileHandle, DateTime.FromFileTimeUtc((long)lastAccessTime));
                File.SetLastWriteTimeUtc(Stream.SafeFileHandle, DateTime.FromFileTimeUtc((long)lastWriteTime));
            }
            else
            {
                if (fileAttributes != unchecked((uint)-1))
                    DirInfo.Attributes = (FileAttributes)fileAttributes;
                if (creationTime != 0)
                    DirInfo.CreationTimeUtc = DateTime.FromFileTimeUtc((long)creationTime);
                if (lastAccessTime != 0)
                    DirInfo.LastAccessTimeUtc = DateTime.FromFileTimeUtc((long)lastAccessTime);
            }
        }

        public void SetDisposition(bool safe)
        {
            try
            {
                if (Stream != null)
                {
                    File.Delete(Path);
                    return;
                }
                DirInfo.Delete();
            }
            catch (Exception ex)
            {
                if (!safe) CryptoFileSystem.ThrowIOExceptionWithHResult(ex.HResult);
            }
        }

        public byte[] GetSecurityDescriptor()
        {
            if (Stream != null) return Stream.GetAccessControl().GetSecurityDescriptorBinaryForm();
            return DirInfo.GetAccessControl().GetSecurityDescriptorBinaryForm();
        }

        public void SetSecurityDescriptor(AccessControlSections sections, byte[] securityDescriptor)
        {
            //var securityInformation = 0;
            //if ((sections & AccessControlSections.Owner) != 0)
            //    securityInformation |= 1;
            //if((sections & AccessControlSections.Group) != 0)
            //    securityInformation |= 2;
            //if((sections & AccessControlSections.Access) != 0)
            //    securityInformation |= 4;
            //if((sections & AccessControlSections.Audit) != 0)
            //    securityInformation |= 8;
            if (Stream != null)
            {
                var security = new FileSecurity(Path, sections);
                security.SetSecurityDescriptorBinaryForm(securityDescriptor);
                Stream.SetAccessControl(security);
            }
            else
            {
                var security = new DirectorySecurity(DirInfo.FullName, sections);
                security.SetSecurityDescriptorBinaryForm(securityDescriptor);
                DirInfo.SetAccessControl(security);
            }
        }

        public static void Rename(byte[] cryptoKey, string path, string fileName, string newName, bool overwrite)
        {
            var srcFilePath = GetFileForRename(cryptoKey, PathCombine(cryptoKey, path, fileName[..fileName.LastIndexOf('\\')]), fileName[(fileName.LastIndexOf('\\') + 1)..]);
            if (srcFilePath.Length <= 0)
                throw new FileNotFoundException(PathCombine(cryptoKey, path, fileName[..fileName.LastIndexOf('\\')]) + '\\' + fileName[(fileName.LastIndexOf('\\') + 1)..]);
            var descFilePath = PathCombine(cryptoKey, path, newName);
            if (Directory.Exists(srcFilePath))
                Directory.Move(srcFilePath, descFilePath);
            else
                File.Move(srcFilePath, descFilePath, overwrite);
        }

        public static void GetFileInfoFromSystemInfo(FileSystemInfo info, out Fsp.Interop.FileInfo fileInfo)
        {
            fileInfo.FileAttributes = (uint)info.Attributes;
            fileInfo.ReparseTag = 0;
            fileInfo.FileSize = info is FileInfo ? (uint)((FileInfo)info).Length : 0;
            fileInfo.AllocationSize = (fileInfo.FileSize + CryptoFileSystem.ALLOCATION_UNIT - 1);
            fileInfo.CreationTime = (uint)info.CreationTimeUtc.ToFileTimeUtc();
            fileInfo.LastAccessTime = (uint)info.LastAccessTimeUtc.ToFileTimeUtc();
            fileInfo.LastWriteTime = (uint)info.LastWriteTimeUtc.ToFileTimeUtc();
            fileInfo.ChangeTime = fileInfo.LastWriteTime;
            fileInfo.IndexNumber = 0;
            fileInfo.HardLinks = 0;
        }

        internal static string PathCombine(byte[] cryptoKey, string directory, string name)
        {
            var builder = new StringBuilder(directory);
            if (!directory.EndsWith('\\'))
                builder.Append('\\');

            if(name.Length > 0)
                builder.Append(PathEncrypt(cryptoKey, name[1..]));

            return builder.ToString();
        }

        private static string PathEncrypt(byte[] cryptoKey, string path)
        {
            if (path.Length <= 0) return string.Empty;
            var builder = new StringBuilder();
            foreach (var name in path.Split('\\'))
            {
                if (builder.Length > 0)
                    builder.Append('\\');
                //builder.Append(Base256.ToString(SimpleCrypt.Reverse(StringAlgorithm.ToBytes(name), cryptoKey[0])));
                builder.Append(Base256.ToString(StringAlgorithm.ToBytes(name)));
            }
            return builder.ToString();
        }

        internal static string NameDecrypt(byte[] cryptoKey, string name)
        {
            //return StringAlgorithm.ToString(SimpleCrypt.Origin(Base256.ToBytes(name), cryptoKey[0]));
            return StringAlgorithm.ToString(Base256.ToBytes(name));
        }

        private static string GetFileForRename(byte[] cryptoKey, string path, string name)
        {
            foreach (var file in new DirectoryInfo(path).GetDirectories())
            {
                if (NameDecrypt(cryptoKey, file.Name).Equals(name, StringComparison.OrdinalIgnoreCase))
                    return file.FullName;
            }
            foreach (var file in new DirectoryInfo(path).GetFiles())
            {
                if (NameDecrypt(cryptoKey, file.Name).Equals(name, StringComparison.OrdinalIgnoreCase))
                    return file.FullName;
            }
            return string.Empty;
        }
    }
}
