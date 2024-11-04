using CryptoDrive.Cryptography;
using Fsp;
using Fsp.Interop;
using System;
using System.Collections;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using FileInfo = Fsp.Interop.FileInfo;

namespace CryptoDrive.FS
{
    internal class CryptoFileSystem : FileSystemBase
    {
        internal static readonly ushort ALLOCATION_UNIT = 2048;
        public string Root { get; private set; }
        private readonly byte[] cryptoKey;
        public CryptoFileSystem(byte[] cryptoKey, string root)
        {
            this.cryptoKey = cryptoKey;
            Root = root;
        }

        public override int Init(object Host)
        {
            var host = (FileSystemHost)Host;
            host.SectorSize = ALLOCATION_UNIT;
            host.SectorsPerAllocationUnit = 1;
            host.MaxComponentLength = 255;
            host.FileInfoTimeout = 1000;
            host.CaseSensitiveSearch = false;
            host.CasePreservedNames = true;
            host.UnicodeOnDisk = true;
            host.PersistentAcls = true;
            host.PostCleanupWhenModifiedOnly = true;
            host.PassQueryDirectoryPattern = true;
            host.FlushAndPurgeOnCleanup = true;
            host.VolumeCreationTime = (uint)File.GetCreationTimeUtc(Root).ToFileTimeUtc();
            host.VolumeSerialNumber = 0;
            return STATUS_SUCCESS;
        }

        public override int GetVolumeInfo(out VolumeInfo VolumeInfo)
        {
            var info = new DriveInfo(Root);
            VolumeInfo = default;
            VolumeInfo.TotalSize = (ulong)info.TotalSize;
            VolumeInfo.FreeSize = (ulong)info.TotalFreeSpace;
            return STATUS_SUCCESS;
        }

        public override int GetSecurityByName(string FileName, out uint FileAttributes, ref byte[] SecurityDescriptor)
        {
            FileName = FileItem.PathCombine(cryptoKey, Root, FileName);
            var info = new System.IO.FileInfo(FileName);
            FileAttributes = (uint)info.Attributes;
            //if (SecurityDescriptor != null)
            //    SecurityDescriptor = info.GetAccessControl().GetSecurityDescriptorBinaryForm();

            return STATUS_SUCCESS;
        }

        public override int Create(string FileName, uint CreateOptions, uint GrantedAccess, uint FileAttributes, byte[] SecurityDescriptor, ulong AllocationSize, out object FileNode, out object FileDesc, out FileInfo FileInfo, out string NormalizedName)
        {
            FileName = FileItem.PathCombine(cryptoKey, Root, FileName);
            FileItem item = null;
            try
            {
                if ((CreateOptions & FILE_DIRECTORY_FILE) == 0)
                {
                    FileSecurity security = null;
                    if (SecurityDescriptor != null)
                    {
                        security = new FileSecurity();
                        security.SetSecurityDescriptorBinaryForm(SecurityDescriptor);
                    }
                    item = new FileItem(
                        FileName,
                        new CryptoFileStream(
                            cryptoKey,
                            new FileStream(
                                FileName,
                                FileMode.CreateNew,
                                FileAccess.ReadWrite,
                                FileShare.Read | FileShare.Write | FileShare.Delete,
                                4096)
                        ),
                        (FileSystemRights)GrantedAccess | FileSystemRights.WriteAttributes,
                        security);
                    item.SetFileAttributes(FileAttributes | (uint)System.IO.FileAttributes.Archive);
                }
                else
                {
                    if (Directory.Exists(FileName))
                        ThrowIOExceptionWithNtStatus(STATUS_OBJECT_NAME_COLLISION);
                    DirectorySecurity security = null;
                    if (SecurityDescriptor != null)
                    {
                        security = new DirectorySecurity();
                        security.SetSecurityDescriptorBinaryForm(SecurityDescriptor);
                    }
                    item = new FileItem(Directory.CreateDirectory(FileName), security);
                    item.SetFileAttributes(FileAttributes);
                }
                FileNode = default;
                FileDesc = item;
                NormalizedName = default;
                return item.GetFileInfo(out FileInfo);
            }
            catch
            {
                item?.Stream?.Dispose();
                throw;
            }
        }

        public override int Open(string FileName, uint CreateOptions, uint GrantedAccess, out object FileNode, out object FileDesc, out FileInfo FileInfo, out string NormalizedName)
        {
            FileName = FileItem.PathCombine(cryptoKey, Root, FileName);
            FileItem item = null;
            try
            {
                if (!Directory.Exists(FileName))
                {
                    item = new FileItem(
                        FileName,
                        new CryptoFileStream(
                            cryptoKey,
                            new FileStream(
                                FileName,
                                FileMode.Open,
                                FileAccess.ReadWrite,
                                FileShare.Read | FileShare.Write | FileShare.Delete,
                                4096)
                        ),
                        (FileSystemRights)GrantedAccess);
                }
                else
                {
                    item = new FileItem(new DirectoryInfo(FileName));
                }
                FileNode = default;
                FileDesc = item;
                NormalizedName = default;
                return item.GetFileInfo(out FileInfo);
            }
            catch
            {
                item?.Stream?.Dispose();
                throw;
            }
        }

        public override void Cleanup(object FileNode, object FileDesc, string FileName, uint Flags)
        {
            var item = (FileItem)FileDesc;
            if ((Flags & CleanupDelete) != 0)
            {
                item.SetDisposition(true);
                item.Stream?.Dispose();
            }
        }

        public override void Close(object FileNode, object FileDesc)
        {
            var item = (FileItem)FileDesc;
            item.Stream?.Dispose();
        }

        public override int Overwrite(object FileNode, object FileDesc, uint FileAttributes, bool ReplaceFileAttributes, ulong AllocationSize, out FileInfo FileInfo)
        {
            var item = (FileItem)FileDesc;
            if (ReplaceFileAttributes)
                item.SetFileAttributes(FileAttributes | (uint)System.IO.FileAttributes.Archive);
            else if (FileAttributes != 0)
                item.SetFileAttributes(item.GetFileAttributes() | FileAttributes | (uint)System.IO.FileAttributes.Archive);
            item.Stream.SetLength(0);
            return item.GetFileInfo(out FileInfo);
        }

        public override int Read(object FileNode, object FileDesc, nint Buffer, ulong Offset, uint Length, out uint BytesTransferred)
        {
            var item = (FileItem)FileDesc;
            if ((uint)item.Stream.Length <= Offset) ThrowIOExceptionWithNtStatus(STATUS_END_OF_FILE);
            var bytes = new byte[Length];
            item.Stream.Seek((long)Offset, SeekOrigin.Begin);
            BytesTransferred = (uint)item.Stream.Read(bytes, 0, bytes.Length);
            Marshal.Copy(bytes, 0, Buffer, (int)BytesTransferred);
            return STATUS_SUCCESS;
        }

        public override int Write(object FileNode, object FileDesc, nint Buffer, ulong Offset, uint Length, bool WriteToEndOfFile, bool ConstrainedIo, out uint BytesTransferred, out FileInfo FileInfo)
        {
            var item = (FileItem)FileDesc;
            if (ConstrainedIo)
            {
                if ((ulong)item.Stream.Length <= Offset)
                {
                    BytesTransferred = default;
                    FileInfo = default;
                    return STATUS_SUCCESS;
                }
                if ((ulong)item.Stream.Length < Offset + Length)
                    Length = (uint)((ulong)item.Stream.Length - Offset);
            }
            var bytes = new byte[Length];
            Marshal.Copy(Buffer, bytes, 0, bytes.Length);
            if (!WriteToEndOfFile)
                item.Stream.Seek((long)Offset, SeekOrigin.Begin);
            item.Stream.Write(bytes, 0, bytes.Length);
            BytesTransferred = (uint)bytes.Length;
            return item.GetFileInfo(out FileInfo);
        }

        public override int Flush(object FileNode, object FileDesc, out FileInfo FileInfo)
        {
            var item = (FileItem)FileDesc;
            if (item == null)
            {
                FileInfo = default;
                return STATUS_SUCCESS;
            }
            item.Stream.Flush(true);
            return item.GetFileInfo(out FileInfo);
        }

        public override int GetFileInfo(object FileNode, object FileDesc, out FileInfo FileInfo)
        {
            var item = (FileItem)FileDesc;
            return item.GetFileInfo(out FileInfo);
        }

        public override int SetBasicInfo(object FileNode, object FileDesc, uint FileAttributes, ulong CreationTime, ulong LastAccessTime, ulong LastWriteTime, ulong ChangeTime, out FileInfo FileInfo)
        {
            var item = (FileItem)FileDesc;
            item.SetBasicInfo(FileAttributes, CreationTime, LastAccessTime, LastWriteTime);
            return item.GetFileInfo(out FileInfo);
        }

        public override int SetFileSize(object FileNode, object FileDesc, ulong NewSize, bool SetAllocationSize, out FileInfo FileInfo)
        {
            var item = (FileItem)FileDesc;
            if (!SetAllocationSize || (ulong)item.Stream.Length > NewSize)
                item.Stream.SetLength((long)NewSize);
            return item.GetFileInfo(out FileInfo);
        }

        public override int CanDelete(object FileNode, object FileDesc, string FileName)
        {
            var item = (FileItem)FileDesc;
            item.SetDisposition(false);
            return STATUS_SUCCESS;
        }

        public override int Rename(object FileNode, object FileDesc, string FileName, string NewFileName, bool ReplaceIfExists)
        {
            FileName = FileItem.PathCombine(cryptoKey, Root, FileName);
            NewFileName = FileItem.PathCombine(cryptoKey, Root, NewFileName);
            FileItem.Rename(FileName, NewFileName, ReplaceIfExists);
            return STATUS_SUCCESS;
        }

        public override int GetSecurity(object FileNode, object FileDesc, ref byte[] SecurityDescriptor)
        {
            return base.GetSecurity(FileNode, FileDesc, ref SecurityDescriptor);
            //var item = (FileItem)FileDesc;
            //SecurityDescriptor = item.GetSecurityDescriptor();
            //return STATUS_SUCCESS;
        }

        public override int SetSecurity(object FileNode, object FileDesc, AccessControlSections Sections, byte[] SecurityDescriptor)
        {
            return base.SetSecurity(FileNode, FileDesc, Sections, SecurityDescriptor);
            //var item = (FileItem)FileDesc;
            //item.SetSecurityDescriptor(Sections, SecurityDescriptor);
            //return STATUS_SUCCESS;
        }

        public override bool ReadDirectoryEntry(object FileNode, object FileDesc, string Pattern, string Marker, ref object Context, out string FileName, out FileInfo FileInfo)
        {
            var item = (FileItem)FileDesc;
            if (item.FileSystemInfos == null)
            {
                Pattern = Pattern != null ? Pattern.Replace('<', '*').Replace('>', '?').Replace('"', '.') : "*";
                var fileSystemInfos = item.DirInfo.EnumerateFileSystemInfos(Pattern);
                var list = new SortedList();
                if (item.DirInfo?.Parent != null)
                {
                    list.Add(".", item.DirInfo);
                    list.Add("..", item.DirInfo.Parent);
                }
                foreach (var fileSystemInfo in fileSystemInfos)
                    list.Add(FileItem.NameDecrypt(cryptoKey, fileSystemInfo.Name), fileSystemInfo);
                item.FileSystemInfos = new DictionaryEntry[list.Count];
                list.CopyTo(item.FileSystemInfos, 0);
            }
            int index;
            if (Context == null)
            {
                index = 0;
                if (Marker != null)
                {
                    index = Array.BinarySearch(item.FileSystemInfos, new DictionaryEntry(Marker, null), DirectoryEntryComparer.Instance);
                    if (index >= 0) index++;
                    else index = ~index;
                }
            }
            else index = (int)Context;
            if (item.FileSystemInfos.Length > index)
            {
                Context = index + 1;
                FileName = (string)item.FileSystemInfos[index].Key;
                FileItem.GetFileInfoFromSystemInfo((FileSystemInfo)item.FileSystemInfos[index].Value, out FileInfo);
                return true;
            }
            FileName = default;
            FileInfo = default;
            return false;
        }

        public override int ExceptionHandler(Exception ex)
        {
            var hResult = ex.HResult;
            if ((hResult & 0xFFFF0000) == 0x80070000)
                return NtStatusFromWin32((uint)hResult & 0xFFFF);
            return STATUS_UNEXPECTED_IO_ERROR;
        }

        public static void ThrowIOExceptionWithNtStatus(int status)
        {
            ThrowIOExceptionWithWin32((int)Win32FromNtStatus(status));
        }

        public static void ThrowIOExceptionWithWin32(int error)
        {
            ThrowIOExceptionWithHResult(unchecked((int)(0x80070000 | error)));
        }

        public static void ThrowIOExceptionWithHResult(int hResult)
        {
            throw new IOException(null, hResult);
        }
    }
}
