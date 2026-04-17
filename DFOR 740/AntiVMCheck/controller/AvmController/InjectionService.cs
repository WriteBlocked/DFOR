using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;

namespace AvmController
{
    internal static class InjectionService
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(uint desiredAccess, bool inheritHandle, uint processId);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr VirtualAllocEx(IntPtr processHandle, IntPtr address, UIntPtr size, uint allocationType, uint protect);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool WriteProcessMemory(IntPtr processHandle, IntPtr baseAddress, byte[] buffer, int size, out IntPtr bytesWritten);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr GetProcAddress(IntPtr module, string procName);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr GetModuleHandle(string moduleName);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr CreateRemoteThread(IntPtr processHandle, IntPtr threadAttributes, uint stackSize, IntPtr startAddress, IntPtr parameter, uint creationFlags, out uint threadId);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr handle);

        private const uint ProcessAllAccess = 0x1F0FFF;
        private const uint MemCommit = 0x1000;
        private const uint MemReserve = 0x2000;
        private const uint PageReadWrite = 0x04;

        public static void InjectShim(uint processId)
        {
            var shimPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "AvmRuntimeShim.dll");
            if (!File.Exists(shimPath))
            {
                throw new FileNotFoundException("AvmRuntimeShim.dll was not found next to the controller.", shimPath);
            }

            var process = OpenProcess(ProcessAllAccess, false, processId);
            if (process == IntPtr.Zero)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            try
            {
                var bytes = System.Text.Encoding.Unicode.GetBytes(shimPath + "\0");
                var remoteBuffer = VirtualAllocEx(process, IntPtr.Zero, (UIntPtr)bytes.Length, MemCommit | MemReserve, PageReadWrite);
                if (remoteBuffer == IntPtr.Zero)
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }

                if (!WriteProcessMemory(process, remoteBuffer, bytes, bytes.Length, out _))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }

                var kernel32 = GetModuleHandle("kernel32.dll");
                var loadLibrary = GetProcAddress(kernel32, "LoadLibraryW");
                var thread = CreateRemoteThread(process, IntPtr.Zero, 0, loadLibrary, remoteBuffer, 0, out _);
                if (thread == IntPtr.Zero)
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }

                WaitForSingleObject(thread, 5000);
                CloseHandle(thread);
            }
            finally
            {
                CloseHandle(process);
            }
        }
    }
}
