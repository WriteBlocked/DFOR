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

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool CreateProcess(
            string lpApplicationName,
            string lpCommandLine,
            IntPtr lpProcessAttributes,
            IntPtr lpThreadAttributes,
            bool bInheritHandles,
            uint dwCreationFlags,
            IntPtr lpEnvironment,
            string lpCurrentDirectory,
            ref STARTUPINFO lpStartupInfo,
            out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint ResumeThread(IntPtr hThread);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct STARTUPINFO
        {
            public uint   cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public uint   dwX, dwY, dwXSize, dwYSize;
            public uint   dwXCountChars, dwYCountChars;
            public uint   dwFillAttribute, dwFlags;
            public ushort wShowWindow, cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput, hStdOutput, hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public uint   dwProcessId;
            public uint   dwThreadId;
        }

        private const uint ProcessAllAccess = 0x1F0FFF;
        private const uint MemCommit        = 0x1000;
        private const uint MemReserve       = 0x2000;
        private const uint PageReadWrite    = 0x04;
        private const uint CreateSuspended  = 0x00000004;

        private static string RequireShimPath()
        {
            var shimPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "AvmRuntimeShim.dll");
            if (!File.Exists(shimPath))
                throw new FileNotFoundException("AvmRuntimeShim.dll was not found next to the controller.", shimPath);
            return shimPath;
        }

        private static void InjectIntoProcess(IntPtr hProcess, string shimPath)
        {
            var bytes        = System.Text.Encoding.Unicode.GetBytes(shimPath + "\0");
            var remoteBuffer = VirtualAllocEx(hProcess, IntPtr.Zero, (UIntPtr)bytes.Length, MemCommit | MemReserve, PageReadWrite);
            if (remoteBuffer == IntPtr.Zero)
                throw new Win32Exception(Marshal.GetLastWin32Error());

            if (!WriteProcessMemory(hProcess, remoteBuffer, bytes, bytes.Length, out _))
                throw new Win32Exception(Marshal.GetLastWin32Error());

            var kernel32    = GetModuleHandle("kernel32.dll");
            var loadLibrary = GetProcAddress(kernel32, "LoadLibraryW");
            var thread      = CreateRemoteThread(hProcess, IntPtr.Zero, 0, loadLibrary, remoteBuffer, 0, out _);
            if (thread == IntPtr.Zero)
                throw new Win32Exception(Marshal.GetLastWin32Error());

            WaitForSingleObject(thread, 5000);
            CloseHandle(thread);
        }

        /// <summary>Inject the shim into an already-running process by PID.</summary>
        public static void InjectShim(uint processId)
        {
            var shimPath = RequireShimPath();
            var process  = OpenProcess(ProcessAllAccess, false, processId);
            if (process == IntPtr.Zero)
                throw new Win32Exception(Marshal.GetLastWin32Error());

            try   { InjectIntoProcess(process, shimPath); }
            finally { CloseHandle(process); }
        }

        /// <summary>
        /// Launch <paramref name="exePath"/> suspended, inject the shim before any
        /// application code runs, then resume.  Returns the new process ID.
        /// </summary>
        public static uint LaunchWithShim(string exePath)
        {
            var shimPath = RequireShimPath();

            var si = new STARTUPINFO { cb = (uint)Marshal.SizeOf<STARTUPINFO>() };
            if (!CreateProcess(exePath, null, IntPtr.Zero, IntPtr.Zero, false,
                               CreateSuspended, IntPtr.Zero, null, ref si, out var pi))
                throw new Win32Exception(Marshal.GetLastWin32Error());

            try
            {
                InjectIntoProcess(pi.hProcess, shimPath);
                ResumeThread(pi.hThread);
                return pi.dwProcessId;
            }
            catch
            {
                /* If injection fails, resume anyway so the process isn't orphaned */
                ResumeThread(pi.hThread);
                throw;
            }
            finally
            {
                CloseHandle(pi.hThread);
                CloseHandle(pi.hProcess);
            }
        }
    }
}
