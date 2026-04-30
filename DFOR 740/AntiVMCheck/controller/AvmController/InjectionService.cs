using System;
using System.ComponentModel;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

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

        [StructLayout(LayoutKind.Sequential)]
        private struct SECURITY_ATTRIBUTES
        {
            public int nLength;
            public IntPtr lpSecurityDescriptor;
            [MarshalAs(UnmanagedType.Bool)]
            public bool bInheritHandle;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool SetHandleInformation(IntPtr hObject, uint dwMask, uint dwFlags);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetExitCodeProcess(IntPtr hProcess, out uint lpExitCode);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool ReadFile(IntPtr hFile, [Out] byte[] lpBuffer, uint nNumberOfBytesToRead, out uint lpNumberOfBytesRead, IntPtr lpOverlapped);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool PeekNamedPipe(IntPtr hNamedPipe, IntPtr lpBuffer, uint nBufferSize, IntPtr lpBytesRead, out uint lpTotalBytesAvail, IntPtr lpBytesLeftThisMessage);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr GetStdHandle(int nStdHandle);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CreatePipe(out IntPtr hReadPipe, out IntPtr hWritePipe, ref SECURITY_ATTRIBUTES lpPipeAttributes, uint nSize);

        private const uint ProcessAllAccess    = 0x1F0FFF;
        private const uint MemCommit            = 0x1000;
        private const uint MemReserve           = 0x2000;
        private const uint PageReadWrite        = 0x04;
        private const uint CreateSuspended      = 0x00000004;
        private const uint CreateNoWindow       = 0x08000000;
        private const uint STARTF_USESTDHANDLES = 0x00000100;
        private const uint HANDLE_FLAG_INHERIT  = 0x00000001;
        private const uint WAIT_OBJECT_0        = 0x00000000;
        private const uint WAIT_TIMEOUT         = 0x00000102;
        private const int STD_INPUT_HANDLE      = -10;
        private const uint STILL_ACTIVE         = 0x00000103;
        private const int CapturePollSleepMs    = 100;
        private const int CaptureQuietAfterOutputMs = 1500;
        private const int CaptureQuietWithoutOutputMs = 120000;
        private const int CaptureMaxWaitMs      = 180000;
        private const int CaptureStatusIntervalMs = 10000;

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

        /// <summary>
        /// Launch <paramref name="exePath"/>, inject the shim immediately after start,
        /// capture all stdout/stderr output, and return it once the process exits.
        /// Uses System.Diagnostics.Process for reliable pipe handling.
        /// </summary>
        public static string LaunchWithShimCaptured(
            string exePath,
            out uint processId,
            Action<string> onOutputChunk = null,
            Action<string> onStatus = null,
            Action<uint> onStarted = null)
        {
            var shimPath = RequireShimPath();
            var workingDirectory = Path.GetDirectoryName(exePath);
            var commandLine = $"\"{exePath}\"";
            var sa = new SECURITY_ATTRIBUTES
            {
                nLength = Marshal.SizeOf<SECURITY_ATTRIBUTES>(),
                bInheritHandle = true,
                lpSecurityDescriptor = IntPtr.Zero
            };
            IntPtr stdinRead = IntPtr.Zero;
            IntPtr stdinWrite = IntPtr.Zero;

            if (!CreatePipe(out var stdoutRead, out var stdoutWrite, ref sa, 0))
                throw new Win32Exception(Marshal.GetLastWin32Error());

            if (!CreatePipe(out stdinRead, out stdinWrite, ref sa, 0))
            {
                CloseHandle(stdoutRead);
                CloseHandle(stdoutWrite);
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            try
            {
                if (!SetHandleInformation(stdoutRead, HANDLE_FLAG_INHERIT, 0))
                    throw new Win32Exception(Marshal.GetLastWin32Error());

                if (!SetHandleInformation(stdinWrite, HANDLE_FLAG_INHERIT, 0))
                    throw new Win32Exception(Marshal.GetLastWin32Error());

                var si = new STARTUPINFO
                {
                    cb = (uint)Marshal.SizeOf<STARTUPINFO>(),
                    dwFlags = STARTF_USESTDHANDLES,
                    hStdInput = stdinRead,
                    hStdOutput = stdoutWrite,
                    hStdError = stdoutWrite
                };

                if (!CreateProcess(null, commandLine, IntPtr.Zero, IntPtr.Zero, true,
                                   CreateSuspended | CreateNoWindow, IntPtr.Zero, workingDirectory,
                                   ref si, out var pi))
                    throw new Win32Exception(Marshal.GetLastWin32Error());

                processId = pi.dwProcessId;
                onStarted?.Invoke(processId);

                try
                {
                    InjectIntoProcess(pi.hProcess, shimPath);
                    ResumeThread(pi.hThread);
                }
                catch
                {
                    ResumeThread(pi.hThread);
                    throw;
                }
                finally
                {
                    CloseHandle(stdinRead);
                    stdinRead = IntPtr.Zero;
                    CloseHandle(stdinWrite);
                    stdinWrite = IntPtr.Zero;
                    CloseHandle(pi.hThread);
                    CloseHandle(stdoutWrite);
                    stdoutWrite = IntPtr.Zero;
                }

                var bytes = new byte[4096];
                var output = new MemoryStream();
                var sawBytes = false;
                var processExited = false;
                var exitCode = STILL_ACTIVE;
                var quietPollsAfterExit = 0;
                var startedAt = DateTime.UtcNow;
                var lastOutputAt = startedAt;
                var lastStatusAt = startedAt;
                var seenMarkers = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                var sawMarkers = false;

                while (true)
                {
                    GetExitCodeProcess(pi.hProcess, out exitCode);
                    processExited = exitCode != STILL_ACTIVE;

                    if (PeekNamedPipe(stdoutRead, IntPtr.Zero, 0, IntPtr.Zero, out var available, IntPtr.Zero) && available > 0)
                    {
                        if (ReadFile(stdoutRead, bytes, (uint)Math.Min(bytes.Length, (int)available), out var read, IntPtr.Zero) && read > 0)
                        {
                            output.Write(bytes, 0, (int)read);
                            sawBytes = true;
                            lastOutputAt = DateTime.UtcNow;
                            quietPollsAfterExit = 0;
                            onOutputChunk?.Invoke(DecodeCapturedOutput(CopyChunk(bytes, (int)read)));
                            continue;
                        }
                    }

                    sawMarkers |= PumpMarkerFiles(workingDirectory, seenMarkers, onOutputChunk);

                    if (processExited)
                    {
                        quietPollsAfterExit++;
                        if (quietPollsAfterExit >= 6)
                        {
                            break;
                        }
                    }

                    var elapsedMs = (DateTime.UtcNow - startedAt).TotalMilliseconds;
                    var quietMs = (DateTime.UtcNow - lastOutputAt).TotalMilliseconds;
                    var statusMs = (DateTime.UtcNow - lastStatusAt).TotalMilliseconds;

                    if (sawBytes && quietMs >= CaptureQuietAfterOutputMs)
                    {
                        break;
                    }

                    if (!sawBytes && quietMs >= CaptureQuietWithoutOutputMs)
                    {
                        break;
                    }

                    if (elapsedMs >= CaptureMaxWaitMs)
                    {
                        break;
                    }

                    if (!processExited && statusMs >= CaptureStatusIntervalMs)
                    {
                        lastStatusAt = DateTime.UtcNow;
                        onStatus?.Invoke(sawBytes
                            ? "[Still running. Waiting for more output...]"
                            : "[Still running. Waiting for first output...]");
                    }

                    System.Threading.Thread.Sleep(CapturePollSleepMs);
                }

                var result = DecodeCapturedOutput(output.ToArray());
                if (string.IsNullOrWhiteSpace(result))
                {
                    var wait = WaitForSingleObject(pi.hProcess, 3000);
                    GetExitCodeProcess(pi.hProcess, out exitCode);

                    if (sawMarkers)
                    {
                        result = "[No stdout/stderr was captured. Detection markers were observed in the working directory.]";
                    }
                    else if (!sawBytes && wait == WAIT_TIMEOUT)
                    {
                        result = "[No output captured. The target is still running but did not write to stdout/stderr.]";
                    }
                    else
                    {
                        result = $"[No output captured. Process exit code: 0x{exitCode:X8}]";
                    }
                }
                else if (!processExited)
                {
                    result += Environment.NewLine + Environment.NewLine
                        + "[Capture ended while the target was still running. The output above is partial.]";
                }

                if (processExited)
                {
                    CleanupMarkerFiles(workingDirectory);
                }
                CloseHandle(pi.hProcess);
                return result;
            }
            finally
            {
                if (stdinWrite != IntPtr.Zero) CloseHandle(stdinWrite);
                if (stdinRead != IntPtr.Zero) CloseHandle(stdinRead);
                if (stdoutWrite != IntPtr.Zero) CloseHandle(stdoutWrite);
                if (stdoutRead != IntPtr.Zero) CloseHandle(stdoutRead);
            }
        }

        private static string DecodeCapturedOutput(byte[] data)
        {
            if (data == null || data.Length == 0)
            {
                return string.Empty;
            }

            if (data.Length >= 2)
            {
                if (data[0] == 0xFF && data[1] == 0xFE)
                {
                    return Encoding.Unicode.GetString(data, 2, data.Length - 2);
                }

                if (data[0] == 0xFE && data[1] == 0xFF)
                {
                    return Encoding.BigEndianUnicode.GetString(data, 2, data.Length - 2);
                }
            }

            if (data.Length >= 3 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF)
            {
                return Encoding.UTF8.GetString(data, 3, data.Length - 3);
            }

            return Encoding.UTF8.GetString(data);
        }

        private static byte[] CopyChunk(byte[] buffer, int count)
        {
            var chunk = new byte[count];
            Buffer.BlockCopy(buffer, 0, chunk, 0, count);
            return chunk;
        }

        private static void CleanupMarkerFiles(string workingDirectory)
        {
            if (string.IsNullOrWhiteSpace(workingDirectory) || !Directory.Exists(workingDirectory))
            {
                return;
            }

            try
            {
                foreach (var path in Directory.GetFiles(workingDirectory, "hi_*"))
                {
                    try
                    {
                        File.Delete(path);
                    }
                    catch
                    {
                    }
                }
            }
            catch
            {
            }
        }

        private static bool PumpMarkerFiles(string workingDirectory, HashSet<string> seenMarkers, Action<string> onOutputChunk)
        {
            if (string.IsNullOrWhiteSpace(workingDirectory) || !Directory.Exists(workingDirectory))
            {
                return false;
            }

            var sawAny = false;

            try
            {
                foreach (var path in Directory.GetFiles(workingDirectory, "hi_*"))
                {
                    var name = Path.GetFileName(path);
                    if (!seenMarkers.Add(name))
                    {
                        continue;
                    }

                    sawAny = true;
                    onOutputChunk?.Invoke($"[Marker] {name}{Environment.NewLine}");
                }
            }
            catch
            {
            }

            return sawAny;
        }

        private static void InjectIntoRunningProcess(uint processId, string shimPath)
        {
            var process = OpenProcess(ProcessAllAccess, false, processId);
            if (process == IntPtr.Zero)
                throw new Win32Exception(Marshal.GetLastWin32Error());
            try   { InjectIntoProcess(process, shimPath); }
            finally { CloseHandle(process); }
        }
    }
}
