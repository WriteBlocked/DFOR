using Microsoft.Win32.SafeHandles;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace AvmController
{
    internal static class NativeMethods
    {
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern SafeFileHandle CreateFile(
            string fileName,
            uint desiredAccess,
            uint shareMode,
            IntPtr securityAttributes,
            uint creationDisposition,
            uint flagsAndAttributes,
            IntPtr templateFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool DeviceIoControl(
            SafeFileHandle device,
            uint ioControlCode,
            IntPtr inBuffer,
            int inBufferSize,
            IntPtr outBuffer,
            int outBufferSize,
            out int bytesReturned,
            IntPtr overlapped);

        [DllImport("fltlib.dll", CharSet = CharSet.Unicode)]
        internal static extern int FilterConnectCommunicationPort(string portName, uint options, IntPtr context, ushort sizeOfContext, IntPtr securityAttributes, out SafeFileHandle portHandle);

        [DllImport("fltlib.dll")]
        internal static extern int FilterSendMessage(SafeFileHandle portHandle, IntPtr inBuffer, uint inBufferSize, IntPtr outBuffer, uint outBufferSize, out uint bytesReturned);

        internal const uint GenericRead = 0x80000000;
        internal const uint GenericWrite = 0x40000000;
        internal const uint ShareRead = 0x1;
        internal const uint ShareWrite = 0x2;
        internal const uint OpenExisting = 3;
        internal const uint NormalAttributes = 0x80;
    }

    internal sealed class KernelClient : IDisposable
    {
        private readonly SafeFileHandle _handle;

        public KernelClient()
        {
            _handle = NativeMethods.CreateFile(AvmConstants.KernelDevicePath, NativeMethods.GenericRead | NativeMethods.GenericWrite, NativeMethods.ShareRead | NativeMethods.ShareWrite, IntPtr.Zero, NativeMethods.OpenExisting, NativeMethods.NormalAttributes, IntPtr.Zero);
        }

        public bool IsConnected => _handle != null && !_handle.IsInvalid;

        public void Dispose()
        {
            _handle?.Dispose();
        }

        public void SetPolicy(AvmPolicy policy) => SendStruct(AvmConstants.IoctlSetPolicy, policy);

        public void ClearTargets() => SendStruct(AvmConstants.IoctlClearTargets, 0u);

        public void AddTarget(AvmTargetEntry target) => SendStruct(AvmConstants.IoctlAddTarget, target);

        public void ClearFileRules() => SendStruct(AvmConstants.IoctlClearFileRules, 0u);

        public void AddFileRule(AvmFileRule rule) => SendStruct(AvmConstants.IoctlAddFileRule, rule);

        public AvmStatusSnapshot GetStatus() => ReceiveStruct<AvmStatusSnapshot>(AvmConstants.IoctlGetStatus);

        public AvmPolicy GetPolicy() => ReceiveStruct<AvmPolicy>(AvmConstants.IoctlGetPolicy);

        public IReadOnlyList<AvmEventRecord> FetchEvents()
        {
            var batch = ReceiveStruct<AvmEventBatch>(AvmConstants.IoctlFetchEvents);
            var events = new List<AvmEventRecord>();
            if (batch.Events == null)
            {
                return events;
            }

            for (var index = 0; index < batch.Count && index < batch.Events.Length; index++)
            {
                events.Add(batch.Events[index]);
            }

            return events;
        }

        private void SendStruct<T>(uint ioctl, T value) where T : struct
        {
            var size = Marshal.SizeOf(typeof(T));
            var buffer = Marshal.AllocHGlobal(size);
            try
            {
                Marshal.StructureToPtr(value, buffer, false);
                if (!NativeMethods.DeviceIoControl(_handle, ioctl, buffer, size, IntPtr.Zero, 0, out var _, IntPtr.Zero))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        private T ReceiveStruct<T>(uint ioctl) where T : struct
        {
            var size = Marshal.SizeOf(typeof(T));
            var buffer = Marshal.AllocHGlobal(size);
            try
            {
                var value = default(T);
                Marshal.StructureToPtr(value, buffer, false);
                if (!NativeMethods.DeviceIoControl(_handle, ioctl, IntPtr.Zero, 0, buffer, size, out var _, IntPtr.Zero))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }

                return Marshal.PtrToStructure<T>(buffer);
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }
    }

    internal sealed class MiniFilterClient : IDisposable
    {
        private readonly SafeFileHandle _port;

        public MiniFilterClient()
        {
            var status = NativeMethods.FilterConnectCommunicationPort(AvmConstants.MiniFilterPort, 0, IntPtr.Zero, 0, IntPtr.Zero, out _port);
            if (status != 0)
            {
                _port = null;
            }
        }

        public bool IsConnected => _port != null && !_port.IsInvalid;

        public void Dispose()
        {
            _port?.Dispose();
        }

        public void SetPolicy(AvmPolicy policy, IReadOnlyList<AvmTargetEntry> targets, IReadOnlyList<AvmFileRule> fileRules)
        {
            var payload = new AvmFilterPolicyMessage
            {
                Header = new AvmMessageHeader { MessageId = AvmConstants.MessageSetPolicy },
                Policy = policy,
                TargetCount = (uint)targets.Count,
                Targets = new List<AvmTargetEntry>(targets).ToArray(),
                FileRuleCount = (uint)fileRules.Count,
                FileRules = new List<AvmFileRule>(fileRules).ToArray()
            };

            SendBuffer(BuildPolicyBuffer(payload), null);
        }

        public AvmStatusSnapshot GetStatus()
        {
            var header = new AvmMessageHeader { MessageId = AvmConstants.MessageGetStatus, PayloadSize = 0 };
            var request = MarshalToBuffer(header);
            var response = new byte[Marshal.SizeOf(typeof(AvmStatusSnapshot))];
            SendBuffer(request, response);
            return BufferToStruct<AvmStatusSnapshot>(response);
        }

        public IReadOnlyList<AvmEventRecord> FetchEvents()
        {
            var header = new AvmMessageHeader { MessageId = AvmConstants.MessageFetchEvents, PayloadSize = 0 };
            var request = MarshalToBuffer(header);
            var response = new byte[Marshal.SizeOf(typeof(AvmEventBatch))];
            SendBuffer(request, response);
            var batch = BufferToStruct<AvmEventBatch>(response);
            var events = new List<AvmEventRecord>();
            if (batch.Events == null)
            {
                return events;
            }

            for (var index = 0; index < batch.Count && index < batch.Events.Length; index++)
            {
                events.Add(batch.Events[index]);
            }

            return events;
        }

        private byte[] BuildPolicyBuffer(AvmFilterPolicyMessage message)
        {
            var targetSize = Marshal.SizeOf(typeof(AvmTargetEntry)) * AvmConstants.MaxTargets;
            var fileRuleSize = Marshal.SizeOf(typeof(AvmFileRule)) * AvmConstants.MaxFileRules;
            var headerSize = Marshal.SizeOf(typeof(AvmMessageHeader)) + Marshal.SizeOf(typeof(AvmPolicy)) + sizeof(uint) + sizeof(uint);
            var buffer = new byte[headerSize + targetSize + fileRuleSize];
            using (var stream = new MemoryStream(buffer))
            using (var writer = new BinaryWriter(stream, Encoding.Unicode, true))
            {
                writer.Write(message.Header.MessageId);
                writer.Write((uint)(buffer.Length - Marshal.SizeOf(typeof(AvmMessageHeader))));
                WriteStruct(writer, message.Policy);
                writer.Write(message.TargetCount);
                for (var index = 0; index < AvmConstants.MaxTargets; index++)
                {
                    WriteStruct(writer, index < message.Targets.Length ? message.Targets[index] : default(AvmTargetEntry));
                }

                writer.Write(message.FileRuleCount);
                for (var index = 0; index < AvmConstants.MaxFileRules; index++)
                {
                    WriteStruct(writer, index < message.FileRules.Length ? message.FileRules[index] : default(AvmFileRule));
                }
            }

            return buffer;
        }

        private void SendBuffer(byte[] request, byte[] response)
        {
            var inHandle = GCHandle.Alloc(request, GCHandleType.Pinned);
            var outHandle = response != null ? GCHandle.Alloc(response, GCHandleType.Pinned) : default;
            try
            {
                var status = NativeMethods.FilterSendMessage(_port, inHandle.AddrOfPinnedObject(), (uint)request.Length, response != null ? outHandle.AddrOfPinnedObject() : IntPtr.Zero, response != null ? (uint)response.Length : 0, out var _);
                if (status != 0)
                {
                    throw new Win32Exception(status);
                }
            }
            finally
            {
                if (response != null)
                {
                    outHandle.Free();
                }
                inHandle.Free();
            }
        }

        private static byte[] MarshalToBuffer<T>(T value) where T : struct
        {
            var size = Marshal.SizeOf(typeof(T));
            var buffer = new byte[size];
            var handle = GCHandle.Alloc(buffer, GCHandleType.Pinned);
            try
            {
                Marshal.StructureToPtr(value, handle.AddrOfPinnedObject(), false);
                return buffer;
            }
            finally
            {
                handle.Free();
            }
        }

        private static T BufferToStruct<T>(byte[] buffer) where T : struct
        {
            var handle = GCHandle.Alloc(buffer, GCHandleType.Pinned);
            try
            {
                return Marshal.PtrToStructure<T>(handle.AddrOfPinnedObject());
            }
            finally
            {
                handle.Free();
            }
        }

        private static void WriteStruct<T>(BinaryWriter writer, T value) where T : struct
        {
            var size = Marshal.SizeOf(typeof(T));
            var buffer = new byte[size];
            var handle = GCHandle.Alloc(buffer, GCHandleType.Pinned);
            try
            {
                Marshal.StructureToPtr(value, handle.AddrOfPinnedObject(), false);
                writer.Write(buffer);
            }
            finally
            {
                handle.Free();
            }
        }
    }
}
