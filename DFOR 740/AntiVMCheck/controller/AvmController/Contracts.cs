using System;
using System.Runtime.InteropServices;

namespace AvmController
{
    internal static class AvmConstants
    {
        public const string KernelDevicePath = @"\\.\AvmKernel";
        public const string MiniFilterPort = @"\AvmMiniFilterPort";
        public const int MaxPath = 260;
        public const int MaxName = 64;
        public const int MaxText = 128;
        public const int MaxTargets = 64;
        public const int MaxEventsPerFetch = 64;
        public const int MaxFileRules = 32;

        public static readonly uint IoctlSetPolicy = CtlCode(0xA417, 0x801, 0, 0);
        public static readonly uint IoctlGetStatus = CtlCode(0xA417, 0x802, 0, 1);
        public static readonly uint IoctlClearTargets = CtlCode(0xA417, 0x803, 0, 2);
        public static readonly uint IoctlAddTarget = CtlCode(0xA417, 0x804, 0, 2);
        public static readonly uint IoctlClearNameRules = CtlCode(0xA417, 0x805, 0, 2);
        public static readonly uint IoctlAddNameRule = CtlCode(0xA417, 0x806, 0, 2);
        public static readonly uint IoctlFetchEvents = CtlCode(0xA417, 0x807, 0, 1);
        public static readonly uint IoctlSubmitRuntimeEvent = CtlCode(0xA417, 0x808, 0, 2);
        public static readonly uint IoctlHeartbeat = CtlCode(0xA417, 0x809, 0, 0);
        public static readonly uint IoctlClearFileRules = CtlCode(0xA417, 0x80A, 0, 2);
        public static readonly uint IoctlAddFileRule = CtlCode(0xA417, 0x80B, 0, 2);
        public static readonly uint IoctlGetPolicy = CtlCode(0xA417, 0x80C, 0, 1);

        public const uint MessageSetPolicy = 1;
        public const uint MessageFetchEvents = 2;
        public const uint MessageGetStatus = 3;

        private static uint CtlCode(uint deviceType, uint function, uint method, uint access)
        {
            return (deviceType << 16) | (access << 14) | (function << 2) | method;
        }
    }

    [Flags]
    internal enum AvmCheckFlags : uint
    {
        Debugger = 0x1,
        Timing = 0x2,
        NativeApi = 0x4,
        ProcessEnum = 0x8,
        DriverDeviceProbe = 0x10,
        RegistryArtifacts = 0x20,
        FileArtifacts = 0x40,
        DirectoryFilter = 0x80
    }

    internal enum AvmMode : uint
    {
        Observe = 0,
        Selective = 1,
        Full = 2
    }

    internal enum AvmTargetKind : uint
    {
        Pid = 0,
        ImageName = 1,
        ImagePathPrefix = 2
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct AvmPolicy
    {
        public uint Version;
        public uint Mode;
        public uint EnabledChecks;
        public uint Reserved;
        public uint EventQueueCapacity;
        public uint RuntimePolicyRefreshMs;
        public uint DefaultConcealmentMask;
        public uint DefaultLogMask;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct AvmTargetEntry
    {
        public uint Kind;
        public uint ProcessId;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = AvmConstants.MaxPath)]
        public string Pattern;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct AvmFileRule
    {
        public uint Action;
        public uint Reserved;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = AvmConstants.MaxPath)]
        public string MatchPath;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = AvmConstants.MaxPath)]
        public string RedirectPath;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct AvmStatusSnapshot
    {
        public uint Version;
        public uint Mode;
        public uint EnabledChecks;
        public uint TargetCount;
        public uint EventCount;
        public uint NameRuleCount;
        public uint FileRuleCount;
        public uint ControllerConnected;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct AvmEventRecord
    {
        public uint Size;
        public uint Source;
        public uint Kind;
        public uint Action;
        public uint ProcessId;
        public uint ThreadId;
        public int OriginalStatus;
        public int SpoofedStatus;
        public long Timestamp;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = AvmConstants.MaxPath)]
        public string ImagePath;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = AvmConstants.MaxName)]
        public string Mechanism;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = AvmConstants.MaxText)]
        public string OriginalText;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = AvmConstants.MaxText)]
        public string SpoofedText;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct AvmEventBatch
    {
        public uint Count;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = AvmConstants.MaxEventsPerFetch)]
        public AvmEventRecord[] Events;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct AvmMessageHeader
    {
        public uint MessageId;
        public uint PayloadSize;
    }

    internal sealed class AvmFilterPolicyMessage
    {
        public AvmMessageHeader Header;
        public AvmPolicy Policy;
        public uint TargetCount;
        public AvmTargetEntry[] Targets = Array.Empty<AvmTargetEntry>();
        public uint FileRuleCount;
        public AvmFileRule[] FileRules = Array.Empty<AvmFileRule>();
    }
}
