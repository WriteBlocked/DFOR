#pragma once

#ifdef _KERNEL_MODE
#include <ntddk.h>
#include <ntstrsafe.h>
#else
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>
#include <winioctl.h>
#endif

#define AVM_VERSION 1u
#define AVM_DEVICE_TYPE 0xA417u

#define AVM_MAX_PATH_CHARS 260u
#define AVM_MAX_NAME_CHARS 64u
#define AVM_MAX_TEXT_CHARS 128u
#define AVM_MAX_TARGETS 64u
#define AVM_MAX_EVENTS 512u
#define AVM_MAX_FETCH_EVENTS 64u
#define AVM_MAX_NAME_RULES 32u
#define AVM_MAX_FILE_RULES 32u

#define AVM_KERNEL_NT_DEVICE      L"\\Device\\AvmKernel"
#define AVM_KERNEL_DOS_DEVICE     L"\\DosDevices\\AvmKernel"
#define AVM_KERNEL_USER_PATH      L"\\\\.\\AvmKernel"
#define AVM_MINIFILTER_PORT_NAME  L"\\AvmMiniFilterPort"

#define AVM_MESSAGE_SET_POLICY 1u
#define AVM_MESSAGE_FETCH_EVENTS 2u
#define AVM_MESSAGE_GET_STATUS 3u

typedef enum _AVM_MODE {
    AvmModeObserve = 0,
    AvmModeSelective = 1,
    AvmModeFull = 2
} AVM_MODE;

typedef enum _AVM_CHECK_FLAG {
    AvmCheckDebugger          = 0x00000001,
    AvmCheckTiming            = 0x00000002,
    AvmCheckNativeApi         = 0x00000004,
    AvmCheckProcessEnum       = 0x00000008,
    AvmCheckDriverDeviceProbe = 0x00000010,
    AvmCheckRegistryArtifacts = 0x00000020,
    AvmCheckFileArtifacts     = 0x00000040,
    AvmCheckDirectoryFilter   = 0x00000080
} AVM_CHECK_FLAG;

typedef enum _AVM_TARGET_KIND {
    AvmTargetByPid = 0,
    AvmTargetByImageName = 1,
    AvmTargetByImagePathPrefix = 2
} AVM_TARGET_KIND;

typedef enum _AVM_EVENT_SOURCE {
    AvmSourceKernel = 1,
    AvmSourceRuntime = 2,
    AvmSourceMiniFilter = 3
} AVM_EVENT_SOURCE;

typedef enum _AVM_EVENT_KIND {
    AvmEventProcessStart = 1,
    AvmEventProcessExit = 2,
    AvmEventImageLoad = 3,
    AvmEventHandleProbe = 4,
    AvmEventRegistryProbe = 5,
    AvmEventDebuggerCheck = 6,
    AvmEventTimingCheck = 7,
    AvmEventNativeApiCall = 8,
    AvmEventFileProbe = 9,
    AvmEventDirectoryEnum = 10,
    AvmEventPolicyUpdate = 11,
    AvmEventTargetUpdate = 12
} AVM_EVENT_KIND;

typedef enum _AVM_POLICY_ACTION {
    AvmActionLog = 0,
    AvmActionAllow = 1,
    AvmActionBlock = 2,
    AvmActionSpoof = 3,
    AvmActionHide = 4,
    AvmActionRedirect = 5
} AVM_POLICY_ACTION;

typedef enum _AVM_NAME_RULE_KIND {
    AvmNameRuleHiddenProcess = 1,
    AvmNameRuleHiddenModule = 2,
    AvmNameRuleHiddenDevice = 3,
    AvmNameRuleRegistryPrefix = 4
} AVM_NAME_RULE_KIND;

typedef enum _AVM_FILE_RULE_ACTION {
    AvmFileRuleHide = 1,
    AvmFileRuleRedirect = 2
} AVM_FILE_RULE_ACTION;

typedef struct _AVM_POLICY {
    ULONG Version;
    ULONG Mode;
    ULONG EnabledChecks;
    ULONG Reserved;
    ULONG EventQueueCapacity;
    ULONG RuntimePolicyRefreshMs;
    ULONG DefaultConcealmentMask;
    ULONG DefaultLogMask;
} AVM_POLICY, *PAVM_POLICY;

typedef struct _AVM_TARGET_ENTRY {
    ULONG Kind;
    ULONG ProcessId;
    WCHAR Pattern[AVM_MAX_PATH_CHARS];
} AVM_TARGET_ENTRY, *PAVM_TARGET_ENTRY;

typedef struct _AVM_NAME_RULE {
    ULONG Kind;
    ULONG Action;
    WCHAR Pattern[AVM_MAX_PATH_CHARS];
} AVM_NAME_RULE, *PAVM_NAME_RULE;

typedef struct _AVM_FILE_RULE {
    ULONG Action;
    ULONG Reserved;
    WCHAR MatchPath[AVM_MAX_PATH_CHARS];
    WCHAR RedirectPath[AVM_MAX_PATH_CHARS];
} AVM_FILE_RULE, *PAVM_FILE_RULE;

typedef struct _AVM_STATUS_SNAPSHOT {
    ULONG Version;
    ULONG Mode;
    ULONG EnabledChecks;
    ULONG TargetCount;
    ULONG EventCount;
    ULONG NameRuleCount;
    ULONG FileRuleCount;
    ULONG ControllerConnected;
} AVM_STATUS_SNAPSHOT, *PAVM_STATUS_SNAPSHOT;

typedef struct _AVM_EVENT_RECORD {
    ULONG Size;
    ULONG Source;
    ULONG Kind;
    ULONG Action;
    ULONG ProcessId;
    ULONG ThreadId;
    LONG OriginalStatus;
    LONG SpoofedStatus;
    LARGE_INTEGER Timestamp;
    WCHAR ImagePath[AVM_MAX_PATH_CHARS];
    WCHAR Mechanism[AVM_MAX_NAME_CHARS];
    WCHAR OriginalText[AVM_MAX_TEXT_CHARS];
    WCHAR SpoofedText[AVM_MAX_TEXT_CHARS];
} AVM_EVENT_RECORD, *PAVM_EVENT_RECORD;

typedef struct _AVM_EVENT_BATCH {
    ULONG Count;
    AVM_EVENT_RECORD Events[AVM_MAX_FETCH_EVENTS];
} AVM_EVENT_BATCH, *PAVM_EVENT_BATCH;

typedef struct _AVM_MESSAGE_HEADER {
    ULONG MessageId;
    ULONG PayloadSize;
} AVM_MESSAGE_HEADER, *PAVM_MESSAGE_HEADER;

typedef struct _AVM_MINIFILTER_POLICY_MESSAGE {
    AVM_MESSAGE_HEADER Header;
    AVM_POLICY Policy;
    ULONG TargetCount;
    AVM_TARGET_ENTRY Targets[AVM_MAX_TARGETS];
    ULONG FileRuleCount;
    AVM_FILE_RULE FileRules[AVM_MAX_FILE_RULES];
} AVM_MINIFILTER_POLICY_MESSAGE, *PAVM_MINIFILTER_POLICY_MESSAGE;

typedef struct _AVM_MINIFILTER_EVENT_MESSAGE {
    AVM_MESSAGE_HEADER Header;
    AVM_EVENT_RECORD Event;
} AVM_MINIFILTER_EVENT_MESSAGE, *PAVM_MINIFILTER_EVENT_MESSAGE;

#define AVM_IOCTL_SET_POLICY           CTL_CODE(AVM_DEVICE_TYPE, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define AVM_IOCTL_GET_STATUS           CTL_CODE(AVM_DEVICE_TYPE, 0x802, METHOD_BUFFERED, FILE_READ_ACCESS)
#define AVM_IOCTL_CLEAR_TARGETS        CTL_CODE(AVM_DEVICE_TYPE, 0x803, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define AVM_IOCTL_ADD_TARGET           CTL_CODE(AVM_DEVICE_TYPE, 0x804, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define AVM_IOCTL_CLEAR_NAME_RULES     CTL_CODE(AVM_DEVICE_TYPE, 0x805, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define AVM_IOCTL_ADD_NAME_RULE        CTL_CODE(AVM_DEVICE_TYPE, 0x806, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define AVM_IOCTL_FETCH_EVENTS         CTL_CODE(AVM_DEVICE_TYPE, 0x807, METHOD_BUFFERED, FILE_READ_ACCESS)
#define AVM_IOCTL_SUBMIT_RUNTIME_EVENT CTL_CODE(AVM_DEVICE_TYPE, 0x808, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define AVM_IOCTL_HEARTBEAT            CTL_CODE(AVM_DEVICE_TYPE, 0x809, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define AVM_IOCTL_CLEAR_FILE_RULES     CTL_CODE(AVM_DEVICE_TYPE, 0x80A, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define AVM_IOCTL_ADD_FILE_RULE        CTL_CODE(AVM_DEVICE_TYPE, 0x80B, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define AVM_IOCTL_GET_POLICY           CTL_CODE(AVM_DEVICE_TYPE, 0x80C, METHOD_BUFFERED, FILE_READ_ACCESS)

