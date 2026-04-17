#include <fltKernel.h>
#include <ntstrsafe.h>
#include "..\..\shared\avm_shared.h"

/* ----------------------------------------------------------------
 * Default VMware artifact paths to hide
 * ---------------------------------------------------------------- */
static PCWSTR gDefaultHidePaths[] = {
    /* VMware driver files */
    L"C:\\Windows\\System32\\drivers\\vmci.sys",
    L"C:\\Windows\\System32\\drivers\\vmhgfs.sys",
    L"C:\\Windows\\System32\\drivers\\vmmouse.sys",
    L"C:\\Windows\\System32\\drivers\\vm3dmp.sys",
    L"C:\\Windows\\System32\\drivers\\vmxnet.sys",
    L"C:\\Windows\\System32\\drivers\\vmx_svga.sys",
    L"C:\\Windows\\System32\\drivers\\vm3dmp_loader.sys",
    L"C:\\Windows\\System32\\drivers\\vmrawdsk.sys",
    L"C:\\Windows\\System32\\drivers\\vmusbmouse.sys",
    L"C:\\Windows\\System32\\drivers\\vmxnet3.sys",
    /* VMware Tools */
    L"C:\\Program Files\\VMware\\VMware Tools\\vmtoolsd.exe",
    L"C:\\Program Files\\VMware\\VMware Tools\\VMwareToolboxCmd.exe",
    L"C:\\Program Files\\VMware",
    L"C:\\Program Files\\VMware\\VMware Tools",
    /* Common analysis tools - files that reveal an analysis environment */
    L"C:\\Program Files\\Wireshark",
    L"C:\\Program Files (x86)\\Wireshark",
    L"C:\\Program Files\\Wireshark\\Wireshark.exe",
    L"C:\\ProgramData\\chocolatey\\lib\\sysinternals",
};
#define AVM_DEFAULT_HIDE_COUNT (sizeof(gDefaultHidePaths) / sizeof(gDefaultHidePaths[0]))

/* ----------------------------------------------------------------
 * Global state
 * ---------------------------------------------------------------- */
typedef struct _AVM_FILTER_STATE {
    FAST_MUTEX Guard;
    PFLT_FILTER Filter;
    PFLT_PORT ServerPort;
    PFLT_PORT ClientPort;
    AVM_POLICY Policy;
    AVM_TARGET_ENTRY Targets[AVM_MAX_TARGETS];
    ULONG TargetCount;
    AVM_FILE_RULE FileRules[AVM_MAX_FILE_RULES];
    ULONG FileRuleCount;
    AVM_EVENT_BATCH EventBatch;
} AVM_FILTER_STATE;

static AVM_FILTER_STATE gState;

/* Forward declarations */
DRIVER_INITIALIZE DriverEntry;

static FLT_PREOP_CALLBACK_STATUS
AvmPreCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext);

static FLT_PREOP_CALLBACK_STATUS
AvmPreDirControl(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext);

static FLT_POSTOP_CALLBACK_STATUS
AvmPostDirControl(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags);

static NTSTATUS AvmUnload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags);

static NTSTATUS
AvmPortConnect(
    _In_ PFLT_PORT ClientPort,
    _In_opt_ PVOID ServerPortCookie,
    _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
    _In_ ULONG SizeOfContext,
    _Outptr_result_maybenull_ PVOID* ConnectionPortCookie);

static VOID AvmPortDisconnect(_In_opt_ PVOID ConnectionCookie);

static NTSTATUS
AvmMessageNotify(
    _In_opt_ PVOID PortCookie,
    _In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _Out_writes_bytes_to_opt_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG ReturnOutputBufferLength);

/* ----------------------------------------------------------------
 * Event logging
 * ---------------------------------------------------------------- */
static VOID
AvmFilterAppendEvent(
    _In_ ULONG Kind,
    _In_ ULONG Action,
    _In_opt_ PCWSTR Mechanism,
    _In_opt_ PCWSTR OriginalText,
    _In_opt_ PCWSTR SpoofedText)
{
    PAVM_EVENT_RECORD record;

    ExAcquireFastMutex(&gState.Guard);

    if (gState.EventBatch.Count >= AVM_MAX_FETCH_EVENTS) {
        RtlMoveMemory(&gState.EventBatch.Events[0],
                       &gState.EventBatch.Events[1],
                       sizeof(AVM_EVENT_RECORD) * (AVM_MAX_FETCH_EVENTS - 1));
        gState.EventBatch.Count = AVM_MAX_FETCH_EVENTS - 1;
    }

    record = &gState.EventBatch.Events[gState.EventBatch.Count++];
    RtlZeroMemory(record, sizeof(*record));
    record->Size = sizeof(*record);
    record->Source = AvmSourceMiniFilter;
    record->Kind = Kind;
    record->Action = Action;
    record->ProcessId = HandleToULong(PsGetCurrentProcessId());
    record->ThreadId = HandleToULong(PsGetCurrentThreadId());
    KeQuerySystemTimePrecise(&record->Timestamp);

    if (Mechanism)
        RtlStringCchCopyW(record->Mechanism, AVM_MAX_NAME_CHARS, Mechanism);
    if (OriginalText)
        RtlStringCchCopyW(record->OriginalText, AVM_MAX_TEXT_CHARS, OriginalText);
    if (SpoofedText)
        RtlStringCchCopyW(record->SpoofedText, AVM_MAX_TEXT_CHARS, SpoofedText);

    ExReleaseFastMutex(&gState.Guard);
}

/* ----------------------------------------------------------------
 * Targeting - check if current process should be filtered
 * ---------------------------------------------------------------- */
static BOOLEAN AvmIsTargeted(void)
{
    ULONG mode;
    ULONG currentPid;
    ULONG i;
    BOOLEAN result = FALSE;

    ExAcquireFastMutex(&gState.Guard);
    mode = gState.Policy.Mode;
    ExReleaseFastMutex(&gState.Guard);

    if (mode == AvmModeFull) {
        currentPid = HandleToULong(PsGetCurrentProcessId());
        return currentPid > 4;
    }

    if (mode != AvmModeSelective)
        return FALSE;

    currentPid = HandleToULong(PsGetCurrentProcessId());

    ExAcquireFastMutex(&gState.Guard);
    for (i = 0; i < gState.TargetCount; i++) {
        if (gState.Targets[i].Kind == AvmTargetByPid &&
            gState.Targets[i].ProcessId == currentPid) {
            result = TRUE;
            break;
        }
    }
    ExReleaseFastMutex(&gState.Guard);

    return result;
}

/* ----------------------------------------------------------------
 * Path matching helpers
 * ---------------------------------------------------------------- */
static WCHAR AvmToUpper(WCHAR c)
{
    return (c >= L'a' && c <= L'z') ? (WCHAR)(c - 32) : c;
}

/*
 * Check if NormalizedName ends with the portion of RulePath after
 * the drive letter. Case-insensitive comparison.
 */
static BOOLEAN
AvmPathMatchesSuffix(
    _In_ PCUNICODE_STRING NormalizedName,
    _In_ PCWSTR RulePath)
{
    PCWSTR suffix;
    USHORT suffixLen;
    USHORT nameChars;
    PWCH nameTail;
    USHORT i;

    if (!RulePath || RulePath[0] == L'\0') return FALSE;

    suffix = RulePath;
    if (suffix[0] != L'\0' && suffix[1] == L':')
        suffix += 2;

    suffixLen = (USHORT)wcslen(suffix);
    if (suffixLen == 0) return FALSE;

    nameChars = NormalizedName->Length / sizeof(WCHAR);
    if (nameChars < suffixLen) return FALSE;

    nameTail = NormalizedName->Buffer + (nameChars - suffixLen);
    for (i = 0; i < suffixLen; i++) {
        if (AvmToUpper(nameTail[i]) != AvmToUpper(suffix[i]))
            return FALSE;
    }
    return TRUE;
}

/* Extract the last path component after the final backslash */
static PCWSTR AvmGetFileName(PCWSTR Path)
{
    PCWSTR last = NULL;
    PCWSTR p;

    if (!Path) return NULL;
    for (p = Path; *p; p++) {
        if (*p == L'\\') last = p;
    }
    return last ? last + 1 : Path;
}

/*
 * Check a normalized file name against user rules and defaults.
 * Caller must hold gState.Guard.
 */
static BOOLEAN
AvmShouldHidePath_Locked(
    _In_ PCUNICODE_STRING NormalizedName)
{
    ULONG i;

    for (i = 0; i < gState.FileRuleCount; i++) {
        if (gState.FileRules[i].Action == AvmFileRuleHide &&
            AvmPathMatchesSuffix(NormalizedName, gState.FileRules[i].MatchPath)) {
            return TRUE;
        }
    }

    for (i = 0; i < AVM_DEFAULT_HIDE_COUNT; i++) {
        if (AvmPathMatchesSuffix(NormalizedName, gDefaultHidePaths[i]))
            return TRUE;
    }
    return FALSE;
}

/*
 * Check if a directory entry should be hidden.
 * Matches entry name against the file-name component of each rule
 * AND verifies the directory matches the rule's parent path.
 * Caller must hold gState.Guard.
 */
static BOOLEAN
AvmShouldHideEntry_Locked(
    _In_ PCUNICODE_STRING DirName,
    _In_ PCWSTR EntryName,
    _In_ USHORT EntryNameChars)
{
    ULONG i;
    ULONG checkCount;
    PCWSTR checkPath;
    PCWSTR ruleFileName;
    USHORT ruleFileNameLen;
    USHORT j;
    BOOLEAN nameMatch;
    USHORT parentLen;
    PCWSTR stripped;
    USHORT strippedLen;
    USHORT dirChars;
    PWCH dirTail;
    BOOLEAN dirMatch;

    checkCount = gState.FileRuleCount + AVM_DEFAULT_HIDE_COUNT;

    for (i = 0; i < checkCount; i++) {
        if (i < gState.FileRuleCount) {
            if (gState.FileRules[i].Action != AvmFileRuleHide) continue;
            checkPath = gState.FileRules[i].MatchPath;
        } else {
            checkPath = gDefaultHidePaths[i - gState.FileRuleCount];
        }

        ruleFileName = AvmGetFileName(checkPath);
        if (!ruleFileName || ruleFileName[0] == L'\0') continue;
        ruleFileNameLen = (USHORT)wcslen(ruleFileName);

        if (ruleFileNameLen != EntryNameChars) continue;

        nameMatch = TRUE;
        for (j = 0; j < ruleFileNameLen; j++) {
            if (AvmToUpper(EntryName[j]) != AvmToUpper(ruleFileName[j])) {
                nameMatch = FALSE;
                break;
            }
        }
        if (!nameMatch) continue;

        /* Verify directory matches rule's parent path */
        parentLen = (USHORT)(ruleFileName - checkPath);
        if (parentLen > 0 && checkPath[parentLen - 1] == L'\\')
            parentLen--;

        stripped = checkPath;
        strippedLen = parentLen;
        if (stripped[0] != L'\0' && stripped[1] == L':' && strippedLen >= 2) {
            stripped += 2;
            strippedLen -= 2;
        }

        if (strippedLen == 0)
            return TRUE;

        dirChars = DirName->Length / sizeof(WCHAR);
        if (dirChars < strippedLen) continue;

        dirTail = DirName->Buffer + (dirChars - strippedLen);
        dirMatch = TRUE;
        for (j = 0; j < strippedLen; j++) {
            if (AvmToUpper(dirTail[j]) != AvmToUpper(stripped[j])) {
                dirMatch = FALSE;
                break;
            }
        }
        if (dirMatch) return TRUE;
    }

    return FALSE;
}

/* ----------------------------------------------------------------
 * PreCreate callback - hide file artifacts
 * ---------------------------------------------------------------- */
static FLT_PREOP_CALLBACK_STATUS
AvmPreCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext)
{
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    NTSTATUS status;
    ULONG enabledChecks;
    BOOLEAN shouldHide = FALSE;
    WCHAR truncName[AVM_MAX_TEXT_CHARS];
    USHORT copyLen;

    UNREFERENCED_PARAMETER(FltObjects);
    *CompletionContext = NULL;

    ExAcquireFastMutex(&gState.Guard);
    enabledChecks = gState.Policy.EnabledChecks;
    ExReleaseFastMutex(&gState.Guard);

    if (!(enabledChecks & AvmCheckFileArtifacts))
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    if (!AvmIsTargeted())
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    status = FltGetFileNameInformation(Data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
        &nameInfo);
    if (!NT_SUCCESS(status))
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    status = FltParseFileNameInformation(nameInfo);
    if (!NT_SUCCESS(status)) {
        FltReleaseFileNameInformation(nameInfo);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    ExAcquireFastMutex(&gState.Guard);
    shouldHide = AvmShouldHidePath_Locked(&nameInfo->Name);
    ExReleaseFastMutex(&gState.Guard);

    if (shouldHide) {
        RtlZeroMemory(truncName, sizeof(truncName));
        copyLen = nameInfo->Name.Length / sizeof(WCHAR);
        if (copyLen >= AVM_MAX_TEXT_CHARS) copyLen = AVM_MAX_TEXT_CHARS - 1;
        RtlCopyMemory(truncName, nameInfo->Name.Buffer, copyLen * sizeof(WCHAR));

        AvmFilterAppendEvent(AvmEventFileProbe, AvmActionHide,
            L"PreCreate", truncName, L"hidden");

        FltReleaseFileNameInformation(nameInfo);
        Data->IoStatus.Status = STATUS_OBJECT_NAME_NOT_FOUND;
        Data->IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;
    }

    FltReleaseFileNameInformation(nameInfo);
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

/* ----------------------------------------------------------------
 * PreDirControl - request post-operation callback
 * ---------------------------------------------------------------- */
static FLT_PREOP_CALLBACK_STATUS
AvmPreDirControl(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext)
{
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(FltObjects);
    *CompletionContext = NULL;
    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

/* ----------------------------------------------------------------
 * PostDirControl - filter directory entries
 * ---------------------------------------------------------------- */
static FLT_POSTOP_CALLBACK_STATUS
AvmPostDirControl(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags)
{
    PFLT_FILE_NAME_INFORMATION dirInfo = NULL;
    NTSTATUS status;
    PVOID buffer;
    ULONG enabledChecks;
    FILE_INFORMATION_CLASS infoClass;
    ULONG nameOffset = 0;
    ULONG nameLenOffset = 0;
    PUCHAR current;
    PUCHAR prev;
    ULONG nextOffset;
    ULONG hiddenCount = 0;
    ULONG totalBytes;
    PCWSTR entryName;
    ULONG entryNameLen;
    USHORT entryNameChars;
    BOOLEAN shouldHide;
    BOOLEAN allHidden = FALSE;

    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    if (FlagOn(Flags, FLTFL_POST_OPERATION_DRAINING))
        return FLT_POSTOP_FINISHED_PROCESSING;

    if (!NT_SUCCESS(Data->IoStatus.Status))
        return FLT_POSTOP_FINISHED_PROCESSING;

    if (Data->Iopb->MinorFunction != IRP_MN_QUERY_DIRECTORY)
        return FLT_POSTOP_FINISHED_PROCESSING;

    ExAcquireFastMutex(&gState.Guard);
    enabledChecks = gState.Policy.EnabledChecks;
    ExReleaseFastMutex(&gState.Guard);

    if (!(enabledChecks & AvmCheckDirectoryFilter))
        return FLT_POSTOP_FINISHED_PROCESSING;

    if (!AvmIsTargeted())
        return FLT_POSTOP_FINISHED_PROCESSING;

    buffer = Data->Iopb->Parameters.DirectoryControl.QueryDirectory.DirectoryBuffer;
    if (!buffer)
        return FLT_POSTOP_FINISHED_PROCESSING;

    infoClass = Data->Iopb->Parameters.DirectoryControl.QueryDirectory.FileInformationClass;

    switch (infoClass) {
    case FileDirectoryInformation:
        nameOffset = FIELD_OFFSET(FILE_DIRECTORY_INFORMATION, FileName);
        nameLenOffset = FIELD_OFFSET(FILE_DIRECTORY_INFORMATION, FileNameLength);
        break;
    case FileBothDirectoryInformation:
        nameOffset = FIELD_OFFSET(FILE_BOTH_DIR_INFORMATION, FileName);
        nameLenOffset = FIELD_OFFSET(FILE_BOTH_DIR_INFORMATION, FileNameLength);
        break;
    case FileFullDirectoryInformation:
        nameOffset = FIELD_OFFSET(FILE_FULL_DIR_INFORMATION, FileName);
        nameLenOffset = FIELD_OFFSET(FILE_FULL_DIR_INFORMATION, FileNameLength);
        break;
    case FileIdBothDirectoryInformation:
        nameOffset = FIELD_OFFSET(FILE_ID_BOTH_DIR_INFORMATION, FileName);
        nameLenOffset = FIELD_OFFSET(FILE_ID_BOTH_DIR_INFORMATION, FileNameLength);
        break;
    case FileIdFullDirectoryInformation:
        nameOffset = FIELD_OFFSET(FILE_ID_FULL_DIR_INFORMATION, FileName);
        nameLenOffset = FIELD_OFFSET(FILE_ID_FULL_DIR_INFORMATION, FileNameLength);
        break;
    case FileNamesInformation:
        nameOffset = FIELD_OFFSET(FILE_NAMES_INFORMATION, FileName);
        nameLenOffset = FIELD_OFFSET(FILE_NAMES_INFORMATION, FileNameLength);
        break;
    default:
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    status = FltGetFileNameInformation(Data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
        &dirInfo);
    if (!NT_SUCCESS(status))
        return FLT_POSTOP_FINISHED_PROCESSING;

    FltParseFileNameInformation(dirInfo);

    totalBytes = (ULONG)Data->IoStatus.Information;
    prev = NULL;
    current = (PUCHAR)buffer;

    ExAcquireFastMutex(&gState.Guard);

    for (;;) {
        nextOffset = *(PULONG)current;
        entryNameLen = *(PULONG)(current + nameLenOffset);
        entryName = (PCWSTR)(current + nameOffset);
        entryNameChars = (USHORT)(entryNameLen / sizeof(WCHAR));

        shouldHide = AvmShouldHideEntry_Locked(
            &dirInfo->Name, entryName, entryNameChars);

        if (shouldHide) {
            hiddenCount++;

            if (prev == NULL) {
                if (nextOffset == 0) {
                    allHidden = TRUE;
                    break;
                }
                RtlMoveMemory(current, current + nextOffset,
                              totalBytes - nextOffset);
                totalBytes -= nextOffset;
                Data->IoStatus.Information = totalBytes;
                continue;
            } else {
                if (nextOffset == 0) {
                    *(PULONG)prev = 0;
                    break;
                }
                *(PULONG)prev += nextOffset;
                current = prev + *(PULONG)prev;
                continue;
            }
        }

        prev = current;
        if (nextOffset == 0) break;
        current += nextOffset;
    }

    ExReleaseFastMutex(&gState.Guard);

    if (allHidden) {
        Data->IoStatus.Status = STATUS_NO_MORE_FILES;
        Data->IoStatus.Information = 0;
    }

    FltReleaseFileNameInformation(dirInfo);

    if (hiddenCount > 0) {
        AvmFilterAppendEvent(AvmEventDirectoryEnum, AvmActionHide,
            L"PostDirControl", L"entries-filtered", L"hidden");
    }

    return FLT_POSTOP_FINISHED_PROCESSING;
}

/* ----------------------------------------------------------------
 * Communication port callbacks
 * ---------------------------------------------------------------- */
static NTSTATUS
AvmPortConnect(
    _In_ PFLT_PORT ClientPort,
    _In_opt_ PVOID ServerPortCookie,
    _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
    _In_ ULONG SizeOfContext,
    _Outptr_result_maybenull_ PVOID* ConnectionPortCookie)
{
    UNREFERENCED_PARAMETER(ServerPortCookie);
    UNREFERENCED_PARAMETER(ConnectionContext);
    UNREFERENCED_PARAMETER(SizeOfContext);

    gState.ClientPort = ClientPort;
    if (ConnectionPortCookie)
        *ConnectionPortCookie = NULL;

    return STATUS_SUCCESS;
}

static VOID AvmPortDisconnect(_In_opt_ PVOID ConnectionCookie)
{
    UNREFERENCED_PARAMETER(ConnectionCookie);
    FltCloseClientPort(gState.Filter, &gState.ClientPort);
    gState.ClientPort = NULL;
}

static NTSTATUS
AvmMessageNotify(
    _In_opt_ PVOID PortCookie,
    _In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _Out_writes_bytes_to_opt_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG ReturnOutputBufferLength)
{
    PAVM_MESSAGE_HEADER header;
    PAVM_MINIFILTER_POLICY_MESSAGE policyMsg;
    PAVM_STATUS_SNAPSHOT snapshot;

    UNREFERENCED_PARAMETER(PortCookie);

    if (ReturnOutputBufferLength)
        *ReturnOutputBufferLength = 0;

    if (!InputBuffer || InputBufferLength < sizeof(AVM_MESSAGE_HEADER))
        return STATUS_INVALID_PARAMETER;

    header = (PAVM_MESSAGE_HEADER)InputBuffer;

    switch (header->MessageId) {
    case AVM_MESSAGE_SET_POLICY:
        if (InputBufferLength >= sizeof(AVM_MINIFILTER_POLICY_MESSAGE)) {
            policyMsg = (PAVM_MINIFILTER_POLICY_MESSAGE)InputBuffer;
            ExAcquireFastMutex(&gState.Guard);
            gState.Policy = policyMsg->Policy;
            gState.TargetCount = policyMsg->TargetCount;
            if (gState.TargetCount > AVM_MAX_TARGETS)
                gState.TargetCount = AVM_MAX_TARGETS;
            RtlCopyMemory(gState.Targets, policyMsg->Targets,
                sizeof(AVM_TARGET_ENTRY) * gState.TargetCount);
            gState.FileRuleCount = policyMsg->FileRuleCount;
            if (gState.FileRuleCount > AVM_MAX_FILE_RULES)
                gState.FileRuleCount = AVM_MAX_FILE_RULES;
            RtlCopyMemory(gState.FileRules, policyMsg->FileRules,
                sizeof(AVM_FILE_RULE) * gState.FileRuleCount);
            ExReleaseFastMutex(&gState.Guard);
            AvmFilterAppendEvent(AvmEventPolicyUpdate, AvmActionLog,
                L"SetPolicy", L"policy-applied", L"active");
        }
        break;

    case AVM_MESSAGE_GET_STATUS:
        if (OutputBuffer && OutputBufferLength >= sizeof(AVM_STATUS_SNAPSHOT)) {
            snapshot = (PAVM_STATUS_SNAPSHOT)OutputBuffer;
            ExAcquireFastMutex(&gState.Guard);
            RtlZeroMemory(snapshot, sizeof(*snapshot));
            snapshot->Version = AVM_VERSION;
            snapshot->Mode = gState.Policy.Mode;
            snapshot->EnabledChecks = gState.Policy.EnabledChecks;
            snapshot->TargetCount = gState.TargetCount;
            snapshot->EventCount = gState.EventBatch.Count;
            snapshot->FileRuleCount = gState.FileRuleCount;
            snapshot->ControllerConnected = (gState.ClientPort != NULL) ? 1u : 0u;
            ExReleaseFastMutex(&gState.Guard);
            if (ReturnOutputBufferLength)
                *ReturnOutputBufferLength = sizeof(AVM_STATUS_SNAPSHOT);
        }
        break;

    case AVM_MESSAGE_FETCH_EVENTS:
        if (OutputBuffer && OutputBufferLength >= sizeof(AVM_EVENT_BATCH)) {
            ExAcquireFastMutex(&gState.Guard);
            RtlCopyMemory(OutputBuffer, &gState.EventBatch, sizeof(AVM_EVENT_BATCH));
            gState.EventBatch.Count = 0;
            ExReleaseFastMutex(&gState.Guard);
            if (ReturnOutputBufferLength)
                *ReturnOutputBufferLength = sizeof(AVM_EVENT_BATCH);
        }
        break;

    default:
        return STATUS_INVALID_PARAMETER;
    }

    return STATUS_SUCCESS;
}

/* ----------------------------------------------------------------
 * Filter registration
 * ---------------------------------------------------------------- */
CONST FLT_OPERATION_REGISTRATION gCallbacks[] = {
    { IRP_MJ_CREATE,            0, AvmPreCreate,     NULL              },
    { IRP_MJ_DIRECTORY_CONTROL, 0, AvmPreDirControl, AvmPostDirControl },
    { IRP_MJ_OPERATION_END }
};

CONST FLT_REGISTRATION gFilterRegistration = {
    sizeof(FLT_REGISTRATION),
    FLT_REGISTRATION_VERSION,
    0,
    NULL,
    gCallbacks,
    AvmUnload,
    NULL,   /* InstanceSetup */
    NULL,   /* InstanceQueryTeardown */
    NULL,   /* InstanceTeardownStart */
    NULL,   /* InstanceTeardownComplete */
    NULL,   /* GenerateFileName */
    NULL,   /* NormalizeNameComponent */
    NULL,   /* NormalizeContextCleanup */
    NULL,   /* TransactionNotification */
    NULL    /* NormalizeNameComponentEx */
};

/* ----------------------------------------------------------------
 * Unload
 * ---------------------------------------------------------------- */
static NTSTATUS AvmUnload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(Flags);

    if (gState.ServerPort != NULL) {
        FltCloseCommunicationPort(gState.ServerPort);
        gState.ServerPort = NULL;
    }

    if (gState.Filter != NULL) {
        FltUnregisterFilter(gState.Filter);
        gState.Filter = NULL;
    }

    return STATUS_SUCCESS;
}

/* ----------------------------------------------------------------
 * DriverEntry
 * ---------------------------------------------------------------- */
NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath)
{
    NTSTATUS status;
    PSECURITY_DESCRIPTOR sd = NULL;
    UNICODE_STRING portName;
    OBJECT_ATTRIBUTES oa;

    UNREFERENCED_PARAMETER(RegistryPath);

    RtlZeroMemory(&gState, sizeof(gState));
    ExInitializeFastMutex(&gState.Guard);
    gState.Policy.Version = AVM_VERSION;
    gState.Policy.Mode = AvmModeObserve;
    gState.Policy.EnabledChecks =
        AvmCheckDebugger | AvmCheckTiming | AvmCheckNativeApi |
        AvmCheckProcessEnum | AvmCheckDriverDeviceProbe |
        AvmCheckRegistryArtifacts | AvmCheckFileArtifacts |
        AvmCheckDirectoryFilter;
    gState.Policy.EventQueueCapacity = AVM_MAX_EVENTS;
    gState.Policy.RuntimePolicyRefreshMs = 1000;
    gState.Policy.DefaultConcealmentMask = gState.Policy.EnabledChecks;
    gState.Policy.DefaultLogMask = 0xFFFFFFFF;

    status = FltRegisterFilter(DriverObject, &gFilterRegistration, &gState.Filter);
    if (!NT_SUCCESS(status))
        return status;

    status = FltBuildDefaultSecurityDescriptor(&sd, FLT_PORT_ALL_ACCESS);
    if (!NT_SUCCESS(status)) {
        FltUnregisterFilter(gState.Filter);
        gState.Filter = NULL;
        return status;
    }

    RtlInitUnicodeString(&portName, AVM_MINIFILTER_PORT_NAME);
    InitializeObjectAttributes(&oa, &portName,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, sd);

    status = FltCreateCommunicationPort(
        gState.Filter,
        &gState.ServerPort,
        &oa,
        NULL,
        AvmPortConnect,
        AvmPortDisconnect,
        AvmMessageNotify,
        1);

    FltFreeSecurityDescriptor(sd);

    if (!NT_SUCCESS(status)) {
        FltUnregisterFilter(gState.Filter);
        gState.Filter = NULL;
        return status;
    }

    status = FltStartFiltering(gState.Filter);
    if (!NT_SUCCESS(status)) {
        FltCloseCommunicationPort(gState.ServerPort);
        gState.ServerPort = NULL;
        FltUnregisterFilter(gState.Filter);
        gState.Filter = NULL;
        return status;
    }

    return STATUS_SUCCESS;
}
