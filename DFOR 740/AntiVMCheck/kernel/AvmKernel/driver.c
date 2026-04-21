#include "driver.h"

static AVM_KERNEL_STATE gState;

/* Forward declaration */
static VOID AvmAppendEvent(_In_ ULONG Kind, _In_ ULONG Action, _In_opt_ PCWSTR Mechanism, _In_opt_ PCWSTR OriginalText, _In_opt_ PCWSTR SpoofedText);

/* ----------------------------------------------------------------
 * Registry key leaf names to block (VM indicators)
 * ---------------------------------------------------------------- */
static PCWSTR gRegistryBlockLeaves[] = {
    /* VMware */
    L"VMware, Inc.",
    L"VMware Tools",
    L"VMware VGAuth",
    L"vmci",
    L"vmhgfs",
    L"vmmouse",
    L"VMTools",
    L"vmvss",
    L"vm3dmp",
    L"vmrawdsk",
    L"vmusbmouse",
    L"VGAuth",
    L"vm3dmp-debug",
    L"vm3dmp-stats",
    L"vm3dmp_loader",
    L"vmxnet3",
    /* VirtualBox */
    L"VirtualBox",
    L"Oracle",
    L"VirtualBox Guest Additions",
    L"VBoxGuest",
    L"VBoxMouse",
    L"VBoxSF",
    L"VBoxVideo",
    L"VBoxService",
    L"VBoxTray",
    L"VBoxWddm",
};
#define AVM_REGISTRY_BLOCK_COUNT (sizeof(gRegistryBlockLeaves) / sizeof(gRegistryBlockLeaves[0]))

/* Default file paths the kernel driver can load into its rule set */
static PCWSTR gDefaultHidePaths[] = {
    /* VMware drivers */
    L"C:\\Windows\\System32\\drivers\\vmci.sys",
    L"C:\\Windows\\System32\\drivers\\vmhgfs.sys",
    L"C:\\Windows\\System32\\drivers\\vmmouse.sys",
    L"C:\\Windows\\System32\\drivers\\vm3dmp.sys",
    L"C:\\Windows\\System32\\drivers\\vmxnet.sys",
    L"C:\\Windows\\System32\\drivers\\vm3dmp_loader.sys",
    L"C:\\Windows\\System32\\drivers\\vmrawdsk.sys",
    L"C:\\Windows\\System32\\drivers\\vmusbmouse.sys",
    L"C:\\Windows\\System32\\drivers\\vmxnet3.sys",
    L"C:\\Windows\\System32\\drivers\\vmx_svga.sys",
    L"C:\\Program Files\\VMware\\VMware Tools\\vmtoolsd.exe",
    L"C:\\Program Files\\VMware\\VMware Tools\\VMwareToolboxCmd.exe",
    L"C:\\Program Files\\VMware",
    L"C:\\Program Files\\VMware\\VMware Tools",
    /* VirtualBox drivers and files */
    L"C:\\Windows\\System32\\drivers\\VBoxGuest.sys",
    L"C:\\Windows\\System32\\drivers\\VBoxMouse.sys",
    L"C:\\Windows\\System32\\drivers\\VBoxSF.sys",
    L"C:\\Windows\\System32\\drivers\\VBoxVideo.sys",
    L"C:\\Windows\\System32\\drivers\\VBoxWddm.sys",
    L"C:\\Windows\\System32\\VBoxControl.exe",
    L"C:\\Windows\\System32\\VBoxService.exe",
    L"C:\\Windows\\System32\\VBoxTray.exe",
    L"C:\\Windows\\System32\\VBoxDisp.dll",
    L"C:\\Windows\\System32\\VBoxHook.dll",
    L"C:\\Windows\\System32\\VBoxOGL.dll",
    L"C:\\Program Files\\Oracle\\VirtualBox Guest Additions",
    L"C:\\Program Files\\Oracle",
};
#define AVM_DEFAULT_HIDE_PATH_COUNT (sizeof(gDefaultHidePaths) / sizeof(gDefaultHidePaths[0]))

static WCHAR AvmToUpperW(WCHAR c)
{
    return (c >= L'a' && c <= L'z') ? (WCHAR)(c - 32) : c;
}

/*
 * Extract the leaf component from a registry key path.
 * Returns pointer into the buffer after the last backslash.
 */
static PCWSTR AvmGetLeaf(PCWSTR Path, USHORT LenChars)
{
    USHORT i;
    PCWSTR last = Path;

    for (i = 0; i < LenChars; i++) {
        if (Path[i] == L'\\')
            last = &Path[i + 1];
    }
    return last;
}

/*
 * Check if a registry key leaf name matches any VM indicator.
 * Uses case-insensitive exact comparison.
 */
static BOOLEAN IsVmRegistryLeaf(PCWSTR Leaf, USHORT LeafChars)
{
    ULONG i;
    USHORT j;
    PCWSTR candidate;
    USHORT candLen;
    BOOLEAN match;

    for (i = 0; i < AVM_REGISTRY_BLOCK_COUNT; i++) {
        candidate = gRegistryBlockLeaves[i];
        candLen = (USHORT)wcslen(candidate);
        if (candLen != LeafChars) continue;

        match = TRUE;
        for (j = 0; j < candLen; j++) {
            if (AvmToUpperW(Leaf[j]) != AvmToUpperW(candidate[j])) {
                match = FALSE;
                break;
            }
        }
        if (match) return TRUE;
    }
    return FALSE;
}

/* ----------------------------------------------------------------
 * Registry value spoofing table
 * Maps {key suffix, value name} -> spoofed string
 * ---------------------------------------------------------------- */
typedef struct _AVM_VALUE_SPOOF {
    PCWSTR KeySuffix;      /* Matched against end of full key path */
    PCWSTR ValueName;
    PCWSTR SpoofedValue;
} AVM_VALUE_SPOOF;

static const AVM_VALUE_SPOOF gValueSpoofs[] = {
    /* VMware BIOS values */
    { L"\\BIOS",              L"BIOSVendor",        L"Dell Inc." },
    { L"\\BIOS",              L"SystemManufacturer", L"Dell Inc." },
    { L"\\BIOS",              L"SystemProductName",  L"OptiPlex 7090" },
    { L"\\BIOS",              L"BIOSVersion",        L"2.18.0" },
    { L"\\BIOS",              L"BaseBoardManufacturer", L"Dell Inc." },
    { L"\\BIOS",              L"BaseBoardProduct",   L"0XHGX6" },
    /* VirtualBox BIOS values (innotek/Oracle) */
    { L"\\BIOS",              L"BIOSReleaseDate",    L"09/17/2023" },
    { L"\\BIOS",              L"SystemFamily",       L"OptiPlex" },
    /* SystemInformation path */
    { L"\\SystemInformation", L"BIOSVersion",        L"2.18.0" },
    { L"\\SystemInformation", L"SystemManufacturer", L"Dell Inc." },
    { L"\\SystemInformation", L"SystemProductName",  L"OptiPlex 7090" },
};
#define AVM_VALUE_SPOOF_COUNT (sizeof(gValueSpoofs) / sizeof(gValueSpoofs[0]))

/*
 * Case-insensitive check whether FullPath ends with Suffix.
 */
static BOOLEAN AvmPathEndsWith(PCWSTR FullPath, USHORT FullChars,
                               PCWSTR Suffix)
{
    USHORT suffLen = (USHORT)wcslen(Suffix);
    USHORT i;
    if (FullChars < suffLen) return FALSE;
    for (i = 0; i < suffLen; i++) {
        if (AvmToUpperW(FullPath[FullChars - suffLen + i]) !=
            AvmToUpperW(Suffix[i]))
            return FALSE;
    }
    return TRUE;
}

/*
 * Case-insensitive wide-string comparison.
 */
static BOOLEAN AvmEqualCI(PCWSTR A, USHORT AChars, PCWSTR B)
{
    USHORT bLen = (USHORT)wcslen(B);
    USHORT i;
    if (AChars != bLen) return FALSE;
    for (i = 0; i < AChars; i++) {
        if (AvmToUpperW(A[i]) != AvmToUpperW(B[i]))
            return FALSE;
    }
    return TRUE;
}

/*
 * Post-callback for RegNtPostQueryValueKey.
 * Spoofs BIOS/hardware identity values in the returned buffer.
 */
static NTSTATUS
AvmPostQueryValueKey(PREG_POST_OPERATION_INFORMATION PostInfo)
{
    PREG_QUERY_VALUE_KEY_INFORMATION preInfo;
    PCUNICODE_STRING keyName = NULL;
    NTSTATUS status;
    ULONG mode, enabledChecks, currentPid, i;
    USHORT keyChars;
    BOOLEAN isTargeted;
    PCWSTR spoofValue = NULL;

    if (!NT_SUCCESS(PostInfo->Status))
        return STATUS_SUCCESS;

    preInfo = (PREG_QUERY_VALUE_KEY_INFORMATION)PostInfo->PreInformation;
    if (preInfo == NULL || preInfo->ValueName == NULL ||
        preInfo->ValueName->Buffer == NULL || preInfo->ValueName->Length == 0)
        return STATUS_SUCCESS;

    /* Check policy */
    ExAcquireFastMutex(&gState.Guard);
    mode = gState.Policy.Mode;
    enabledChecks = gState.Policy.EnabledChecks;
    ExReleaseFastMutex(&gState.Guard);

    if (!(enabledChecks & AvmCheckRegistryArtifacts))
        return STATUS_SUCCESS;
    if (mode == AvmModeObserve)
        return STATUS_SUCCESS;

    currentPid = HandleToULong(PsGetCurrentProcessId());

    if (mode == AvmModeFull) {
        if (currentPid <= 4)
            return STATUS_SUCCESS;
        isTargeted = TRUE;
    } else {
        isTargeted = FALSE;
        ExAcquireFastMutex(&gState.Guard);
        for (i = 0; i < gState.TargetCount; i++) {
            if (gState.Targets[i].Kind == AvmTargetByPid &&
                gState.Targets[i].ProcessId == currentPid) {
                isTargeted = TRUE;
                break;
            }
        }
        ExReleaseFastMutex(&gState.Guard);
    }

    if (!isTargeted)
        return STATUS_SUCCESS;

    /* Resolve the key object to its full path */
    status = CmCallbackGetKeyObjectIDEx(
        &gState.RegistryCallbackCookie,
        PostInfo->Object, NULL, &keyName, 0);
    if (!NT_SUCCESS(status) || keyName == NULL)
        return STATUS_SUCCESS;

    keyChars = keyName->Length / sizeof(WCHAR);

    /* Find a matching spoof entry */
    for (i = 0; i < AVM_VALUE_SPOOF_COUNT; i++) {
        if (AvmPathEndsWith(keyName->Buffer, keyChars,
                            gValueSpoofs[i].KeySuffix) &&
            AvmEqualCI(preInfo->ValueName->Buffer,
                       preInfo->ValueName->Length / sizeof(WCHAR),
                       gValueSpoofs[i].ValueName)) {
            spoofValue = gValueSpoofs[i].SpoofedValue;
            break;
        }
    }

    CmCallbackReleaseKeyObjectIDEx(keyName);

    if (spoofValue == NULL)
        return STATUS_SUCCESS;

    /* Overwrite the returned data in-place */
    {
        ULONG spoofBytes = ((ULONG)wcslen(spoofValue) + 1) * sizeof(WCHAR);

        if (preInfo->KeyValueInformationClass == KeyValuePartialInformation) {
            PKEY_VALUE_PARTIAL_INFORMATION partial =
                (PKEY_VALUE_PARTIAL_INFORMATION)preInfo->KeyValueInformation;
            ULONG needed = FIELD_OFFSET(KEY_VALUE_PARTIAL_INFORMATION, Data)
                           + spoofBytes;
            if (partial->Type == REG_SZ && preInfo->Length >= needed) {
                RtlCopyMemory(partial->Data, spoofValue, spoofBytes);
                partial->DataLength = spoofBytes;
                if (preInfo->ResultLength)
                    *preInfo->ResultLength = needed;

                AvmAppendEvent(AvmEventRegistryProbe, AvmActionSpoof,
                    L"CmPostQueryValue",
                    gValueSpoofs[i].ValueName, spoofValue);
            }
        } else if (preInfo->KeyValueInformationClass ==
                   KeyValueFullInformation) {
            PKEY_VALUE_FULL_INFORMATION full =
                (PKEY_VALUE_FULL_INFORMATION)preInfo->KeyValueInformation;
            if (full->Type == REG_SZ && full->DataOffset > 0 &&
                preInfo->Length >= full->DataOffset + spoofBytes) {
                RtlCopyMemory((PUCHAR)full + full->DataOffset,
                              spoofValue, spoofBytes);
                full->DataLength = spoofBytes;
                if (preInfo->ResultLength)
                    *preInfo->ResultLength = full->DataOffset + spoofBytes;

                AvmAppendEvent(AvmEventRegistryProbe, AvmActionSpoof,
                    L"CmPostQueryValue",
                    gValueSpoofs[i].ValueName, spoofValue);
            }
        }
    }

    return STATUS_SUCCESS;
}

/*
 * CmRegisterCallbackEx handler - intercept VM-related registry keys
 */
static NTSTATUS
AvmRegistryCallback(
    _In_ PVOID CallbackContext,
    _In_opt_ PVOID Argument1,
    _In_opt_ PVOID Argument2)
{
    REG_NOTIFY_CLASS notifyClass;
    PREG_CREATE_KEY_INFORMATION_V1 createInfo;
    PUNICODE_STRING completeName;
    PCWSTR leaf;
    USHORT leafChars;
    USHORT nameChars;
    ULONG mode;
    ULONG enabledChecks;
    ULONG currentPid;
    ULONG i;
    BOOLEAN isTargeted;
    WCHAR leafBuf[AVM_MAX_TEXT_CHARS];
    USHORT copyLen;

    UNREFERENCED_PARAMETER(CallbackContext);

    if (Argument1 == NULL || Argument2 == NULL)
        return STATUS_SUCCESS;

    notifyClass = (REG_NOTIFY_CLASS)(ULONG_PTR)Argument1;

    if (notifyClass == RegNtPostQueryValueKey)
        return AvmPostQueryValueKey((PREG_POST_OPERATION_INFORMATION)Argument2);

    if (notifyClass != RegNtPreCreateKeyEx && notifyClass != RegNtPreOpenKeyEx)
        return STATUS_SUCCESS;

    ExAcquireFastMutex(&gState.Guard);
    mode = gState.Policy.Mode;
    enabledChecks = gState.Policy.EnabledChecks;
    ExReleaseFastMutex(&gState.Guard);

    if (!(enabledChecks & AvmCheckRegistryArtifacts))
        return STATUS_SUCCESS;

    if (mode == AvmModeObserve)
        goto observeOnly;

    currentPid = HandleToULong(PsGetCurrentProcessId());

    if (mode == AvmModeFull) {
        if (currentPid <= 4)
            return STATUS_SUCCESS;
        isTargeted = TRUE;
    } else {
        isTargeted = FALSE;
        ExAcquireFastMutex(&gState.Guard);
        for (i = 0; i < gState.TargetCount; i++) {
            if (gState.Targets[i].Kind == AvmTargetByPid &&
                gState.Targets[i].ProcessId == currentPid) {
                isTargeted = TRUE;
                break;
            }
        }
        ExReleaseFastMutex(&gState.Guard);
    }

    if (!isTargeted)
        return STATUS_SUCCESS;

observeOnly:
    createInfo = (PREG_CREATE_KEY_INFORMATION_V1)Argument2;
    completeName = createInfo->CompleteName;

    if (completeName == NULL || completeName->Buffer == NULL || completeName->Length == 0)
        return STATUS_SUCCESS;

    nameChars = completeName->Length / sizeof(WCHAR);
    leaf = AvmGetLeaf(completeName->Buffer, nameChars);
    leafChars = (USHORT)(nameChars - (USHORT)(leaf - completeName->Buffer));

    if (leafChars == 0 || leafChars >= AVM_MAX_TEXT_CHARS)
        return STATUS_SUCCESS;

    if (!IsVmRegistryLeaf(leaf, leafChars))
        return STATUS_SUCCESS;

    /* Copy leaf to local buffer for logging */
    copyLen = leafChars;
    if (copyLen >= AVM_MAX_TEXT_CHARS) copyLen = AVM_MAX_TEXT_CHARS - 1;
    RtlCopyMemory(leafBuf, leaf, copyLen * sizeof(WCHAR));
    leafBuf[copyLen] = L'\0';

    if (mode == AvmModeObserve) {
        AvmAppendEvent(AvmEventRegistryProbe, AvmActionLog,
            L"CmCallback", leafBuf, L"observed");
        return STATUS_SUCCESS;
    }

    AvmAppendEvent(AvmEventRegistryProbe, AvmActionBlock,
        L"CmCallback", leafBuf, L"blocked");
    return STATUS_OBJECT_NAME_NOT_FOUND;
}

static NTSTATUS AvmCompleteIrp(_Inout_ PIRP Irp, _In_ NTSTATUS Status, _In_ ULONG_PTR Information)
{
    Irp->IoStatus.Status = Status;
    Irp->IoStatus.Information = Information;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Status;
}

static VOID AvmResetState(VOID)
{
    RtlZeroMemory(&gState, sizeof(gState));
    ExInitializeFastMutex(&gState.Guard);
    gState.Policy.Version = AVM_VERSION;
    gState.Policy.Mode = AvmModeObserve;
    gState.Policy.EnabledChecks =
        AvmCheckDebugger |
        AvmCheckTiming |
        AvmCheckNativeApi |
        AvmCheckProcessEnum |
        AvmCheckDriverDeviceProbe |
        AvmCheckRegistryArtifacts |
        AvmCheckFileArtifacts |
        AvmCheckDirectoryFilter;
    gState.Policy.EventQueueCapacity = AVM_MAX_EVENTS;
    gState.Policy.RuntimePolicyRefreshMs = 1000;
    gState.Policy.DefaultConcealmentMask = gState.Policy.EnabledChecks;
    gState.Policy.DefaultLogMask = 0xFFFFFFFF;
}

static VOID AvmAppendEvent(_In_ ULONG Kind, _In_ ULONG Action, _In_opt_ PCWSTR Mechanism, _In_opt_ PCWSTR OriginalText, _In_opt_ PCWSTR SpoofedText)
{
    PAVM_EVENT_RECORD record = NULL;

    ExAcquireFastMutex(&gState.Guard);

    if (gState.EventBatch.Count >= AVM_MAX_FETCH_EVENTS) {
        RtlMoveMemory(&gState.EventBatch.Events[0], &gState.EventBatch.Events[1], sizeof(AVM_EVENT_RECORD) * (AVM_MAX_FETCH_EVENTS - 1));
        gState.EventBatch.Count = AVM_MAX_FETCH_EVENTS - 1;
    }

    record = &gState.EventBatch.Events[gState.EventBatch.Count++];
    RtlZeroMemory(record, sizeof(*record));
    record->Size = sizeof(*record);
    record->Source = AvmSourceKernel;
    record->Kind = Kind;
    record->Action = Action;
    record->ProcessId = HandleToULong(PsGetCurrentProcessId());
    record->ThreadId = HandleToULong(PsGetCurrentThreadId());
    KeQuerySystemTimePrecise(&record->Timestamp);

    if (Mechanism != NULL) {
        RtlStringCchCopyW(record->Mechanism, AVM_MAX_NAME_CHARS, Mechanism);
    }

    if (OriginalText != NULL) {
        RtlStringCchCopyW(record->OriginalText, AVM_MAX_TEXT_CHARS, OriginalText);
    }

    if (SpoofedText != NULL) {
        RtlStringCchCopyW(record->SpoofedText, AVM_MAX_TEXT_CHARS, SpoofedText);
    }

    ExReleaseFastMutex(&gState.Guard);
}

NTSTATUS
AvmCreateClose(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
    )
{
    UNREFERENCED_PARAMETER(DeviceObject);
    return AvmCompleteIrp(Irp, STATUS_SUCCESS, 0);
}

NTSTATUS
AvmDeviceControl(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
    )
{
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    ULONG code = stack->Parameters.DeviceIoControl.IoControlCode;
    ULONG inputLength = stack->Parameters.DeviceIoControl.InputBufferLength;
    ULONG outputLength = stack->Parameters.DeviceIoControl.OutputBufferLength;
    PVOID buffer = Irp->AssociatedIrp.SystemBuffer;
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    ULONG_PTR information = 0;

    UNREFERENCED_PARAMETER(DeviceObject);

    switch (code) {
    case AVM_IOCTL_SET_POLICY:
        if (inputLength >= sizeof(AVM_POLICY) && buffer != NULL) {
            ExAcquireFastMutex(&gState.Guard);
            gState.Policy = *(PAVM_POLICY)buffer;
            ExReleaseFastMutex(&gState.Guard);
            AvmAppendEvent(AvmEventPolicyUpdate, AvmActionLog, L"IOCTL_SET_POLICY", L"policy-updated", L"applied");
            status = STATUS_SUCCESS;
        } else {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;

    case AVM_IOCTL_GET_POLICY:
        if (outputLength >= sizeof(AVM_POLICY) && buffer != NULL) {
            ExAcquireFastMutex(&gState.Guard);
            *(PAVM_POLICY)buffer = gState.Policy;
            ExReleaseFastMutex(&gState.Guard);
            status = STATUS_SUCCESS;
            information = sizeof(AVM_POLICY);
        } else {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;

    case AVM_IOCTL_GET_STATUS:
        if (outputLength >= sizeof(AVM_STATUS_SNAPSHOT) && buffer != NULL) {
            PAVM_STATUS_SNAPSHOT snapshot = (PAVM_STATUS_SNAPSHOT)buffer;
            ExAcquireFastMutex(&gState.Guard);
            RtlZeroMemory(snapshot, sizeof(*snapshot));
            snapshot->Version = AVM_VERSION;
            snapshot->Mode = gState.Policy.Mode;
            snapshot->EnabledChecks = gState.Policy.EnabledChecks;
            snapshot->TargetCount = gState.TargetCount;
            snapshot->EventCount = gState.EventBatch.Count;
            snapshot->NameRuleCount = gState.NameRuleCount;
            snapshot->FileRuleCount = gState.FileRuleCount;
            snapshot->ControllerConnected = 1;
            ExReleaseFastMutex(&gState.Guard);
            status = STATUS_SUCCESS;
            information = sizeof(*snapshot);
        } else {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;

    case AVM_IOCTL_CLEAR_TARGETS:
        ExAcquireFastMutex(&gState.Guard);
        gState.TargetCount = 0;
        RtlZeroMemory(gState.Targets, sizeof(gState.Targets));
        ExReleaseFastMutex(&gState.Guard);
        AvmAppendEvent(AvmEventTargetUpdate, AvmActionLog, L"IOCTL_CLEAR_TARGETS", L"targets-cleared", L"applied");
        status = STATUS_SUCCESS;
        break;

    case AVM_IOCTL_ADD_TARGET:
        if (inputLength >= sizeof(AVM_TARGET_ENTRY) && buffer != NULL) {
            ExAcquireFastMutex(&gState.Guard);
            if (gState.TargetCount < AVM_MAX_TARGETS) {
                gState.Targets[gState.TargetCount++] = *(PAVM_TARGET_ENTRY)buffer;
                status = STATUS_SUCCESS;
            } else {
                status = STATUS_BUFFER_OVERFLOW;
            }
            ExReleaseFastMutex(&gState.Guard);
            if (NT_SUCCESS(status)) {
                AvmAppendEvent(AvmEventTargetUpdate, AvmActionLog, L"IOCTL_ADD_TARGET", L"target-added", L"applied");
            }
        } else {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;

    case AVM_IOCTL_CLEAR_NAME_RULES:
        ExAcquireFastMutex(&gState.Guard);
        gState.NameRuleCount = 0;
        RtlZeroMemory(gState.NameRules, sizeof(gState.NameRules));
        ExReleaseFastMutex(&gState.Guard);
        status = STATUS_SUCCESS;
        break;

    case AVM_IOCTL_ADD_NAME_RULE:
        if (inputLength >= sizeof(AVM_NAME_RULE) && buffer != NULL) {
            ExAcquireFastMutex(&gState.Guard);
            if (gState.NameRuleCount < AVM_MAX_NAME_RULES) {
                gState.NameRules[gState.NameRuleCount++] = *(PAVM_NAME_RULE)buffer;
                status = STATUS_SUCCESS;
            } else {
                status = STATUS_BUFFER_OVERFLOW;
            }
            ExReleaseFastMutex(&gState.Guard);
        } else {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;

    case AVM_IOCTL_CLEAR_FILE_RULES:
        ExAcquireFastMutex(&gState.Guard);
        gState.FileRuleCount = 0;
        RtlZeroMemory(gState.FileRules, sizeof(gState.FileRules));
        ExReleaseFastMutex(&gState.Guard);
        status = STATUS_SUCCESS;
        break;

    case AVM_IOCTL_ADD_FILE_RULE:
        if (inputLength >= sizeof(AVM_FILE_RULE) && buffer != NULL) {
            ExAcquireFastMutex(&gState.Guard);
            if (gState.FileRuleCount < AVM_MAX_FILE_RULES) {
                gState.FileRules[gState.FileRuleCount++] = *(PAVM_FILE_RULE)buffer;
                status = STATUS_SUCCESS;
            } else {
                status = STATUS_BUFFER_OVERFLOW;
            }
            ExReleaseFastMutex(&gState.Guard);
        } else {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;

    case AVM_IOCTL_FETCH_EVENTS:
        if (outputLength >= sizeof(AVM_EVENT_BATCH) && buffer != NULL) {
            ExAcquireFastMutex(&gState.Guard);
            *(PAVM_EVENT_BATCH)buffer = gState.EventBatch;
            gState.EventBatch.Count = 0;
            ExReleaseFastMutex(&gState.Guard);
            status = STATUS_SUCCESS;
            information = sizeof(AVM_EVENT_BATCH);
        } else {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;

    case AVM_IOCTL_SUBMIT_RUNTIME_EVENT:
        if (inputLength >= sizeof(AVM_EVENT_RECORD) && buffer != NULL) {
            ExAcquireFastMutex(&gState.Guard);
            if (gState.EventBatch.Count < AVM_MAX_FETCH_EVENTS) {
                gState.EventBatch.Events[gState.EventBatch.Count++] = *(PAVM_EVENT_RECORD)buffer;
            }
            ExReleaseFastMutex(&gState.Guard);
            status = STATUS_SUCCESS;
        } else {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;

    case AVM_IOCTL_HEARTBEAT:
        status = STATUS_SUCCESS;
        break;

    case AVM_IOCTL_LOAD_DEFAULTS:
    {
        ULONG idx;

        ExAcquireFastMutex(&gState.Guard);

        /* Set mode to Full with all checks enabled */
        gState.Policy.Mode = AvmModeFull;
        gState.Policy.EnabledChecks =
            AvmCheckDebugger | AvmCheckTiming | AvmCheckNativeApi |
            AvmCheckProcessEnum | AvmCheckDriverDeviceProbe |
            AvmCheckRegistryArtifacts | AvmCheckFileArtifacts |
            AvmCheckDirectoryFilter;
        gState.Policy.DefaultConcealmentMask = gState.Policy.EnabledChecks;

        /* Load default file-hide rules */
        gState.FileRuleCount = 0;
        for (idx = 0; idx < AVM_DEFAULT_HIDE_PATH_COUNT && idx < AVM_MAX_FILE_RULES; idx++) {
            RtlZeroMemory(&gState.FileRules[idx], sizeof(AVM_FILE_RULE));
            gState.FileRules[idx].Action = AvmFileRuleHide;
            RtlStringCchCopyW(gState.FileRules[idx].MatchPath, AVM_MAX_PATH_CHARS,
                              gDefaultHidePaths[idx]);
            gState.FileRuleCount++;
        }

        ExReleaseFastMutex(&gState.Guard);
        AvmAppendEvent(AvmEventPolicyUpdate, AvmActionLog,
            L"IOCTL_LOAD_DEFAULTS", L"defaults-loaded", L"applied");
        status = STATUS_SUCCESS;
    }
    break;

    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    return AvmCompleteIrp(Irp, status, information);
}

VOID
AvmUnload(
    _In_ PDRIVER_OBJECT DriverObject
    )
{
    UNICODE_STRING dosName;

    if (gState.RegistryCallbackCookie.QuadPart != 0) {
        CmUnRegisterCallback(gState.RegistryCallbackCookie);
        gState.RegistryCallbackCookie.QuadPart = 0;
    }

    RtlInitUnicodeString(&dosName, AVM_KERNEL_DOS_DEVICE);
    IoDeleteSymbolicLink(&dosName);

    if (DriverObject->DeviceObject != NULL) {
        IoDeleteDevice(DriverObject->DeviceObject);
    }
}

NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    )
{
    UNICODE_STRING deviceName;
    UNICODE_STRING dosName;
    NTSTATUS status = STATUS_SUCCESS;
    ULONG index = 0;

    UNREFERENCED_PARAMETER(RegistryPath);

    AvmResetState();

    RtlInitUnicodeString(&deviceName, AVM_KERNEL_NT_DEVICE);
    RtlInitUnicodeString(&dosName, AVM_KERNEL_DOS_DEVICE);

    status = IoCreateDevice(
        DriverObject,
        0,
        &deviceName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &gState.DeviceObject);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = IoCreateSymbolicLink(&dosName, &deviceName);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(gState.DeviceObject);
        gState.DeviceObject = NULL;
        return status;
    }

    for (index = 0; index <= IRP_MJ_MAXIMUM_FUNCTION; ++index) {
        DriverObject->MajorFunction[index] = AvmCreateClose;
    }

    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = AvmDeviceControl;
    DriverObject->DriverUnload = AvmUnload;
    gState.DeviceObject->Flags |= DO_BUFFERED_IO;
    gState.DeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

    AvmAppendEvent(AvmEventProcessStart, AvmActionLog, L"DriverEntry", L"kernel-driver-loaded", L"ready");

    /* Register registry callback to intercept VM-related key access */
    {
        UNICODE_STRING altitude;
        RtlInitUnicodeString(&altitude, L"42000");
        status = CmRegisterCallbackEx(AvmRegistryCallback, &altitude,
                                       DriverObject, NULL,
                                       &gState.RegistryCallbackCookie, NULL);
        if (!NT_SUCCESS(status)) {
            /* Non-fatal: driver works without registry interception */
            gState.RegistryCallbackCookie.QuadPart = 0;
        }
    }

    return STATUS_SUCCESS;
}
