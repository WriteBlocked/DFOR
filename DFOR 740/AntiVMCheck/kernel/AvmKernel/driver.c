#include "driver.h"

static AVM_KERNEL_STATE gState;

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
    return STATUS_SUCCESS;
}
