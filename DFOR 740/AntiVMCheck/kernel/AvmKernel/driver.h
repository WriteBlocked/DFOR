#pragma once

#include <ntddk.h>
#include <ntstrsafe.h>
#include "..\..\shared\avm_shared.h"

typedef struct _AVM_KERNEL_STATE {
    FAST_MUTEX Guard;
    PDEVICE_OBJECT DeviceObject;
    LARGE_INTEGER RegistryCallbackCookie;
    AVM_POLICY Policy;
    AVM_TARGET_ENTRY Targets[AVM_MAX_TARGETS];
    ULONG TargetCount;
    AVM_NAME_RULE NameRules[AVM_MAX_NAME_RULES];
    ULONG NameRuleCount;
    AVM_FILE_RULE FileRules[AVM_MAX_FILE_RULES];
    ULONG FileRuleCount;
    AVM_EVENT_BATCH EventBatch;
} AVM_KERNEL_STATE, *PAVM_KERNEL_STATE;

DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD AvmUnload;
_Dispatch_type_(IRP_MJ_CREATE) DRIVER_DISPATCH AvmCreateClose;
_Dispatch_type_(IRP_MJ_CLOSE) DRIVER_DISPATCH AvmCreateClose;
_Dispatch_type_(IRP_MJ_DEVICE_CONTROL) DRIVER_DISPATCH AvmDeviceControl;

