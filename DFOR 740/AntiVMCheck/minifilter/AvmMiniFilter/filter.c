#include <fltKernel.h>

PFLT_FILTER gFilterHandle = NULL;

DRIVER_INITIALIZE DriverEntry;

static FLT_PREOP_CALLBACK_STATUS
AvmPreOperation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
    )
{
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

static NTSTATUS
AvmUnload(
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
    )
{
    UNREFERENCED_PARAMETER(Flags);

    if (gFilterHandle != NULL) {
        FltUnregisterFilter(gFilterHandle);
        gFilterHandle = NULL;
    }

    return STATUS_SUCCESS;
}

CONST FLT_OPERATION_REGISTRATION gCallbacks[] = {
    { IRP_MJ_CREATE, 0, AvmPreOperation, NULL },
    { IRP_MJ_CLEANUP, 0, AvmPreOperation, NULL },
    { IRP_MJ_CLOSE, 0, AvmPreOperation, NULL },
    { IRP_MJ_DIRECTORY_CONTROL, 0, AvmPreOperation, NULL },
    { IRP_MJ_OPERATION_END }
};

CONST FLT_REGISTRATION gFilterRegistration = {
    sizeof(FLT_REGISTRATION),
    FLT_REGISTRATION_VERSION,
    0,
    NULL,
    gCallbacks,
    AvmUnload,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL
};

NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    )
{
    NTSTATUS status = STATUS_SUCCESS;

    status = FltRegisterFilter(DriverObject, &gFilterRegistration, &gFilterHandle);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = FltStartFiltering(gFilterHandle);
    if (!NT_SUCCESS(status)) {
        FltUnregisterFilter(gFilterHandle);
        gFilterHandle = NULL;
    }

    UNREFERENCED_PARAMETER(RegistryPath);
    return status;
}
