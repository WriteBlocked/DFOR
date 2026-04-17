#include <Windows.h>
#include <strsafe.h>
#include "..\..\shared\avm_shared.h"

static HANDLE gDriver = INVALID_HANDLE_VALUE;

static bool EnsureDriver()
{
    if (gDriver != INVALID_HANDLE_VALUE) {
        return true;
    }

    gDriver = ::CreateFileW(
        AVM_KERNEL_USER_PATH,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);

    return gDriver != INVALID_HANDLE_VALUE;
}

static void CloseDriver()
{
    if (gDriver != INVALID_HANDLE_VALUE) {
        ::CloseHandle(gDriver);
        gDriver = INVALID_HANDLE_VALUE;
    }
}

static void SubmitRuntimeEvent(
    ULONG kind,
    ULONG action,
    PCWSTR mechanism,
    PCWSTR originalText,
    PCWSTR spoofedText,
    LONG originalStatus,
    LONG spoofedStatus)
{
    AVM_EVENT_RECORD record = {};
    DWORD bytesReturned = 0;

    if (!EnsureDriver()) {
        return;
    }

    record.Size = sizeof(record);
    record.Source = AvmSourceRuntime;
    record.Kind = kind;
    record.Action = action;
    record.ProcessId = GetCurrentProcessId();
    record.ThreadId = GetCurrentThreadId();
    record.OriginalStatus = originalStatus;
    record.SpoofedStatus = spoofedStatus;
    GetSystemTimePreciseAsFileTime(reinterpret_cast<FILETIME*>(&record.Timestamp));
    GetModuleFileNameW(nullptr, record.ImagePath, AVM_MAX_PATH_CHARS);

    if (mechanism != nullptr) {
        StringCchCopyW(record.Mechanism, AVM_MAX_NAME_CHARS, mechanism);
    }

    if (originalText != nullptr) {
        StringCchCopyW(record.OriginalText, AVM_MAX_TEXT_CHARS, originalText);
    }

    if (spoofedText != nullptr) {
        StringCchCopyW(record.SpoofedText, AVM_MAX_TEXT_CHARS, spoofedText);
    }

    DeviceIoControl(
        gDriver,
        AVM_IOCTL_SUBMIT_RUNTIME_EVENT,
        &record,
        sizeof(record),
        nullptr,
        0,
        &bytesReturned,
        nullptr);
}

static DWORD WINAPI InitializationThread(LPVOID)
{
    AVM_POLICY policy = {};
    DWORD bytesReturned = 0;

    if (EnsureDriver()) {
        DeviceIoControl(
            gDriver,
            AVM_IOCTL_GET_POLICY,
            nullptr,
            0,
            &policy,
            sizeof(policy),
            &bytesReturned,
            nullptr);

        SubmitRuntimeEvent(
            AvmEventPolicyUpdate,
            AvmActionLog,
            L"AvmRuntimeShim",
            L"dll-loaded",
            L"policy-snapshot-read",
            0,
            0);
    }

    return 0;
}

extern "C" __declspec(dllexport) void WINAPI AvmRuntimePing()
{
    SubmitRuntimeEvent(
        AvmEventNativeApiCall,
        AvmActionLog,
        L"AvmRuntimePing",
        L"manual-ping",
        L"logged",
        0,
        0);
}

BOOL APIENTRY DllMain(HMODULE module, DWORD reason, LPVOID reserved)
{
    UNREFERENCED_PARAMETER(reserved);

    if (reason == DLL_PROCESS_ATTACH) {
        HANDLE thread = nullptr;

        DisableThreadLibraryCalls(module);
        thread = CreateThread(nullptr, 0, InitializationThread, nullptr, 0, nullptr);
        if (thread != nullptr) {
            CloseHandle(thread);
        }
    } else if (reason == DLL_PROCESS_DETACH) {
        SubmitRuntimeEvent(
            AvmEventProcessExit,
            AvmActionLog,
            L"AvmRuntimeShim",
            L"dll-unloaded",
            L"detach",
            0,
            0);
        CloseDriver();
    }

    return TRUE;
}
