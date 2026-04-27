/* Pull in the full NTSTATUS code set before Windows.h suppresses them */
#define WIN32_NO_STATUS
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>
#undef WIN32_NO_STATUS
#include <ntstatus.h>
#include <winternl.h>
#include <strsafe.h>
#include <TlHelp32.h>
#include "..\..\shared\avm_shared.h"

#pragma warning(disable:4996)  /* stricmp/wcsicmp */

/* ═══════════════════════════════════════════════════════════════════
 * Function-pointer typedefs for every hooked API
 * ═══════════════════════════════════════════════════════════════════ */
typedef BOOL      (WINAPI *Fn_IsDebuggerPresent)(void);
typedef BOOL      (WINAPI *Fn_CheckRemoteDebuggerPresent)(HANDLE, PBOOL);
typedef BOOL      (WINAPI *Fn_GetDiskFreeSpaceExA)(LPCSTR, PULARGE_INTEGER, PULARGE_INTEGER, PULARGE_INTEGER);
typedef BOOL      (WINAPI *Fn_GetDiskFreeSpaceExW)(LPCWSTR, PULARGE_INTEGER, PULARGE_INTEGER, PULARGE_INTEGER);
typedef LSTATUS   (WINAPI *Fn_RegOpenKeyExA)(HKEY, LPCSTR, DWORD, REGSAM, PHKEY);
typedef LSTATUS   (WINAPI *Fn_RegOpenKeyExW)(HKEY, LPCWSTR, DWORD, REGSAM, PHKEY);
typedef LSTATUS   (WINAPI *Fn_RegQueryValueExA)(HKEY, LPCSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
typedef LSTATUS   (WINAPI *Fn_RegQueryValueExW)(HKEY, LPCWSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
typedef HANDLE    (WINAPI *Fn_CreateFileA)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef HANDLE    (WINAPI *Fn_CreateFileW)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef DWORD     (WINAPI *Fn_GetFileAttributesA)(LPCSTR);
typedef DWORD     (WINAPI *Fn_GetFileAttributesW)(LPCWSTR);
typedef SHORT     (WINAPI *Fn_GetAsyncKeyState)(int);
typedef DWORD     (WINAPI *Fn_GetTickCount)(void);
typedef ULONGLONG (WINAPI *Fn_GetTickCount64)(void);
typedef BOOL      (WINAPI *Fn_QueryPerformanceCounter)(LARGE_INTEGER*);
typedef FARPROC   (WINAPI *Fn_GetProcAddress)(HMODULE, LPCSTR);
typedef NTSTATUS  (NTAPI *Fn_NtQueryInformationProcess)(HANDLE, ULONG, PVOID, ULONG, PULONG);
typedef NTSTATUS  (NTAPI *Fn_NtQuerySystemInformation)(ULONG, PVOID, ULONG, PULONG);
typedef int       (WINAPI *Fn_MessageBoxA)(HWND, LPCSTR, LPCSTR, UINT);
typedef int       (WINAPI *Fn_MessageBoxW)(HWND, LPCWSTR, LPCWSTR, UINT);

/* ═══════════════════════════════════════════════════════════════════
 * Original function pointer globals  (set once before IAT patching)
 * ═══════════════════════════════════════════════════════════════════ */
static Fn_IsDebuggerPresent             gOrig_IsDebuggerPresent             = nullptr;
static Fn_CheckRemoteDebuggerPresent    gOrig_CheckRemoteDebuggerPresent    = nullptr;
static Fn_GetDiskFreeSpaceExA           gOrig_GetDiskFreeSpaceExA           = nullptr;
static Fn_GetDiskFreeSpaceExW           gOrig_GetDiskFreeSpaceExW           = nullptr;
static Fn_RegOpenKeyExA                 gOrig_RegOpenKeyExA                 = nullptr;
static Fn_RegOpenKeyExW                 gOrig_RegOpenKeyExW                 = nullptr;
static Fn_RegQueryValueExA              gOrig_RegQueryValueExA              = nullptr;
static Fn_RegQueryValueExW              gOrig_RegQueryValueExW              = nullptr;
static Fn_CreateFileA                   gOrig_CreateFileA                   = nullptr;
static Fn_CreateFileW                   gOrig_CreateFileW                   = nullptr;
static Fn_GetFileAttributesA            gOrig_GetFileAttributesA            = nullptr;
static Fn_GetFileAttributesW            gOrig_GetFileAttributesW            = nullptr;
static Fn_GetAsyncKeyState              gOrig_GetAsyncKeyState              = nullptr;
static Fn_GetTickCount                  gOrig_GetTickCount                  = nullptr;
static Fn_GetTickCount64                gOrig_GetTickCount64                = nullptr;
static Fn_QueryPerformanceCounter       gOrig_QueryPerformanceCounter       = nullptr;
static Fn_GetProcAddress                gOrig_GetProcAddress                = nullptr;
static Fn_NtQueryInformationProcess     gOrig_NtQueryInformationProcess     = nullptr;
static Fn_NtQuerySystemInformation      gOrig_NtQuerySystemInformation      = nullptr;
static Fn_MessageBoxA                   gOrig_MessageBoxA                   = nullptr;
static Fn_MessageBoxW                   gOrig_MessageBoxW                   = nullptr;

/* Mouse activity simulation state */
static volatile LONG gMouseCallCount = 0;

/* Uptime padding: add 4 hours so sandbox uptime checks pass */
#define AVM_UPTIME_OFFSET_MS  (4UL * 3600UL * 1000UL)

/* ═══════════════════════════════════════════════════════════════════
 * Driver communication
 * ═══════════════════════════════════════════════════════════════════ */
static HANDLE gDriver = INVALID_HANDLE_VALUE;

static bool EnsureDriver()
{
    if (gDriver != INVALID_HANDLE_VALUE) {
        return true;
    }
    gDriver = CreateFileW(
        AVM_KERNEL_USER_PATH,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    return gDriver != INVALID_HANDLE_VALUE;
}

static void CloseDriver()
{
    if (gDriver != INVALID_HANDLE_VALUE) {
        CloseHandle(gDriver);
        gDriver = INVALID_HANDLE_VALUE;
    }
}

static void SubmitRuntimeEvent(
    ULONG kind, ULONG action,
    PCWSTR mechanism, PCWSTR originalText, PCWSTR spoofedText,
    LONG originalStatus, LONG spoofedStatus)
{
    AVM_EVENT_RECORD record = {};
    DWORD bytesReturned = 0;
    if (!EnsureDriver()) return;

    record.Size            = sizeof(record);
    record.Source          = AvmSourceRuntime;
    record.Kind            = kind;
    record.Action          = action;
    record.ProcessId       = GetCurrentProcessId();
    record.ThreadId        = GetCurrentThreadId();
    record.OriginalStatus  = originalStatus;
    record.SpoofedStatus   = spoofedStatus;
    GetSystemTimePreciseAsFileTime(reinterpret_cast<FILETIME*>(&record.Timestamp));
    GetModuleFileNameW(nullptr, record.ImagePath, AVM_MAX_PATH_CHARS);
    if (mechanism)    StringCchCopyW(record.Mechanism,     AVM_MAX_NAME_CHARS, mechanism);
    if (originalText) StringCchCopyW(record.OriginalText,  AVM_MAX_TEXT_CHARS, originalText);
    if (spoofedText)  StringCchCopyW(record.SpoofedText,   AVM_MAX_TEXT_CHARS, spoofedText);
    DeviceIoControl(gDriver, AVM_IOCTL_SUBMIT_RUNTIME_EVENT,
        &record, sizeof(record), nullptr, 0, &bytesReturned, nullptr);
}

/* ═══════════════════════════════════════════════════════════════════
 * VM artifact identifier tables
 * ═══════════════════════════════════════════════════════════════════ */

/* Registry key substrings to block (case-insensitive, ANSI) */
static const char* const kVmRegSubstringsA[] = {
    "vmware",
    "vmci",
    "vmhgfs",
    "vmmouse",
    "vmtools",
    "vmx_svga",
    "vmxnet",
    "vboxguest",
    "vboxmouse",
    "vboxsf",
    "vboxvideo",
    "vboxservice",
    "virtualbox",
    nullptr
};

/* Registry key substrings to block (wide) */
static const wchar_t* const kVmRegSubstringsW[] = {
    L"vmware",
    L"vmci",
    L"vmhgfs",
    L"vmmouse",
    L"vmtools",
    L"vmx_svga",
    L"vmxnet",
    L"vboxguest",
    L"vboxmouse",
    L"vboxsf",
    L"vboxvideo",
    L"vboxservice",
    L"virtualbox",
    nullptr
};

/* VM-related file path substrings to hide (ANSI, lower-case) */
static const char* const kVmFileSubstringsA[] = {
    "\\drivers\\vmmouse.sys",
    "\\drivers\\vmhgfs.sys",
    "\\drivers\\vmci.sys",
    "\\drivers\\vm3dmp",
    "\\drivers\\vmxnet",
    "\\drivers\\vmrawdsk.sys",
    "\\drivers\\vmusbmouse.sys",
    "\\drivers\\vmx_svga.sys",
    "\\drivers\\vboxguest.sys",
    "\\drivers\\vboxmouse.sys",
    "\\drivers\\vboxsf.sys",
    "\\drivers\\vboxvideo.sys",
    "\\drivers\\vboxwddm.sys",
    "program files\\vmware",
    "program files\\oracle\\virtualbox",
    nullptr
};

/* VM-related file path substrings (wide) */
static const wchar_t* const kVmFileSubstringsW[] = {
    L"\\drivers\\vmmouse.sys",
    L"\\drivers\\vmhgfs.sys",
    L"\\drivers\\vmci.sys",
    L"\\drivers\\vm3dmp",
    L"\\drivers\\vmxnet",
    L"\\drivers\\vmrawdsk.sys",
    L"\\drivers\\vmusbmouse.sys",
    L"\\drivers\\vmx_svga.sys",
    L"\\drivers\\vboxguest.sys",
    L"\\drivers\\vboxmouse.sys",
    L"\\drivers\\vboxsf.sys",
    L"\\drivers\\vboxvideo.sys",
    L"\\drivers\\vboxwddm.sys",
    L"\\program files\\vmware",
    L"\\program files\\oracle\\virtualbox",
    nullptr
};

/* VM pseudo-device names (ANSI) */
static const char* const kVmDevicesA[] = {
    "\\\\.\\hgfs",
    "\\\\.\\vmci",
    "\\\\.\\vmcihostdev",
    "\\\\.\\vmmemctl",
    "\\\\.\\vmx_svga",
    "\\\\.\\vboxguest",
    "\\\\.\\vboxminidrv",
    nullptr
};

/* VM pseudo-device names (wide) */
static const wchar_t* const kVmDevicesW[] = {
    L"\\\\.\\hgfs",
    L"\\\\.\\vmci",
    L"\\\\.\\vmcihostdev",
    L"\\\\.\\vmmemctl",
    L"\\\\.\\vmx_svga",
    L"\\\\.\\vboxguest",
    L"\\\\.\\vboxminidrv",
    nullptr
};

/* ═══════════════════════════════════════════════════════════════════
 * Helper predicates
 * ═══════════════════════════════════════════════════════════════════ */

/* Case-insensitive substring search (ANSI) */
static bool ContainsIA(const char* haystack, const char* needle)
{
    if (!haystack || !needle) return false;
    size_t hLen = strlen(haystack);
    size_t nLen = strlen(needle);
    if (nLen == 0 || hLen < nLen) return false;
    for (size_t i = 0; i <= hLen - nLen; ++i) {
        bool match = true;
        for (size_t j = 0; j < nLen; ++j) {
            if (tolower((unsigned char)haystack[i+j]) != (unsigned char)needle[j]) {
                match = false;
                break;
            }
        }
        if (match) return true;
    }
    return false;
}

/* Case-insensitive substring search (wide) */
static bool ContainsIW(const wchar_t* haystack, const wchar_t* needle)
{
    if (!haystack || !needle) return false;
    size_t hLen = wcslen(haystack);
    size_t nLen = wcslen(needle);
    if (nLen == 0 || hLen < nLen) return false;
    for (size_t i = 0; i <= hLen - nLen; ++i) {
        bool match = true;
        for (size_t j = 0; j < nLen; ++j) {
            if (towlower(haystack[i+j]) != needle[j]) {
                match = false;
                break;
            }
        }
        if (match) return true;
    }
    return false;
}

static bool IsVmRegistryPathA(const char* path)
{
    if (!path) return false;
    for (int i = 0; kVmRegSubstringsA[i]; ++i)
        if (ContainsIA(path, kVmRegSubstringsA[i])) return true;
    return false;
}

static bool IsVmRegistryPathW(const wchar_t* path)
{
    if (!path) return false;
    for (int i = 0; kVmRegSubstringsW[i]; ++i)
        if (ContainsIW(path, kVmRegSubstringsW[i])) return true;
    return false;
}

static bool IsVmFilePathA(const char* path)
{
    if (!path) return false;
    for (int i = 0; kVmFileSubstringsA[i]; ++i)
        if (ContainsIA(path, kVmFileSubstringsA[i])) return true;
    return false;
}

static bool IsVmFilePathW(const wchar_t* path)
{
    if (!path) return false;
    for (int i = 0; kVmFileSubstringsW[i]; ++i)
        if (ContainsIW(path, kVmFileSubstringsW[i])) return true;
    return false;
}

static bool IsVmDeviceA(const char* path)
{
    if (!path) return false;
    for (int i = 0; kVmDevicesA[i]; ++i)
        if (_stricmp(path, kVmDevicesA[i]) == 0) return true;
    return false;
}

static bool IsVmDeviceW(const wchar_t* path)
{
    if (!path) return false;
    for (int i = 0; kVmDevicesW[i]; ++i)
        if (_wcsicmp(path, kVmDevicesW[i]) == 0) return true;
    return false;
}

/* ═══════════════════════════════════════════════════════════════════
 * Hook implementations
 * ═══════════════════════════════════════════════════════════════════ */

static BOOL WINAPI Hook_IsDebuggerPresent(void)
{
    SubmitRuntimeEvent(AvmEventDebuggerCheck, AvmActionSpoof,
        L"IsDebuggerPresent", L"TRUE", L"FALSE", 1, 0);
    return FALSE;
}

static BOOL WINAPI Hook_CheckRemoteDebuggerPresent(HANDLE hProcess, PBOOL pbDebuggerPresent)
{
    (void)hProcess;
    if (pbDebuggerPresent) *pbDebuggerPresent = FALSE;
    SubmitRuntimeEvent(AvmEventDebuggerCheck, AvmActionSpoof,
        L"CheckRemoteDebuggerPresent", L"TRUE", L"FALSE", 1, 0);
    return TRUE;
}

/* Fake a 500 GB disk so sandbox disk-size checks pass */
static BOOL WINAPI Hook_GetDiskFreeSpaceExA(
    LPCSTR lpDir,
    PULARGE_INTEGER lpFreeToCaller,
    PULARGE_INTEGER lpTotal,
    PULARGE_INTEGER lpFreeBytes)
{
    if (gOrig_GetDiskFreeSpaceExA)
        gOrig_GetDiskFreeSpaceExA(lpDir, lpFreeToCaller, lpTotal, lpFreeBytes);

    /* Inflate total to 500 GB regardless of actual disk size */
    ULONGLONG fakeTotal = 500ULL * 1024 * 1024 * 1024;
    if (lpTotal)      lpTotal->QuadPart      = fakeTotal;
    if (lpFreeToCaller && lpFreeToCaller->QuadPart < fakeTotal / 2)
                      lpFreeToCaller->QuadPart = fakeTotal / 2;
    if (lpFreeBytes && lpFreeBytes->QuadPart < fakeTotal / 2)
                      lpFreeBytes->QuadPart    = fakeTotal / 2;

    SubmitRuntimeEvent(AvmEventNativeApiCall, AvmActionSpoof,
        L"GetDiskFreeSpaceExA", L"<=60GB", L"500GB", 0, 0);
    return TRUE;
}

static BOOL WINAPI Hook_GetDiskFreeSpaceExW(
    LPCWSTR lpDir,
    PULARGE_INTEGER lpFreeToCaller,
    PULARGE_INTEGER lpTotal,
    PULARGE_INTEGER lpFreeBytes)
{
    if (gOrig_GetDiskFreeSpaceExW)
        gOrig_GetDiskFreeSpaceExW(lpDir, lpFreeToCaller, lpTotal, lpFreeBytes);

    ULONGLONG fakeTotal = 500ULL * 1024 * 1024 * 1024;
    if (lpTotal)      lpTotal->QuadPart      = fakeTotal;
    if (lpFreeToCaller && lpFreeToCaller->QuadPart < fakeTotal / 2)
                      lpFreeToCaller->QuadPart = fakeTotal / 2;
    if (lpFreeBytes && lpFreeBytes->QuadPart < fakeTotal / 2)
                      lpFreeBytes->QuadPart    = fakeTotal / 2;

    SubmitRuntimeEvent(AvmEventNativeApiCall, AvmActionSpoof,
        L"GetDiskFreeSpaceExW", L"<=60GB", L"500GB", 0, 0);
    return TRUE;
}

static LSTATUS WINAPI Hook_RegOpenKeyExA(
    HKEY hKey, LPCSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult)
{
    if (IsVmRegistryPathA(lpSubKey)) {
        SubmitRuntimeEvent(AvmEventRegistryProbe, AvmActionBlock,
            L"RegOpenKeyExA", L"vm-key", L"blocked", 0, ERROR_FILE_NOT_FOUND);
        SetLastError(ERROR_FILE_NOT_FOUND);
        return ERROR_FILE_NOT_FOUND;
    }
    if (gOrig_RegOpenKeyExA)
        return gOrig_RegOpenKeyExA(hKey, lpSubKey, ulOptions, samDesired, phkResult);
    return RegOpenKeyExA(hKey, lpSubKey, ulOptions, samDesired, phkResult);
}

static LSTATUS WINAPI Hook_RegOpenKeyExW(
    HKEY hKey, LPCWSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult)
{
    if (IsVmRegistryPathW(lpSubKey)) {
        SubmitRuntimeEvent(AvmEventRegistryProbe, AvmActionBlock,
            L"RegOpenKeyExW", lpSubKey ? lpSubKey : L"?", L"blocked",
            0, ERROR_FILE_NOT_FOUND);
        SetLastError(ERROR_FILE_NOT_FOUND);
        return ERROR_FILE_NOT_FOUND;
    }
    if (gOrig_RegOpenKeyExW)
        return gOrig_RegOpenKeyExW(hKey, lpSubKey, ulOptions, samDesired, phkResult);
    return RegOpenKeyExW(hKey, lpSubKey, ulOptions, samDesired, phkResult);
}

static LSTATUS WINAPI Hook_RegQueryValueExA(
    HKEY hKey, LPCSTR lpValueName, LPDWORD lpReserved,
    LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData)
{
    if (IsVmRegistryPathA(lpValueName)) {
        SetLastError(ERROR_FILE_NOT_FOUND);
        return ERROR_FILE_NOT_FOUND;
    }
    if (gOrig_RegQueryValueExA)
        return gOrig_RegQueryValueExA(hKey, lpValueName, lpReserved, lpType, lpData, lpcbData);
    return RegQueryValueExA(hKey, lpValueName, lpReserved, lpType, lpData, lpcbData);
}

static LSTATUS WINAPI Hook_RegQueryValueExW(
    HKEY hKey, LPCWSTR lpValueName, LPDWORD lpReserved,
    LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData)
{
    if (IsVmRegistryPathW(lpValueName)) {
        SetLastError(ERROR_FILE_NOT_FOUND);
        return ERROR_FILE_NOT_FOUND;
    }
    if (gOrig_RegQueryValueExW)
        return gOrig_RegQueryValueExW(hKey, lpValueName, lpReserved, lpType, lpData, lpcbData);
    return RegQueryValueExW(hKey, lpValueName, lpReserved, lpType, lpData, lpcbData);
}

static HANDLE WINAPI Hook_CreateFileA(
    LPCSTR lpFileName, DWORD dwAccess, DWORD dwShare,
    LPSECURITY_ATTRIBUTES lpSA, DWORD dwCreation, DWORD dwFlags, HANDLE hTemplate)
{
    if (IsVmDeviceA(lpFileName) || IsVmFilePathA(lpFileName)) {
        SubmitRuntimeEvent(AvmEventFileProbe, AvmActionBlock,
            L"CreateFileA", L"vm-artifact", L"blocked", 0, 0);
        SetLastError(ERROR_FILE_NOT_FOUND);
        return INVALID_HANDLE_VALUE;
    }
    if (gOrig_CreateFileA)
        return gOrig_CreateFileA(lpFileName, dwAccess, dwShare, lpSA, dwCreation, dwFlags, hTemplate);
    return CreateFileA(lpFileName, dwAccess, dwShare, lpSA, dwCreation, dwFlags, hTemplate);
}

static HANDLE WINAPI Hook_CreateFileW(
    LPCWSTR lpFileName, DWORD dwAccess, DWORD dwShare,
    LPSECURITY_ATTRIBUTES lpSA, DWORD dwCreation, DWORD dwFlags, HANDLE hTemplate)
{
    /* Guard: don't intercept the driver itself or the shim's own file operations */
    if (lpFileName && wcscmp(lpFileName, AVM_KERNEL_USER_PATH) == 0) {
        if (gOrig_CreateFileW)
            return gOrig_CreateFileW(lpFileName, dwAccess, dwShare, lpSA, dwCreation, dwFlags, hTemplate);
        return CreateFileW(lpFileName, dwAccess, dwShare, lpSA, dwCreation, dwFlags, hTemplate);
    }
    if (IsVmDeviceW(lpFileName) || IsVmFilePathW(lpFileName)) {
        SubmitRuntimeEvent(AvmEventFileProbe, AvmActionBlock,
            L"CreateFileW", lpFileName ? lpFileName : L"?", L"blocked", 0, 0);
        SetLastError(ERROR_FILE_NOT_FOUND);
        return INVALID_HANDLE_VALUE;
    }
    if (gOrig_CreateFileW)
        return gOrig_CreateFileW(lpFileName, dwAccess, dwShare, lpSA, dwCreation, dwFlags, hTemplate);
    return CreateFileW(lpFileName, dwAccess, dwShare, lpSA, dwCreation, dwFlags, hTemplate);
}

static DWORD WINAPI Hook_GetFileAttributesA(LPCSTR lpFileName)
{
    if (IsVmFilePathA(lpFileName)) {
        SubmitRuntimeEvent(AvmEventFileProbe, AvmActionBlock,
            L"GetFileAttributesA", L"vm-file", L"INVALID_FILE_ATTRIBUTES", 0, 0);
        SetLastError(ERROR_FILE_NOT_FOUND);
        return INVALID_FILE_ATTRIBUTES;
    }
    if (gOrig_GetFileAttributesA) return gOrig_GetFileAttributesA(lpFileName);
    return GetFileAttributesA(lpFileName);
}

static DWORD WINAPI Hook_GetFileAttributesW(LPCWSTR lpFileName)
{
    if (IsVmFilePathW(lpFileName)) {
        SubmitRuntimeEvent(AvmEventFileProbe, AvmActionBlock,
            L"GetFileAttributesW", lpFileName ? lpFileName : L"?",
            L"INVALID_FILE_ATTRIBUTES", 0, 0);
        SetLastError(ERROR_FILE_NOT_FOUND);
        return INVALID_FILE_ATTRIBUTES;
    }
    if (gOrig_GetFileAttributesW) return gOrig_GetFileAttributesW(lpFileName);
    return GetFileAttributesW(lpFileName);
}

/* Fake mouse activity so reverse-turing checks pass.
 * Return "was pressed since last call" on first few calls per key,
 * then settle to "not pressed" so the target process is not confused. */
static SHORT WINAPI Hook_GetAsyncKeyState(int vKey)
{
    if (vKey == VK_LBUTTON || vKey == VK_RBUTTON) {
        LONG n = InterlockedIncrement(&gMouseCallCount);
        /* Return "pressed" on first 4 calls: covers single-click + double-click */
        if (n <= 4) {
            SubmitRuntimeEvent(AvmEventNativeApiCall, AvmActionSpoof,
                L"GetAsyncKeyState", L"0", L"1 (mouse-click-fake)", 0, 1);
            return 0x0001;
        }
        return 0x0000;
    }
    if (gOrig_GetAsyncKeyState) return gOrig_GetAsyncKeyState(vKey);
    return 0;
}

/* Inflate tick count so uptime-threshold checks pass */
static DWORD WINAPI Hook_GetTickCount(void)
{
    DWORD base = gOrig_GetTickCount ? gOrig_GetTickCount() : (DWORD)::GetTickCount();
    return base + AVM_UPTIME_OFFSET_MS;
}

static ULONGLONG WINAPI Hook_GetTickCount64(void)
{
    ULONGLONG base = gOrig_GetTickCount64
        ? gOrig_GetTickCount64()
        : (ULONGLONG)::GetTickCount64();
    return base + (ULONGLONG)AVM_UPTIME_OFFSET_MS;
}

static BOOL WINAPI Hook_QueryPerformanceCounter(LARGE_INTEGER* lpPerformanceCount)
{
    BOOL ok = gOrig_QueryPerformanceCounter
        ? gOrig_QueryPerformanceCounter(lpPerformanceCount)
        : QueryPerformanceCounter(lpPerformanceCount);
    return ok;
}

/* NtQueryInformationProcess — hide debugger port/flags */
#define PROCESSINFOCLASS_DebugPort          7UL
#define PROCESSINFOCLASS_DebugObjectHandle  30UL
#define PROCESSINFOCLASS_DebugFlags         31UL
#ifndef STATUS_PORT_NOT_SET
#define STATUS_PORT_NOT_SET                 ((NTSTATUS)0xC0000353L)
#endif

static NTSTATUS NTAPI Hook_NtQueryInformationProcess(
    HANDLE hProcess, ULONG infoClass, PVOID buffer, ULONG bufLen, PULONG retLen)
{
    if (infoClass == PROCESSINFOCLASS_DebugPort) {
        if (buffer && bufLen >= sizeof(HANDLE)) {
            *(HANDLE*)buffer = NULL;
            if (retLen) *retLen = sizeof(HANDLE);
        }
        SubmitRuntimeEvent(AvmEventDebuggerCheck, AvmActionSpoof,
            L"NtQueryInformationProcess", L"DebugPort=non-null", L"0", 0, 0);
        return STATUS_SUCCESS;
    }
    if (infoClass == PROCESSINFOCLASS_DebugObjectHandle) {
        if (buffer && bufLen >= sizeof(HANDLE)) {
            *(HANDLE*)buffer = INVALID_HANDLE_VALUE;
            if (retLen) *retLen = sizeof(HANDLE);
        }
        SubmitRuntimeEvent(AvmEventDebuggerCheck, AvmActionSpoof,
            L"NtQueryInformationProcess", L"DebugObjectHandle", L"INVALID", 0, 0);
        return STATUS_PORT_NOT_SET;
    }
    if (infoClass == PROCESSINFOCLASS_DebugFlags) {
        if (buffer && bufLen >= sizeof(ULONG)) {
            *(ULONG*)buffer = 1; /* PROCESS_NO_DEBUG_INHERIT */
            if (retLen) *retLen = sizeof(ULONG);
        }
        return STATUS_SUCCESS;
    }
    if (gOrig_NtQueryInformationProcess)
        return gOrig_NtQueryInformationProcess(hProcess, infoClass, buffer, bufLen, retLen);
    return STATUS_SUCCESS;
}

/* MessageBox — auto-confirm dialogs so pafish dialog checks pass */
static int AutoConfirmMessageBox(UINT uType)
{
    UINT type = uType & MB_TYPEMASK;
    if (type == MB_YESNO || type == MB_YESNOCANCEL)
        return IDYES;
    if (type == MB_RETRYCANCEL)
        return IDRETRY;
    return IDOK;
}

static int WINAPI Hook_MessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType)
{
    (void)hWnd;
    SubmitRuntimeEvent(AvmEventNativeApiCall, AvmActionSpoof,
        L"MessageBoxA", L"dialog", L"auto-confirmed", 0, 0);
    if (gOrig_MessageBoxA)
        gOrig_MessageBoxA(hWnd, lpText, lpCaption, uType | MB_DEFBUTTON1);
    return AutoConfirmMessageBox(uType);
}

static int WINAPI Hook_MessageBoxW(HWND hWnd, LPCWSTR lpText, LPCWSTR lpCaption, UINT uType)
{
    (void)hWnd;
    SubmitRuntimeEvent(AvmEventNativeApiCall, AvmActionSpoof,
        L"MessageBoxW", L"dialog", L"auto-confirmed", 0, 0);
    if (gOrig_MessageBoxW)
        gOrig_MessageBoxW(hWnd, lpText, lpCaption, uType | MB_DEFBUTTON1);
    return AutoConfirmMessageBox(uType);
}

/* ═══════════════════════════════════════════════════════════════════
 * GetProcAddress hook — redirect dynamic API resolution to our hooks
 * ═══════════════════════════════════════════════════════════════════ */

struct AvmFuncRedirect {
    const char* name;
    PVOID       hookFn;
};

static const AvmFuncRedirect kRedirects[] = {
    { "IsDebuggerPresent",              (PVOID)Hook_IsDebuggerPresent },
    { "CheckRemoteDebuggerPresent",     (PVOID)Hook_CheckRemoteDebuggerPresent },
    { "GetDiskFreeSpaceExA",            (PVOID)Hook_GetDiskFreeSpaceExA },
    { "GetDiskFreeSpaceExW",            (PVOID)Hook_GetDiskFreeSpaceExW },
    { "RegOpenKeyExA",                  (PVOID)Hook_RegOpenKeyExA },
    { "RegOpenKeyExW",                  (PVOID)Hook_RegOpenKeyExW },
    { "RegQueryValueExA",               (PVOID)Hook_RegQueryValueExA },
    { "RegQueryValueExW",               (PVOID)Hook_RegQueryValueExW },
    { "CreateFileA",                    (PVOID)Hook_CreateFileA },
    { "CreateFileW",                    (PVOID)Hook_CreateFileW },
    { "GetFileAttributesA",             (PVOID)Hook_GetFileAttributesA },
    { "GetFileAttributesW",             (PVOID)Hook_GetFileAttributesW },
    { "GetAsyncKeyState",               (PVOID)Hook_GetAsyncKeyState },
    { "GetTickCount",                   (PVOID)Hook_GetTickCount },
    { "GetTickCount64",                 (PVOID)Hook_GetTickCount64 },
    { "QueryPerformanceCounter",        (PVOID)Hook_QueryPerformanceCounter },
    { "NtQueryInformationProcess",      (PVOID)Hook_NtQueryInformationProcess },
    { "MessageBoxA",                    (PVOID)Hook_MessageBoxA },
    { "MessageBoxW",                    (PVOID)Hook_MessageBoxW },
    { nullptr, nullptr }
};

static FARPROC WINAPI Hook_GetProcAddress(HMODULE hModule, LPCSTR lpProcName)
{
    FARPROC result = gOrig_GetProcAddress
        ? gOrig_GetProcAddress(hModule, lpProcName)
        : ::GetProcAddress(hModule, lpProcName);

    /* Ordinal imports — can't redirect by name */
    if (!lpProcName || (ULONG_PTR)lpProcName < 0x10000) return result;
    if (!result) return result;

    for (int i = 0; kRedirects[i].name; ++i) {
        if (strcmp(lpProcName, kRedirects[i].name) == 0)
            return (FARPROC)kRedirects[i].hookFn;
    }
    return result;
}

/* ═══════════════════════════════════════════════════════════════════
 * IAT patching infrastructure
 * ═══════════════════════════════════════════════════════════════════ */

/* Extract the basename of a DLL name (strip path, no extension comparison needed) */
static const char* BaseName(const char* s)
{
    const char* last = s;
    for (const char* p = s; *p; ++p)
        if (*p == '\\' || *p == '/') last = p + 1;
    return last;
}

/*
 * Walk one module's import directory and replace each matching IAT entry.
 * dllNameFilter: the DLL whose exports to intercept, e.g. "kernel32.dll"
 *   Pass nullptr to match any source DLL.
 * funcName:      the exported function name
 * hookFn:        our replacement
 */
static void PatchIATEntry(
    HMODULE hMod,
    const char* dllNameFilter,
    const char* funcName,
    PVOID hookFn)
{
    auto* dos = (IMAGE_DOS_HEADER*)hMod;
    if (!dos || dos->e_magic != IMAGE_DOS_SIGNATURE) return;

    auto* nt = (IMAGE_NT_HEADERS*)((BYTE*)hMod + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return;

    DWORD importRVA = nt->OptionalHeader
        .DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if (!importRVA) return;

    auto* imp = (IMAGE_IMPORT_DESCRIPTOR*)((BYTE*)hMod + importRVA);

    for (; imp->Name; ++imp) {
        const char* impDll = (const char*)((BYTE*)hMod + imp->Name);
        if (dllNameFilter && _stricmp(BaseName(impDll), dllNameFilter) != 0)
            continue;

        auto* origThunk = (IMAGE_THUNK_DATA*)((BYTE*)hMod + imp->OriginalFirstThunk);
        auto* iatThunk  = (IMAGE_THUNK_DATA*)((BYTE*)hMod + imp->FirstThunk);

        /* Some modules have a null OriginalFirstThunk; fall back to FirstThunk */
        if (!imp->OriginalFirstThunk)
            origThunk = iatThunk;

        for (; origThunk->u1.AddressOfData; ++origThunk, ++iatThunk) {
            if (IMAGE_SNAP_BY_ORDINAL(origThunk->u1.Ordinal)) continue;

            auto* ibn = (IMAGE_IMPORT_BY_NAME*)((BYTE*)hMod + origThunk->u1.AddressOfData);
            if (_stricmp((char*)ibn->Name, funcName) != 0) continue;

            /* Patch the IAT entry */
            DWORD oldProt = 0;
            VirtualProtect(&iatThunk->u1.Function, sizeof(PVOID), PAGE_READWRITE, &oldProt);
            iatThunk->u1.Function = (ULONG_PTR)hookFn;
            VirtualProtect(&iatThunk->u1.Function, sizeof(PVOID), oldProt, &oldProt);
        }
    }
}

/* Patch a single module for all hooks in the redirect table */
static void PatchModule(HMODULE hMod)
{
    /* kernel32 / kernelbase hooks */
    PatchIATEntry(hMod, nullptr, "IsDebuggerPresent",           Hook_IsDebuggerPresent);
    PatchIATEntry(hMod, nullptr, "CheckRemoteDebuggerPresent",  Hook_CheckRemoteDebuggerPresent);
    PatchIATEntry(hMod, nullptr, "GetDiskFreeSpaceExA",         Hook_GetDiskFreeSpaceExA);
    PatchIATEntry(hMod, nullptr, "GetDiskFreeSpaceExW",         Hook_GetDiskFreeSpaceExW);
    PatchIATEntry(hMod, nullptr, "CreateFileA",                 Hook_CreateFileA);
    PatchIATEntry(hMod, nullptr, "CreateFileW",                 Hook_CreateFileW);
    PatchIATEntry(hMod, nullptr, "GetFileAttributesA",          Hook_GetFileAttributesA);
    PatchIATEntry(hMod, nullptr, "GetFileAttributesW",          Hook_GetFileAttributesW);
    PatchIATEntry(hMod, nullptr, "GetAsyncKeyState",            Hook_GetAsyncKeyState);
    PatchIATEntry(hMod, nullptr, "GetTickCount",                Hook_GetTickCount);
    PatchIATEntry(hMod, nullptr, "GetTickCount64",              Hook_GetTickCount64);
    PatchIATEntry(hMod, nullptr, "QueryPerformanceCounter",     Hook_QueryPerformanceCounter);
    PatchIATEntry(hMod, nullptr, "GetProcAddress",              Hook_GetProcAddress);
    /* advapi32 / kernelbase registry */
    PatchIATEntry(hMod, nullptr, "RegOpenKeyExA",               Hook_RegOpenKeyExA);
    PatchIATEntry(hMod, nullptr, "RegOpenKeyExW",               Hook_RegOpenKeyExW);
    PatchIATEntry(hMod, nullptr, "RegQueryValueExA",            Hook_RegQueryValueExA);
    PatchIATEntry(hMod, nullptr, "RegQueryValueExW",            Hook_RegQueryValueExW);
    /* ntdll */
    PatchIATEntry(hMod, nullptr, "NtQueryInformationProcess",   Hook_NtQueryInformationProcess);
    /* user32 dialog hooks */
    PatchIATEntry(hMod, nullptr, "MessageBoxA",                 Hook_MessageBoxA);
    PatchIATEntry(hMod, nullptr, "MessageBoxW",                 Hook_MessageBoxW);
    PatchIATEntry(hMod, nullptr, "NtQuerySystemInformation",    nullptr); /* covered by GetProcAddress hook */
}

/* Enumerate all modules in the current process and patch each one */
static void PatchAllModules(void)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, 0);
    if (snap == INVALID_HANDLE_VALUE) return;

    MODULEENTRY32W me = { sizeof(me) };
    HMODULE hSelf = nullptr;
    GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                       GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                       (LPCWSTR)PatchAllModules, &hSelf);

    if (Module32FirstW(snap, &me)) {
        do {
            HMODULE hMod = (HMODULE)me.modBaseAddr;
            if (hMod != hSelf) /* don't patch our own IAT */
                PatchModule(hMod);
        } while (Module32NextW(snap, &me));
    }
    CloseHandle(snap);
}

/* Resolve original function pointers directly from the exporting DLLs
 * BEFORE patching any IAT, so our hooks always have a safe call-through. */
static void ResolveOriginals(void)
{
    HMODULE hK32  = GetModuleHandleW(L"kernel32.dll");
    HMODULE hKB   = GetModuleHandleW(L"kernelbase.dll");
    HMODULE hAdv  = GetModuleHandleW(L"advapi32.dll");
    HMODULE hU32  = GetModuleHandleW(L"user32.dll");
    HMODULE hNtdl = GetModuleHandleW(L"ntdll.dll");

#define RESOLVE(mod, name, type, global) \
    if (!global && mod) global = (type)GetProcAddress(mod, name)

    RESOLVE(hK32,  "IsDebuggerPresent",             Fn_IsDebuggerPresent,          gOrig_IsDebuggerPresent);
    RESOLVE(hKB,   "IsDebuggerPresent",             Fn_IsDebuggerPresent,          gOrig_IsDebuggerPresent);
    RESOLVE(hK32,  "CheckRemoteDebuggerPresent",    Fn_CheckRemoteDebuggerPresent, gOrig_CheckRemoteDebuggerPresent);
    RESOLVE(hKB,   "CheckRemoteDebuggerPresent",    Fn_CheckRemoteDebuggerPresent, gOrig_CheckRemoteDebuggerPresent);
    RESOLVE(hK32,  "GetDiskFreeSpaceExA",           Fn_GetDiskFreeSpaceExA,        gOrig_GetDiskFreeSpaceExA);
    RESOLVE(hKB,   "GetDiskFreeSpaceExA",           Fn_GetDiskFreeSpaceExA,        gOrig_GetDiskFreeSpaceExA);
    RESOLVE(hK32,  "GetDiskFreeSpaceExW",           Fn_GetDiskFreeSpaceExW,        gOrig_GetDiskFreeSpaceExW);
    RESOLVE(hKB,   "GetDiskFreeSpaceExW",           Fn_GetDiskFreeSpaceExW,        gOrig_GetDiskFreeSpaceExW);
    RESOLVE(hAdv,  "RegOpenKeyExA",                 Fn_RegOpenKeyExA,              gOrig_RegOpenKeyExA);
    RESOLVE(hKB,   "RegOpenKeyExA",                 Fn_RegOpenKeyExA,              gOrig_RegOpenKeyExA);
    RESOLVE(hAdv,  "RegOpenKeyExW",                 Fn_RegOpenKeyExW,              gOrig_RegOpenKeyExW);
    RESOLVE(hKB,   "RegOpenKeyExW",                 Fn_RegOpenKeyExW,              gOrig_RegOpenKeyExW);
    RESOLVE(hAdv,  "RegQueryValueExA",              Fn_RegQueryValueExA,           gOrig_RegQueryValueExA);
    RESOLVE(hKB,   "RegQueryValueExA",              Fn_RegQueryValueExA,           gOrig_RegQueryValueExA);
    RESOLVE(hAdv,  "RegQueryValueExW",              Fn_RegQueryValueExW,           gOrig_RegQueryValueExW);
    RESOLVE(hKB,   "RegQueryValueExW",              Fn_RegQueryValueExW,           gOrig_RegQueryValueExW);
    RESOLVE(hK32,  "CreateFileA",                   Fn_CreateFileA,                gOrig_CreateFileA);
    RESOLVE(hKB,   "CreateFileA",                   Fn_CreateFileA,                gOrig_CreateFileA);
    RESOLVE(hK32,  "CreateFileW",                   Fn_CreateFileW,                gOrig_CreateFileW);
    RESOLVE(hKB,   "CreateFileW",                   Fn_CreateFileW,                gOrig_CreateFileW);
    RESOLVE(hK32,  "GetFileAttributesA",            Fn_GetFileAttributesA,         gOrig_GetFileAttributesA);
    RESOLVE(hKB,   "GetFileAttributesA",            Fn_GetFileAttributesA,         gOrig_GetFileAttributesA);
    RESOLVE(hK32,  "GetFileAttributesW",            Fn_GetFileAttributesW,         gOrig_GetFileAttributesW);
    RESOLVE(hKB,   "GetFileAttributesW",            Fn_GetFileAttributesW,         gOrig_GetFileAttributesW);
    RESOLVE(hU32,  "GetAsyncKeyState",              Fn_GetAsyncKeyState,           gOrig_GetAsyncKeyState);
    RESOLVE(hK32,  "GetTickCount",                  Fn_GetTickCount,               gOrig_GetTickCount);
    RESOLVE(hKB,   "GetTickCount",                  Fn_GetTickCount,               gOrig_GetTickCount);
    RESOLVE(hK32,  "GetTickCount64",                Fn_GetTickCount64,             gOrig_GetTickCount64);
    RESOLVE(hKB,   "GetTickCount64",                Fn_GetTickCount64,             gOrig_GetTickCount64);
    RESOLVE(hK32,  "QueryPerformanceCounter",       Fn_QueryPerformanceCounter,    gOrig_QueryPerformanceCounter);
    RESOLVE(hKB,   "QueryPerformanceCounter",       Fn_QueryPerformanceCounter,    gOrig_QueryPerformanceCounter);
    RESOLVE(hK32,  "GetProcAddress",                Fn_GetProcAddress,             gOrig_GetProcAddress);
    RESOLVE(hKB,   "GetProcAddress",                Fn_GetProcAddress,             gOrig_GetProcAddress);
    RESOLVE(hNtdl, "NtQueryInformationProcess",     Fn_NtQueryInformationProcess,  gOrig_NtQueryInformationProcess);
    RESOLVE(hNtdl, "NtQuerySystemInformation",      Fn_NtQuerySystemInformation,   gOrig_NtQuerySystemInformation);
    RESOLVE(hU32,  "MessageBoxA",                   Fn_MessageBoxA,                gOrig_MessageBoxA);
    RESOLVE(hU32,  "MessageBoxW",                   Fn_MessageBoxW,                gOrig_MessageBoxW);

#undef RESOLVE
}

/* ═══════════════════════════════════════════════════════════════════
 * Initialization
 * ═══════════════════════════════════════════════════════════════════ */

static DWORD WINAPI InitializationThread(LPVOID)
{
    /* 1. Resolve originals from export tables (before any IAT patching) */
    ResolveOriginals();

    /* 2. Patch every loaded module's IAT */
    PatchAllModules();

    /* 3. Optionally read policy from kernel driver */
    if (EnsureDriver()) {
        AVM_POLICY policy = {};
        DWORD bytesReturned = 0;
        DeviceIoControl(gDriver, AVM_IOCTL_GET_POLICY,
            nullptr, 0, &policy, sizeof(policy), &bytesReturned, nullptr);
    }

    SubmitRuntimeEvent(AvmEventPolicyUpdate, AvmActionLog,
        L"AvmRuntimeShim", L"dll-loaded", L"hooks-applied", 0, 0);

    return 0;
}

extern "C" __declspec(dllexport) void WINAPI AvmRuntimePing()
{
    SubmitRuntimeEvent(AvmEventNativeApiCall, AvmActionLog,
        L"AvmRuntimePing", L"manual-ping", L"logged", 0, 0);
}

BOOL APIENTRY DllMain(HMODULE module, DWORD reason, LPVOID reserved)
{
    UNREFERENCED_PARAMETER(reserved);

    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(module);
        HANDLE thread = CreateThread(nullptr, 0, InitializationThread, nullptr, 0, nullptr);
        if (thread) CloseHandle(thread);
    } else if (reason == DLL_PROCESS_DETACH) {
        SubmitRuntimeEvent(AvmEventProcessExit, AvmActionLog,
            L"AvmRuntimeShim", L"dll-unloaded", L"detach", 0, 0);
        CloseDriver();
    }
    return TRUE;
}
