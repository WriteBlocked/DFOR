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
#include <winsvc.h>
#include <stdio.h>
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
typedef SC_HANDLE (WINAPI *Fn_OpenServiceA)(SC_HANDLE, LPCSTR, DWORD);
typedef SC_HANDLE (WINAPI *Fn_OpenServiceW)(SC_HANDLE, LPCWSTR, DWORD);
typedef DWORD     (WINAPI *Fn_GetFileAttributesA)(LPCSTR);
typedef DWORD     (WINAPI *Fn_GetFileAttributesW)(LPCWSTR);
typedef SHORT     (WINAPI *Fn_GetAsyncKeyState)(int);
typedef DWORD     (WINAPI *Fn_GetTickCount)(void);
typedef ULONGLONG (WINAPI *Fn_GetTickCount64)(void);
typedef BOOL      (WINAPI *Fn_QueryPerformanceCounter)(LARGE_INTEGER*);
typedef FARPROC   (WINAPI *Fn_GetProcAddress)(HMODULE, LPCSTR);
typedef NTSTATUS  (NTAPI *Fn_NtQueryInformationProcess)(HANDLE, ULONG, PVOID, ULONG, PULONG);
typedef NTSTATUS  (NTAPI *Fn_NtQuerySystemInformation)(ULONG, PVOID, ULONG, PULONG);
typedef BOOL      (WINAPI *Fn_GetCursorPos)(LPPOINT);
typedef HANDLE    (WINAPI *Fn_FindFirstFileA)(LPCSTR, WIN32_FIND_DATAA*);
typedef HANDLE    (WINAPI *Fn_FindFirstFileW)(LPCWSTR, WIN32_FIND_DATAW*);
typedef BOOL      (WINAPI *Fn_FindNextFileA)(HANDLE, WIN32_FIND_DATAA*);
typedef BOOL      (WINAPI *Fn_FindNextFileW)(HANDLE, WIN32_FIND_DATAW*);
typedef BOOL      (WINAPI *Fn_FindClose)(HANDLE);
typedef BOOL      (WINAPI *Fn_Process32FirstW)(HANDLE, LPPROCESSENTRY32W);
typedef BOOL      (WINAPI *Fn_Process32NextW)(HANDLE, LPPROCESSENTRY32W);
typedef BOOL      (WINAPI *Fn_EnumServicesStatusExA)(SC_HANDLE, SC_ENUM_TYPE, DWORD, DWORD, LPBYTE, DWORD, LPDWORD, LPDWORD, LPDWORD, LPCSTR);
typedef BOOL      (WINAPI *Fn_EnumServicesStatusExW)(SC_HANDLE, SC_ENUM_TYPE, DWORD, DWORD, LPBYTE, DWORD, LPDWORD, LPDWORD, LPDWORD, LPCWSTR);
typedef UINT      (WINAPI *Fn_GetSystemFirmwareTable)(DWORD, DWORD, PVOID, DWORD);
typedef BOOL      (WINAPI *Fn_WriteConsoleA)(HANDLE, const VOID*, DWORD, LPDWORD, LPVOID);
typedef BOOL      (WINAPI *Fn_WriteConsoleW)(HANDLE, const VOID*, DWORD, LPDWORD, LPVOID);

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
static Fn_OpenServiceA                  gOrig_OpenServiceA                  = nullptr;
static Fn_OpenServiceW                  gOrig_OpenServiceW                  = nullptr;
static Fn_GetFileAttributesA            gOrig_GetFileAttributesA            = nullptr;
static Fn_GetFileAttributesW            gOrig_GetFileAttributesW            = nullptr;
static Fn_GetAsyncKeyState              gOrig_GetAsyncKeyState              = nullptr;
static Fn_GetTickCount                  gOrig_GetTickCount                  = nullptr;
static Fn_GetTickCount64                gOrig_GetTickCount64                = nullptr;
static Fn_QueryPerformanceCounter       gOrig_QueryPerformanceCounter       = nullptr;
static Fn_GetProcAddress                gOrig_GetProcAddress                = nullptr;
static Fn_NtQueryInformationProcess     gOrig_NtQueryInformationProcess     = nullptr;
static Fn_NtQuerySystemInformation      gOrig_NtQuerySystemInformation      = nullptr;
static Fn_GetCursorPos                  gOrig_GetCursorPos                  = nullptr;
static Fn_FindFirstFileA                gOrig_FindFirstFileA                = nullptr;
static Fn_FindFirstFileW                gOrig_FindFirstFileW                = nullptr;
static Fn_FindNextFileA                 gOrig_FindNextFileA                 = nullptr;
static Fn_FindNextFileW                 gOrig_FindNextFileW                 = nullptr;
static Fn_FindClose                     gOrig_FindClose                     = nullptr;
static Fn_Process32FirstW               gOrig_Process32FirstW               = nullptr;
static Fn_Process32NextW                gOrig_Process32NextW                = nullptr;
static Fn_EnumServicesStatusExA         gOrig_EnumServicesStatusExA         = nullptr;
static Fn_EnumServicesStatusExW         gOrig_EnumServicesStatusExW         = nullptr;
static Fn_GetSystemFirmwareTable        gOrig_GetSystemFirmwareTable        = nullptr;
static Fn_WriteConsoleA                 gOrig_WriteConsoleA                 = nullptr;
static Fn_WriteConsoleW                 gOrig_WriteConsoleW                 = nullptr;

/* Mouse activity simulation state */
static volatile LONG gMouseCallCount = 0;

static void DisableStdIoBuffering(void)
{
    if (stdout) {
        setvbuf(stdout, nullptr, _IONBF, 0);
    }

    if (stderr) {
        setvbuf(stderr, nullptr, _IONBF, 0);
    }
}

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
    "vmx86",
    "vmmemctl",
    "vgauth",
    "vmusbarb",
    "vmnet",
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
    L"vmx86",
    L"vmmemctl",
    L"vgauth",
    L"vmusbarb",
    L"vmnet",
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
    "\\drivers\\vmmemctl.sys",
    "\\drivers\\vmx86.sys",
    "\\drivers\\vmx_svga.sys",
    "\\drivers\\vboxguest.sys",
    "\\drivers\\vboxmouse.sys",
    "\\drivers\\vboxsf.sys",
    "\\drivers\\vboxvideo.sys",
    "\\drivers\\vboxwddm.sys",
    "\\vboxcontrol.exe",
    "\\vboxservice.exe",
    "\\vboxtray.exe",
    "\\vboxdisp.dll",
    "\\vboxhook.dll",
    "\\vboxogl.dll",
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
    L"\\drivers\\vmmemctl.sys",
    L"\\drivers\\vmx86.sys",
    L"\\drivers\\vmx_svga.sys",
    L"\\drivers\\vboxguest.sys",
    L"\\drivers\\vboxmouse.sys",
    L"\\drivers\\vboxsf.sys",
    L"\\drivers\\vboxvideo.sys",
    L"\\drivers\\vboxwddm.sys",
    L"\\vboxcontrol.exe",
    L"\\vboxservice.exe",
    L"\\vboxtray.exe",
    L"\\vboxdisp.dll",
    L"\\vboxhook.dll",
    L"\\vboxogl.dll",
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
    "\\\\.\\vmx86",
    "\\\\.\\vmmouse",
    "\\\\.\\vmx_svga",
    "\\\\.\\vboxguest",
    "\\\\.\\vboxminidrv",
    "\\\\.\\vboxminirdrdn",
    "\\\\.\\vboxtrayipc",
    "\\\\.\\vboxminirdr",
    "\\\\.\\vboxvideo",
    "\\\\.\\pipe\\vboxtrayipc",
    nullptr
};

/* VM pseudo-device names (wide) */
static const wchar_t* const kVmDevicesW[] = {
    L"\\\\.\\hgfs",
    L"\\\\.\\vmci",
    L"\\\\.\\vmcihostdev",
    L"\\\\.\\vmmemctl",
    L"\\\\.\\vmx86",
    L"\\\\.\\vmmouse",
    L"\\\\.\\vmx_svga",
    L"\\\\.\\vboxguest",
    L"\\\\.\\vboxminidrv",
    L"\\\\.\\vboxminirdrdn",
    L"\\\\.\\vboxtrayipc",
    L"\\\\.\\vboxminirdr",
    L"\\\\.\\vboxvideo",
    L"\\\\.\\pipe\\vboxtrayipc",
    nullptr
};

/* VM service names to hide — exact case-insensitive match */
static const char* const kVmServiceNamesA[] = {
    "vmci", "vmhgfs", "vmmouse", "vmx_svga", "vmxnet", "vmxnet3",
    "VMTools", "vmtools", "vmvss", "vm3dmp", "vm3dmp_loader",
    "vmrawdsk", "vmusbmouse", "vmmemctl", "vmx86",
    "VGAuthService", "VMUSBArbService", "vmnetbridge", "vmnetuserif",
    "vmnetadapter", "vmnetdhcp",
    "VBoxGuest", "VBoxMouse", "VBoxSF", "VBoxVideo",
    "VBoxService", "VBoxWddm",
    nullptr
};
static const wchar_t* const kVmServiceNamesW[] = {
    L"vmci", L"vmhgfs", L"vmmouse", L"vmx_svga", L"vmxnet", L"vmxnet3",
    L"VMTools", L"vmtools", L"vmvss", L"vm3dmp", L"vm3dmp_loader",
    L"vmrawdsk", L"vmusbmouse", L"vmmemctl", L"vmx86",
    L"VGAuthService", L"VMUSBArbService", L"vmnetbridge", L"vmnetuserif",
    L"vmnetadapter", L"vmnetdhcp",
    L"VBoxGuest", L"VBoxMouse", L"VBoxSF", L"VBoxVideo",
    L"VBoxService", L"VBoxWddm",
    nullptr
};

/* VM artifact file names (basename only) — used by FindFirstFile/FindNextFile hooks */
static const char* const kVmFileNamesA[] = {
    "vmmouse.sys", "vmhgfs.sys", "vmci.sys", "vm3dmp.sys",
    "vmxnet.sys", "vmx_svga.sys", "vmrawdsk.sys", "vmusbmouse.sys",
    "vmmemctl.sys", "vmx86.sys",
    "vboxguest.sys", "vboxmouse.sys", "vboxsf.sys", "vboxvideo.sys", "vboxwddm.sys",
    "vboxcontrol.exe", "vboxservice.exe", "vboxtray.exe",
    "vboxdisp.dll", "vboxhook.dll", "vboxogl.dll",
    nullptr
};

static const wchar_t* const kVmFileNamesW[] = {
    L"vmmouse.sys", L"vmhgfs.sys", L"vmci.sys", L"vm3dmp.sys",
    L"vmxnet.sys", L"vmx_svga.sys", L"vmrawdsk.sys", L"vmusbmouse.sys",
    L"vmmemctl.sys", L"vmx86.sys",
    L"vboxguest.sys", L"vboxmouse.sys", L"vboxsf.sys", L"vboxvideo.sys", L"vboxwddm.sys",
    L"vboxcontrol.exe", L"vboxservice.exe", L"vboxtray.exe",
    L"vboxdisp.dll", L"vboxhook.dll", L"vboxogl.dll",
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

static bool IsVmServiceNameA(const char* name)
{
    if (!name) return false;
    for (int i = 0; kVmServiceNamesA[i]; ++i)
        if (_stricmp(name, kVmServiceNamesA[i]) == 0) return true;
    return false;
}

static bool IsVmServiceNameW(const wchar_t* name)
{
    if (!name) return false;
    for (int i = 0; kVmServiceNamesW[i]; ++i)
        if (_wcsicmp(name, kVmServiceNamesW[i]) == 0) return true;
    return false;
}

/* True if the basename-only name matches a VM artifact */
static bool ShouldHideFileNameA(const char* name)
{
    if (!name) return false;
    for (int i = 0; kVmFileNamesA[i]; ++i)
        if (_stricmp(name, kVmFileNamesA[i]) == 0) return true;
    return IsVmFilePathA(name);
}

static bool ShouldHideFileNameW(const wchar_t* name)
{
    if (!name) return false;
    for (int i = 0; kVmFileNamesW[i]; ++i)
        if (_wcsicmp(name, kVmFileNamesW[i]) == 0) return true;
    return IsVmFilePathW(name);
}

/* ─── Filtered-find tracking ─── */
#define AVM_MAX_FILTERED_FINDS 64
struct AvmFindSlot { HANDLE h; bool active; };
static AvmFindSlot      gFilteredFinds[AVM_MAX_FILTERED_FINDS];
static CRITICAL_SECTION gFindCS;
static LONG             gFindCSInit = 0;

static void EnsureFindCS()
{
    if (InterlockedCompareExchange(&gFindCSInit, 1, 0) == 0)
        InitializeCriticalSection(&gFindCS);
}

static void TrackFilteredFind(HANDLE h)
{
    EnsureFindCS();
    EnterCriticalSection(&gFindCS);
    for (int i = 0; i < AVM_MAX_FILTERED_FINDS; ++i) {
        if (!gFilteredFinds[i].active) { gFilteredFinds[i] = { h, true }; break; }
    }
    LeaveCriticalSection(&gFindCS);
}

static bool IsFilteredFind(HANDLE h)
{
    if (!gFindCSInit) return false;
    EnterCriticalSection(&gFindCS);
    bool found = false;
    for (int i = 0; i < AVM_MAX_FILTERED_FINDS; ++i) {
        if (gFilteredFinds[i].active && gFilteredFinds[i].h == h) { found = true; break; }
    }
    LeaveCriticalSection(&gFindCS);
    return found;
}

static void UntrackFilteredFind(HANDLE h)
{
    if (!gFindCSInit) return;
    EnterCriticalSection(&gFindCS);
    for (int i = 0; i < AVM_MAX_FILTERED_FINDS; ++i) {
        if (gFilteredFinds[i].active && gFilteredFinds[i].h == h) {
            gFilteredFinds[i].active = false;
            break;
        }
    }
    LeaveCriticalSection(&gFindCS);
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

static SC_HANDLE WINAPI Hook_OpenServiceA(SC_HANDLE hSCManager, LPCSTR lpServiceName, DWORD dwDesiredAccess)
{
    if (IsVmServiceNameA(lpServiceName)) {
        SubmitRuntimeEvent(AvmEventFileProbe, AvmActionBlock,
            L"OpenServiceA", L"vm-service", L"hidden", 0, 0);
        SetLastError(ERROR_SERVICE_DOES_NOT_EXIST);
        return NULL;
    }
    if (gOrig_OpenServiceA) return gOrig_OpenServiceA(hSCManager, lpServiceName, dwDesiredAccess);
    return OpenServiceA(hSCManager, lpServiceName, dwDesiredAccess);
}

static SC_HANDLE WINAPI Hook_OpenServiceW(SC_HANDLE hSCManager, LPCWSTR lpServiceName, DWORD dwDesiredAccess)
{
    if (IsVmServiceNameW(lpServiceName)) {
        SubmitRuntimeEvent(AvmEventFileProbe, AvmActionBlock,
            L"OpenServiceW", lpServiceName ? lpServiceName : L"?", L"hidden", 0, 0);
        SetLastError(ERROR_SERVICE_DOES_NOT_EXIST);
        return NULL;
    }
    if (gOrig_OpenServiceW) return gOrig_OpenServiceW(hSCManager, lpServiceName, dwDesiredAccess);
    return OpenServiceW(hSCManager, lpServiceName, dwDesiredAccess);
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

/* ─── FindFirstFileA / FindFirstFileW ─── */

static HANDLE WINAPI Hook_FindFirstFileA(LPCSTR lpFileName, WIN32_FIND_DATAA* lpFindFileData)
{
    if (IsVmFilePathA(lpFileName)) {
        SetLastError(ERROR_FILE_NOT_FOUND);
        return INVALID_HANDLE_VALUE;
    }
    HANDLE h = gOrig_FindFirstFileA
        ? gOrig_FindFirstFileA(lpFileName, lpFindFileData)
        : ::FindFirstFileA(lpFileName, lpFindFileData);
    if (h == INVALID_HANDLE_VALUE || !lpFindFileData) return h;
    /* Skip VM entries at the head of the result set */
    while (ShouldHideFileNameA(lpFindFileData->cFileName)) {
        BOOL more = gOrig_FindNextFileA
            ? gOrig_FindNextFileA(h, lpFindFileData)
            : ::FindNextFileA(h, lpFindFileData);
        if (!more) {
            gOrig_FindClose ? gOrig_FindClose(h) : ::FindClose(h);
            SetLastError(ERROR_FILE_NOT_FOUND);
            return INVALID_HANDLE_VALUE;
        }
    }
    TrackFilteredFind(h);
    return h;
}

static HANDLE WINAPI Hook_FindFirstFileW(LPCWSTR lpFileName, WIN32_FIND_DATAW* lpFindFileData)
{
    if (IsVmFilePathW(lpFileName)) {
        SetLastError(ERROR_FILE_NOT_FOUND);
        return INVALID_HANDLE_VALUE;
    }
    HANDLE h = gOrig_FindFirstFileW
        ? gOrig_FindFirstFileW(lpFileName, lpFindFileData)
        : ::FindFirstFileW(lpFileName, lpFindFileData);
    if (h == INVALID_HANDLE_VALUE || !lpFindFileData) return h;
    while (ShouldHideFileNameW(lpFindFileData->cFileName)) {
        BOOL more = gOrig_FindNextFileW
            ? gOrig_FindNextFileW(h, lpFindFileData)
            : ::FindNextFileW(h, lpFindFileData);
        if (!more) {
            gOrig_FindClose ? gOrig_FindClose(h) : ::FindClose(h);
            SetLastError(ERROR_FILE_NOT_FOUND);
            return INVALID_HANDLE_VALUE;
        }
    }
    TrackFilteredFind(h);
    return h;
}

/* ─── FindNextFileA / FindNextFileW ─── */

static BOOL WINAPI Hook_FindNextFileA(HANDLE hFindFile, WIN32_FIND_DATAA* lpFindFileData)
{
    if (!IsFilteredFind(hFindFile)) {
        return gOrig_FindNextFileA
            ? gOrig_FindNextFileA(hFindFile, lpFindFileData)
            : ::FindNextFileA(hFindFile, lpFindFileData);
    }
    for (;;) {
        BOOL ok = gOrig_FindNextFileA
            ? gOrig_FindNextFileA(hFindFile, lpFindFileData)
            : ::FindNextFileA(hFindFile, lpFindFileData);
        if (!ok) return FALSE;
        if (!ShouldHideFileNameA(lpFindFileData->cFileName)) return TRUE;
    }
}

static BOOL WINAPI Hook_FindNextFileW(HANDLE hFindFile, WIN32_FIND_DATAW* lpFindFileData)
{
    if (!IsFilteredFind(hFindFile)) {
        return gOrig_FindNextFileW
            ? gOrig_FindNextFileW(hFindFile, lpFindFileData)
            : ::FindNextFileW(hFindFile, lpFindFileData);
    }
    for (;;) {
        BOOL ok = gOrig_FindNextFileW
            ? gOrig_FindNextFileW(hFindFile, lpFindFileData)
            : ::FindNextFileW(hFindFile, lpFindFileData);
        if (!ok) return FALSE;
        if (!ShouldHideFileNameW(lpFindFileData->cFileName)) return TRUE;
    }
}

/* ─── FindClose ─── */

static BOOL WINAPI Hook_FindClose(HANDLE hFindFile)
{
    UntrackFilteredFind(hFindFile);
    return gOrig_FindClose ? gOrig_FindClose(hFindFile) : ::FindClose(hFindFile);
}

/* ─── EnumServicesStatusExA / EnumServicesStatusExW ─── */

static BOOL WINAPI Hook_EnumServicesStatusExA(
    SC_HANDLE hSCManager, SC_ENUM_TYPE InfoLevel,
    DWORD dwServiceType, DWORD dwServiceState,
    LPBYTE lpServices, DWORD cbBufSize,
    LPDWORD pcbBytesNeeded, LPDWORD lpServicesReturned,
    LPDWORD lpResumeHandle, LPCSTR pszGroupName)
{
    BOOL ok = gOrig_EnumServicesStatusExA
        ? gOrig_EnumServicesStatusExA(hSCManager, InfoLevel, dwServiceType, dwServiceState,
                                       lpServices, cbBufSize, pcbBytesNeeded, lpServicesReturned,
                                       lpResumeHandle, pszGroupName)
        : ::EnumServicesStatusExA(hSCManager, InfoLevel, dwServiceType, dwServiceState,
                                   lpServices, cbBufSize, pcbBytesNeeded, lpServicesReturned,
                                   lpResumeHandle, pszGroupName);
    if (!ok || !lpServices || !lpServicesReturned || *lpServicesReturned == 0) return ok;
    if (InfoLevel != SC_ENUM_PROCESS_INFO) return ok;
    auto* arr  = (ENUM_SERVICE_STATUS_PROCESSA*)lpServices;
    DWORD n    = *lpServicesReturned;
    DWORD wIdx = 0;
    for (DWORD i = 0; i < n; ++i) {
        if (!arr[i].lpServiceName || !IsVmServiceNameA(arr[i].lpServiceName)) {
            if (wIdx != i) arr[wIdx] = arr[i];
            ++wIdx;
        }
    }
    *lpServicesReturned = wIdx;
    return ok;
}

static BOOL WINAPI Hook_EnumServicesStatusExW(
    SC_HANDLE hSCManager, SC_ENUM_TYPE InfoLevel,
    DWORD dwServiceType, DWORD dwServiceState,
    LPBYTE lpServices, DWORD cbBufSize,
    LPDWORD pcbBytesNeeded, LPDWORD lpServicesReturned,
    LPDWORD lpResumeHandle, LPCWSTR pszGroupName)
{
    BOOL ok = gOrig_EnumServicesStatusExW
        ? gOrig_EnumServicesStatusExW(hSCManager, InfoLevel, dwServiceType, dwServiceState,
                                       lpServices, cbBufSize, pcbBytesNeeded, lpServicesReturned,
                                       lpResumeHandle, pszGroupName)
        : ::EnumServicesStatusExW(hSCManager, InfoLevel, dwServiceType, dwServiceState,
                                   lpServices, cbBufSize, pcbBytesNeeded, lpServicesReturned,
                                   lpResumeHandle, pszGroupName);
    if (!ok || !lpServices || !lpServicesReturned || *lpServicesReturned == 0) return ok;
    if (InfoLevel != SC_ENUM_PROCESS_INFO) return ok;
    auto* arr  = (ENUM_SERVICE_STATUS_PROCESSW*)lpServices;
    DWORD n    = *lpServicesReturned;
    DWORD wIdx = 0;
    for (DWORD i = 0; i < n; ++i) {
        if (!arr[i].lpServiceName || !IsVmServiceNameW(arr[i].lpServiceName)) {
            if (wIdx != i) arr[wIdx] = arr[i];
            ++wIdx;
        }
    }
    *lpServicesReturned = wIdx;
    return ok;
}

/* ─── GetSystemFirmwareTable — scrub VMware/VirtualBox strings from SMBIOS ─── */
/* CRITICAL: each replacement must be the SAME byte length as its search string. */
static UINT WINAPI Hook_GetSystemFirmwareTable(
    DWORD FirmwareTableProviderSignature, DWORD FirmwareTableID,
    PVOID pFirmwareTableBuffer, DWORD BufferSize)
{
    UINT result = gOrig_GetSystemFirmwareTable
        ? gOrig_GetSystemFirmwareTable(FirmwareTableProviderSignature, FirmwareTableID,
                                        pFirmwareTableBuffer, BufferSize)
        : ::GetSystemFirmwareTable(FirmwareTableProviderSignature, FirmwareTableID,
                                    pFirmwareTableBuffer, BufferSize);
    if (!result || !pFirmwareTableBuffer || !BufferSize) return result;

    struct FwEntry { const char* find; const char* replace; };
    static const FwEntry kFwReplace[] = {
        /* 12-char: */ { "VMware, Inc.", "Dell Inc.   " },
        /* 11-char: */ { "VMware Inc.", "Dell Inc.  " },
        /* 10-char: */ { "VirtualBox",  "Dell Inc. " },
        /* 10-char: */ { "VMware Inc",  "Dell Inc. " },
        /*  7-char: */ { "VMware-",     "SERIAL-"    },
        /*  6-char: */ { "VMware",      "Dell  "     },
        /*  6-char: */ { "VMWARE",      "DELL  "     },
        /*  4-char: */ { "VBox",        "Dell"       },
        /*  4-char: */ { "vbox",        "dell"       },
        { nullptr, nullptr }
    };

    auto* buf = (BYTE*)pFirmwareTableBuffer;
    for (UINT i = 0; i < result; ) {
        bool replaced = false;
        for (int k = 0; kFwReplace[k].find; ++k) {
            size_t flen = strlen(kFwReplace[k].find);
            if (i + flen > result) continue;
            if (_strnicmp((char*)buf + i, kFwReplace[k].find, flen) == 0) {
                memcpy(buf + i, kFwReplace[k].replace, flen);
                i += (UINT)flen;
                replaced = true;
                break;
            }
        }
        if (!replaced) ++i;
    }
    return result;
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

/* Simulate mouse movement so consecutive GetCursorPos calls return different positions */
static volatile LONG sCursorCallCount = 0;

static BOOL WINAPI Hook_GetCursorPos(LPPOINT lpPoint)
{
    BOOL result = FALSE;
    LONG n;

    if (!lpPoint) return FALSE;

    if (gOrig_GetCursorPos)
        result = gOrig_GetCursorPos(lpPoint);
    else {
        lpPoint->x = 400;
        lpPoint->y = 300;
        result = TRUE;
    }

    n = InterlockedIncrement(&sCursorCallCount);
    /* Add a small progressive offset so movement checks see changing positions */
    lpPoint->x += (LONG)((n * 7) % 120);
    lpPoint->y += (LONG)((n * 5) % 90);

    return result;
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
    { "OpenServiceA",                   (PVOID)Hook_OpenServiceA },
    { "OpenServiceW",                   (PVOID)Hook_OpenServiceW },
    { "GetFileAttributesA",             (PVOID)Hook_GetFileAttributesA },
    { "GetFileAttributesW",             (PVOID)Hook_GetFileAttributesW },
    { "FindFirstFileA",                 (PVOID)Hook_FindFirstFileA },
    { "FindFirstFileW",                 (PVOID)Hook_FindFirstFileW },
    { "FindNextFileA",                  (PVOID)Hook_FindNextFileA },
    { "FindNextFileW",                  (PVOID)Hook_FindNextFileW },
    { "FindClose",                      (PVOID)Hook_FindClose },
    { "EnumServicesStatusExA",          (PVOID)Hook_EnumServicesStatusExA },
    { "EnumServicesStatusExW",          (PVOID)Hook_EnumServicesStatusExW },
    { "GetSystemFirmwareTable",         (PVOID)Hook_GetSystemFirmwareTable },
    { "GetAsyncKeyState",               (PVOID)Hook_GetAsyncKeyState },
    { "GetCursorPos",                   (PVOID)Hook_GetCursorPos },
    { "GetTickCount",                   (PVOID)Hook_GetTickCount },
    { "GetTickCount64",                 (PVOID)Hook_GetTickCount64 },
    { "QueryPerformanceCounter",        (PVOID)Hook_QueryPerformanceCounter },
    { "NtQueryInformationProcess",      (PVOID)Hook_NtQueryInformationProcess },
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
 * WriteConsole hooks — redirect to WriteFile so pipe capture works
 * When stdout/stderr is a pipe (e.g. launched via controller "Launch with Shim"),
 * WriteConsoleA/W fails on the pipe handle.  These hooks fall back to
 * WriteFile so all console output is captured.
 * ═══════════════════════════════════════════════════════════════════ */

static BOOL WINAPI Hook_WriteConsoleA(
    HANDLE       hConsoleOutput,
    const VOID*  lpBuffer,
    DWORD        nCharsToWrite,
    LPDWORD      lpCharsWritten,
    LPVOID       lpReserved)
{
    /* Try the real WriteConsoleA first (works when attached to an actual console) */
    if (gOrig_WriteConsoleA &&
        gOrig_WriteConsoleA(hConsoleOutput, lpBuffer, nCharsToWrite, lpCharsWritten, lpReserved))
        return TRUE;

    /* Fall back: pipe / file handle — write raw bytes */
    DWORD written = 0;
    BOOL  ok = WriteFile(hConsoleOutput, lpBuffer, nCharsToWrite, &written, nullptr);
    if (lpCharsWritten) *lpCharsWritten = written;
    return ok;
}

static BOOL WINAPI Hook_WriteConsoleW(
    HANDLE       hConsoleOutput,
    const VOID*  lpBuffer,
    DWORD        nCharsToWrite,
    LPDWORD      lpCharsWritten,
    LPVOID       lpReserved)
{
    /* Try the real WriteConsoleW first */
    if (gOrig_WriteConsoleW &&
        gOrig_WriteConsoleW(hConsoleOutput, lpBuffer, nCharsToWrite, lpCharsWritten, lpReserved))
        return TRUE;

    /* Fall back: convert UTF-16 → UTF-8 and write to the pipe */
    int bytes = WideCharToMultiByte(CP_UTF8, 0, (LPCWSTR)lpBuffer, (int)nCharsToWrite,
                                    nullptr, 0, nullptr, nullptr);
    if (bytes <= 0) return FALSE;

    char* buf = (char*)HeapAlloc(GetProcessHeap(), 0, (SIZE_T)bytes);
    if (!buf) return FALSE;

    WideCharToMultiByte(CP_UTF8, 0, (LPCWSTR)lpBuffer, (int)nCharsToWrite,
                        buf, bytes, nullptr, nullptr);

    DWORD written = 0;
    BOOL  ok = WriteFile(hConsoleOutput, buf, (DWORD)bytes, &written, nullptr);
    HeapFree(GetProcessHeap(), 0, buf);

    if (lpCharsWritten) *lpCharsWritten = (ok ? nCharsToWrite : 0);
    return ok;
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

        /* Skip bound import descriptors (OriginalFirstThunk == 0 means the
         * FirstThunk holds resolved VAs, not RVAs into IMAGE_IMPORT_BY_NAME). */
        if (!imp->OriginalFirstThunk) continue;

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
    PatchIATEntry(hMod, nullptr, "FindFirstFileA",              Hook_FindFirstFileA);
    PatchIATEntry(hMod, nullptr, "FindFirstFileW",              Hook_FindFirstFileW);
    PatchIATEntry(hMod, nullptr, "FindNextFileA",               Hook_FindNextFileA);
    PatchIATEntry(hMod, nullptr, "FindNextFileW",               Hook_FindNextFileW);
    PatchIATEntry(hMod, nullptr, "FindClose",                   Hook_FindClose);
    PatchIATEntry(hMod, nullptr, "EnumServicesStatusExA",       Hook_EnumServicesStatusExA);
    PatchIATEntry(hMod, nullptr, "EnumServicesStatusExW",       Hook_EnumServicesStatusExW);
    PatchIATEntry(hMod, nullptr, "GetSystemFirmwareTable",      Hook_GetSystemFirmwareTable);
    PatchIATEntry(hMod, nullptr, "GetAsyncKeyState",            Hook_GetAsyncKeyState);
    PatchIATEntry(hMod, nullptr, "GetCursorPos",                Hook_GetCursorPos);
    PatchIATEntry(hMod, nullptr, "GetTickCount",                Hook_GetTickCount);
    PatchIATEntry(hMod, nullptr, "GetTickCount64",              Hook_GetTickCount64);
    PatchIATEntry(hMod, nullptr, "QueryPerformanceCounter",     Hook_QueryPerformanceCounter);
    PatchIATEntry(hMod, nullptr, "GetProcAddress",              Hook_GetProcAddress);
    /* advapi32 service manager */
    PatchIATEntry(hMod, nullptr, "OpenServiceA",                Hook_OpenServiceA);
    PatchIATEntry(hMod, nullptr, "OpenServiceW",                Hook_OpenServiceW);
    /* advapi32 / kernelbase registry */
    PatchIATEntry(hMod, nullptr, "RegOpenKeyExA",               Hook_RegOpenKeyExA);
    PatchIATEntry(hMod, nullptr, "RegOpenKeyExW",               Hook_RegOpenKeyExW);
    PatchIATEntry(hMod, nullptr, "RegQueryValueExA",            Hook_RegQueryValueExA);
    PatchIATEntry(hMod, nullptr, "RegQueryValueExW",            Hook_RegQueryValueExW);
    /* ntdll */
    PatchIATEntry(hMod, nullptr, "WriteConsoleA",               Hook_WriteConsoleA);
    PatchIATEntry(hMod, nullptr, "WriteConsoleW",               Hook_WriteConsoleW);
    PatchIATEntry(hMod, nullptr, "NtQueryInformationProcess",   Hook_NtQueryInformationProcess);
    /* NtQuerySystemInformation is intercepted via the GetProcAddress hook above; no IAT patch needed */
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
    RESOLVE(hAdv,  "OpenServiceA",                  Fn_OpenServiceA,               gOrig_OpenServiceA);
    RESOLVE(hAdv,  "OpenServiceW",                  Fn_OpenServiceW,               gOrig_OpenServiceW);
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
    RESOLVE(hU32,  "GetCursorPos",                  Fn_GetCursorPos,               gOrig_GetCursorPos);
    RESOLVE(hK32,  "GetTickCount",                  Fn_GetTickCount,               gOrig_GetTickCount);
    RESOLVE(hKB,   "GetTickCount",                  Fn_GetTickCount,               gOrig_GetTickCount);
    RESOLVE(hK32,  "GetTickCount64",                Fn_GetTickCount64,             gOrig_GetTickCount64);
    RESOLVE(hKB,   "GetTickCount64",                Fn_GetTickCount64,             gOrig_GetTickCount64);
    RESOLVE(hK32,  "QueryPerformanceCounter",       Fn_QueryPerformanceCounter,    gOrig_QueryPerformanceCounter);
    RESOLVE(hKB,   "QueryPerformanceCounter",       Fn_QueryPerformanceCounter,    gOrig_QueryPerformanceCounter);
    RESOLVE(hK32,  "GetProcAddress",                Fn_GetProcAddress,             gOrig_GetProcAddress);
    RESOLVE(hKB,   "GetProcAddress",                Fn_GetProcAddress,             gOrig_GetProcAddress);
    RESOLVE(hK32,  "FindFirstFileA",                Fn_FindFirstFileA,             gOrig_FindFirstFileA);
    RESOLVE(hKB,   "FindFirstFileA",                Fn_FindFirstFileA,             gOrig_FindFirstFileA);
    RESOLVE(hK32,  "FindFirstFileW",                Fn_FindFirstFileW,             gOrig_FindFirstFileW);
    RESOLVE(hKB,   "FindFirstFileW",                Fn_FindFirstFileW,             gOrig_FindFirstFileW);
    RESOLVE(hK32,  "FindNextFileA",                 Fn_FindNextFileA,              gOrig_FindNextFileA);
    RESOLVE(hKB,   "FindNextFileA",                 Fn_FindNextFileA,              gOrig_FindNextFileA);
    RESOLVE(hK32,  "FindNextFileW",                 Fn_FindNextFileW,              gOrig_FindNextFileW);
    RESOLVE(hKB,   "FindNextFileW",                 Fn_FindNextFileW,              gOrig_FindNextFileW);
    RESOLVE(hK32,  "FindClose",                     Fn_FindClose,                  gOrig_FindClose);
    RESOLVE(hKB,   "FindClose",                     Fn_FindClose,                  gOrig_FindClose);
    RESOLVE(hAdv,  "EnumServicesStatusExA",         Fn_EnumServicesStatusExA,      gOrig_EnumServicesStatusExA);
    RESOLVE(hAdv,  "EnumServicesStatusExW",         Fn_EnumServicesStatusExW,      gOrig_EnumServicesStatusExW);
    RESOLVE(hK32,  "GetSystemFirmwareTable",        Fn_GetSystemFirmwareTable,     gOrig_GetSystemFirmwareTable);
    RESOLVE(hKB,   "GetSystemFirmwareTable",        Fn_GetSystemFirmwareTable,     gOrig_GetSystemFirmwareTable);
    RESOLVE(hK32,  "WriteConsoleA",                 Fn_WriteConsoleA,              gOrig_WriteConsoleA);
    RESOLVE(hKB,   "WriteConsoleA",                 Fn_WriteConsoleA,              gOrig_WriteConsoleA);
    RESOLVE(hK32,  "WriteConsoleW",                 Fn_WriteConsoleW,              gOrig_WriteConsoleW);
    RESOLVE(hKB,   "WriteConsoleW",                 Fn_WriteConsoleW,              gOrig_WriteConsoleW);
    RESOLVE(hNtdl, "NtQueryInformationProcess",     Fn_NtQueryInformationProcess,  gOrig_NtQueryInformationProcess);
    RESOLVE(hNtdl, "NtQuerySystemInformation",      Fn_NtQuerySystemInformation,   gOrig_NtQuerySystemInformation);

#undef RESOLVE
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
        DisableStdIoBuffering();

        /* Synchronously resolve originals and patch the main EXE's IAT BEFORE
         * the background thread is created and BEFORE the injector calls
         * ResumeThread.  Patching only the main EXE is sufficient — app code
         * calls functions via its own IAT.  Patching system DLLs here is both
         * unnecessary and dangerous (system DLLs can have bound-import
         * descriptors whose FirstThunk entries are resolved VAs, not RVAs). */
        ResolveOriginals();
        PatchModule(GetModuleHandleW(nullptr)); /* main EXE only */

        /* Keep the shim conservative for stability. Patching the main EXE's
         * imports covers the probe and pafish startup paths without racing a
         * broad background sweep across already-loaded modules. */
    } else if (reason == DLL_PROCESS_DETACH) {
        SubmitRuntimeEvent(AvmEventProcessExit, AvmActionLog,
            L"AvmRuntimeShim", L"dll-unloaded", L"detach", 0, 0);
        CloseDriver();
    }
    return TRUE;
}
