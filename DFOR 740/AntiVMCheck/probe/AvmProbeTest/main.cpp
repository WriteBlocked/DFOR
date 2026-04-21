/*
 * AvmProbeTest - Validation probe for the AntiVMCheck platform.
 *
 * Checks whether common VM indicators are visible on the current machine
 * and probes the AvmKernel driver and minifilter if they are loaded.
 *
 * Usage:  AvmProbeTest.exe [output.json]
 */

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <Windows.h>
#include <winioctl.h>
#include <iphlpapi.h>
#include <ws2ipdef.h>
#include <tlhelp32.h>
#include <intrin.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#include <string>
#include <vector>

#include "avm_shared.h"

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "ws2_32.lib")

/* ------------------------------------------------------------------ */
/*  Result types                                                       */
/* ------------------------------------------------------------------ */

enum ProbeResult { DETECTED = 0, NOT_DETECTED = 1, PROBE_ERROR = 2 };

static const char* ResultLabel(ProbeResult r)
{
    switch (r) {
    case DETECTED:     return "detected";
    case NOT_DETECTED: return "not detected";
    case PROBE_ERROR:  return "error";
    default:           return "unknown";
    }
}

struct ProbeCheck {
    std::string name;
    std::string category;
    ProbeResult result;
    std::string detail;
};

static std::vector<ProbeCheck> g_checks;

static void AddCheck(const char* name, const char* category,
                     ProbeResult result, const char* detail = "")
{
    ProbeCheck c;
    c.name     = name;
    c.category = category;
    c.result   = result;
    c.detail   = detail ? detail : "";
    g_checks.push_back(c);
}

/* ------------------------------------------------------------------ */
/*  Helpers                                                            */
/* ------------------------------------------------------------------ */

static std::string WideToUtf8(const wchar_t* ws)
{
    if (!ws || !ws[0]) return "";
    int len = WideCharToMultiByte(CP_UTF8, 0, ws, -1, NULL, 0, NULL, NULL);
    if (len <= 0) return "";
    std::string s((size_t)(len - 1), '\0');
    WideCharToMultiByte(CP_UTF8, 0, ws, -1, &s[0], len, NULL, NULL);
    return s;
}

static std::string ReadRegString(HKEY root, const wchar_t* subkey,
                                 const wchar_t* valueName)
{
    HKEY hk = NULL;
    if (RegOpenKeyExW(root, subkey, 0, KEY_READ, &hk) != ERROR_SUCCESS)
        return "(could not open key)";
    wchar_t buf[512] = {};
    DWORD sz = sizeof(buf) - sizeof(wchar_t);
    DWORD type = 0;
    std::string result;
    if (RegQueryValueExW(hk, valueName, NULL, &type,
                         (BYTE*)buf, &sz) == ERROR_SUCCESS)
        result = WideToUtf8(buf);
    else
        result = "(value not found)";
    RegCloseKey(hk);
    return result;
}

static bool ContainsAnyCI(const std::string& haystack,
                          const char* const* needles, size_t count)
{
    std::string lower = haystack;
    for (size_t i = 0; i < lower.size(); i++)
        lower[i] = (char)tolower((unsigned char)lower[i]);
    for (size_t i = 0; i < count; i++) {
        if (lower.find(needles[i]) != std::string::npos)
            return true;
    }
    return false;
}

/* ------------------------------------------------------------------ */
/*  CPUID                                                              */
/* ------------------------------------------------------------------ */

static void CheckCpuidHypervisorBit()
{
    int regs[4] = {};
    __cpuid(regs, 1);
    bool hvBit = ((regs[2] >> 31) & 1) != 0;
    AddCheck("CPUID hypervisor bit", "CPUID",
             hvBit ? DETECTED : NOT_DETECTED,
             hvBit ? "ECX bit 31 is set" : "ECX bit 31 is clear");
}

static void CheckCpuidHypervisorVendor()
{
    int regs[4] = {};
    __cpuid(regs, 0x40000000);
    char vendor[13] = {};
    memcpy(vendor,     &regs[1], 4);
    memcpy(vendor + 4, &regs[2], 4);
    memcpy(vendor + 8, &regs[3], 4);

    const char* vmVendors[] = {
        "VMwareVMware", "Microsoft Hv", "KVMKVMKVM\0\0\0",
        "XenVMMXenVMM", "VBoxVBoxVBox"
    };
    bool isVm = false;
    for (int i = 0; i < _countof(vmVendors); i++) {
        if (memcmp(vendor, vmVendors[i], 12) == 0) { isVm = true; break; }
    }

    std::string detail = "vendor: ";
    detail += vendor;
    AddCheck("CPUID hypervisor vendor", "CPUID",
             isVm ? DETECTED : NOT_DETECTED, detail.c_str());
}

/* ------------------------------------------------------------------ */
/*  BIOS / System identity (registry)                                  */
/* ------------------------------------------------------------------ */

static void CheckBiosVendor()
{
    std::string val = ReadRegString(HKEY_LOCAL_MACHINE,
        L"HARDWARE\\DESCRIPTION\\System\\BIOS", L"BIOSVendor");
    const char* kw[] = {"vmware","virtualbox","vbox","qemu","xen",
                        "parallels","innotek"};
    bool isVm = ContainsAnyCI(val, kw, _countof(kw));
    AddCheck("BIOS vendor", "BIOS/Registry", isVm ? DETECTED : NOT_DETECTED,
             val.c_str());
}

static void CheckSystemManufacturer()
{
    std::string val = ReadRegString(HKEY_LOCAL_MACHINE,
        L"HARDWARE\\DESCRIPTION\\System\\BIOS", L"SystemManufacturer");
    const char* kw[] = {"vmware","virtualbox","vbox","qemu","xen",
                        "microsoft corporation","parallels","innotek"};
    bool isVm = ContainsAnyCI(val, kw, _countof(kw));
    AddCheck("System manufacturer", "BIOS/Registry",
             isVm ? DETECTED : NOT_DETECTED, val.c_str());
}

static void CheckSystemProductName()
{
    std::string val = ReadRegString(HKEY_LOCAL_MACHINE,
        L"HARDWARE\\DESCRIPTION\\System\\BIOS", L"SystemProductName");
    const char* kw[] = {"vmware","virtual machine","virtualbox","vbox",
                        "kvm","hvm domU"};
    bool isVm = ContainsAnyCI(val, kw, _countof(kw));
    AddCheck("System product name", "BIOS/Registry",
             isVm ? DETECTED : NOT_DETECTED, val.c_str());
}

/* ------------------------------------------------------------------ */
/*  VMware registry keys                                               */
/* ------------------------------------------------------------------ */

static void CheckVmwareRegistryKeys()
{
    const wchar_t* keys[] = {
        L"SOFTWARE\\VMware, Inc.\\VMware Tools",
        L"SOFTWARE\\VMware, Inc.\\VMware VGAuth",
        L"SYSTEM\\CurrentControlSet\\Services\\vmci",
        L"SYSTEM\\CurrentControlSet\\Services\\vmhgfs",
        L"SYSTEM\\CurrentControlSet\\Services\\vmmouse",
        L"SYSTEM\\CurrentControlSet\\Services\\VMTools"
    };
    int found = 0;
    std::string detail;
    for (int i = 0; i < _countof(keys); i++) {
        HKEY hk = NULL;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, keys[i], 0,
                          KEY_READ, &hk) == ERROR_SUCCESS) {
            RegCloseKey(hk);
            found++;
            if (!detail.empty()) detail += ", ";
            detail += WideToUtf8(keys[i]);
        }
    }
    char buf[64];
    sprintf_s(buf, "%d of %d keys found", found, (int)_countof(keys));
    if (found > 0) detail = std::string(buf) + ": " + detail;
    else detail = buf;
    AddCheck("VMware registry keys", "Registry",
             found > 0 ? DETECTED : NOT_DETECTED, detail.c_str());
}

static void CheckVBoxRegistryKeys()
{
    const wchar_t* keys[] = {
        L"SOFTWARE\\Oracle\\VirtualBox Guest Additions",
        L"SYSTEM\\CurrentControlSet\\Services\\VBoxGuest",
        L"SYSTEM\\CurrentControlSet\\Services\\VBoxMouse",
        L"SYSTEM\\CurrentControlSet\\Services\\VBoxSF",
        L"SYSTEM\\CurrentControlSet\\Services\\VBoxVideo",
        L"SYSTEM\\CurrentControlSet\\Services\\VBoxService",
    };
    int found = 0;
    std::string detail;
    for (int i = 0; i < _countof(keys); i++) {
        HKEY hk = NULL;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, keys[i], 0,
                          KEY_READ, &hk) == ERROR_SUCCESS) {
            RegCloseKey(hk);
            found++;
            if (!detail.empty()) detail += ", ";
            detail += WideToUtf8(keys[i]);
        }
    }
    char buf[64];
    sprintf_s(buf, "%d of %d keys found", found, (int)_countof(keys));
    if (found > 0) detail = std::string(buf) + ": " + detail;
    else detail = buf;
    AddCheck("VirtualBox registry keys", "Registry",
             found > 0 ? DETECTED : NOT_DETECTED, detail.c_str());
}

/* ------------------------------------------------------------------ */
/*  VMware driver / service names                                      */
/* ------------------------------------------------------------------ */

static void CheckVmwareServices()
{
    const wchar_t* services[] = {
        L"vmci", L"vmhgfs", L"vmmouse", L"vmx_svga", L"vmxnet",
        L"VMTools", L"vmvss", L"vm3dmp", L"vmrawdsk", L"vmusbmouse"
    };
    SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    if (!scm) {
        AddCheck("VMware services/drivers", "Services", PROBE_ERROR,
                 "Could not open SCM (run as admin?)");
        return;
    }
    int found = 0;
    std::string detail;
    for (int i = 0; i < _countof(services); i++) {
        SC_HANDLE h = OpenServiceW(scm, services[i], SERVICE_QUERY_STATUS);
        if (h) {
            CloseServiceHandle(h);
            found++;
            if (!detail.empty()) detail += ", ";
            detail += WideToUtf8(services[i]);
        }
    }
    CloseServiceHandle(scm);
    char buf[64];
    sprintf_s(buf, "%d of %d services found", found, (int)_countof(services));
    if (found > 0) detail = std::string(buf) + ": " + detail;
    else detail = buf;
    AddCheck("VMware services/drivers", "Services",
             found > 0 ? DETECTED : NOT_DETECTED, detail.c_str());
}

static void CheckVBoxServices()
{
    const wchar_t* services[] = {
        L"VBoxGuest", L"VBoxMouse", L"VBoxSF", L"VBoxVideo",
        L"VBoxService", L"VBoxWddm",
    };
    SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    if (!scm) {
        AddCheck("VirtualBox services", "Services", PROBE_ERROR,
                 "Could not open SCM");
        return;
    }
    int found = 0;
    std::string detail;
    for (int i = 0; i < _countof(services); i++) {
        SC_HANDLE h = OpenServiceW(scm, services[i], SERVICE_QUERY_STATUS);
        if (h) {
            CloseServiceHandle(h);
            found++;
            if (!detail.empty()) detail += ", ";
            detail += WideToUtf8(services[i]);
        }
    }
    CloseServiceHandle(scm);
    char buf[64];
    sprintf_s(buf, "%d of %d services found", found, (int)_countof(services));
    if (found > 0) detail = std::string(buf) + ": " + detail;
    else detail = buf;
    AddCheck("VirtualBox services", "Services",
             found > 0 ? DETECTED : NOT_DETECTED, detail.c_str());
}

/* ------------------------------------------------------------------ */
/*  VMware files                                                       */
/* ------------------------------------------------------------------ */

static void CheckVmwareFiles()
{
    const wchar_t* files[] = {
        L"C:\\Windows\\System32\\drivers\\vmci.sys",
        L"C:\\Windows\\System32\\drivers\\vmhgfs.sys",
        L"C:\\Windows\\System32\\drivers\\vmmouse.sys",
        L"C:\\Windows\\System32\\drivers\\vm3dmp.sys",
        L"C:\\Windows\\System32\\drivers\\vmxnet.sys",
        L"C:\\Windows\\System32\\drivers\\vmx_svga.sys",
        L"C:\\Program Files\\VMware\\VMware Tools\\vmtoolsd.exe",
        L"C:\\Program Files\\VMware\\VMware Tools\\VMwareToolboxCmd.exe"
    };
    int found = 0;
    std::string detail;
    for (int i = 0; i < _countof(files); i++) {
        if (GetFileAttributesW(files[i]) != INVALID_FILE_ATTRIBUTES) {
            found++;
            if (!detail.empty()) detail += ", ";
            detail += WideToUtf8(files[i]);
        }
    }
    char buf[64];
    sprintf_s(buf, "%d of %d files found", found, (int)_countof(files));
    if (found > 0) detail = std::string(buf) + ": " + detail;
    else detail = buf;
    AddCheck("VMware files", "Files",
             found > 0 ? DETECTED : NOT_DETECTED, detail.c_str());
}

/* ------------------------------------------------------------------ */
/*  VMware directories                                                 */
/* ------------------------------------------------------------------ */

static void CheckVmwareDirectories()
{
    const wchar_t* dirs[] = {
        L"C:\\Program Files\\VMware",
        L"C:\\Program Files\\VMware\\VMware Tools",
        L"C:\\Program Files (x86)\\VMware"
    };
    int found = 0;
    std::string detail;
    for (int i = 0; i < _countof(dirs); i++) {
        DWORD attr = GetFileAttributesW(dirs[i]);
        if (attr != INVALID_FILE_ATTRIBUTES &&
            (attr & FILE_ATTRIBUTE_DIRECTORY)) {
            found++;
            if (!detail.empty()) detail += ", ";
            detail += WideToUtf8(dirs[i]);
        }
    }
    char buf[64];
    sprintf_s(buf, "%d of %d directories found", found, (int)_countof(dirs));
    if (found > 0) detail = std::string(buf) + ": " + detail;
    else detail = buf;
    AddCheck("VMware directories", "Files",
             found > 0 ? DETECTED : NOT_DETECTED, detail.c_str());
}

static void CheckVBoxFiles()
{
    const wchar_t* files[] = {
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
    };
    int found = 0;
    std::string detail;
    for (int i = 0; i < _countof(files); i++) {
        if (GetFileAttributesW(files[i]) != INVALID_FILE_ATTRIBUTES) {
            found++;
            if (!detail.empty()) detail += ", ";
            detail += WideToUtf8(files[i]);
        }
    }
    char buf[64];
    sprintf_s(buf, "%d of %d files found", found, (int)_countof(files));
    if (found > 0) detail = std::string(buf) + ": " + detail;
    else detail = buf;
    AddCheck("VirtualBox files", "Files",
             found > 0 ? DETECTED : NOT_DETECTED, detail.c_str());
}

static void CheckVBoxDirectories()
{
    const wchar_t* dirs[] = {
        L"C:\\Program Files\\Oracle",
        L"C:\\Program Files\\Oracle\\VirtualBox Guest Additions",
    };
    int found = 0;
    std::string detail;
    for (int i = 0; i < _countof(dirs); i++) {
        DWORD attr = GetFileAttributesW(dirs[i]);
        if (attr != INVALID_FILE_ATTRIBUTES &&
            (attr & FILE_ATTRIBUTE_DIRECTORY)) {
            found++;
            if (!detail.empty()) detail += ", ";
            detail += WideToUtf8(dirs[i]);
        }
    }
    char buf[64];
    sprintf_s(buf, "%d of %d directories found", found, (int)_countof(dirs));
    if (found > 0) detail = std::string(buf) + ": " + detail;
    else detail = buf;
    AddCheck("VirtualBox directories", "Files",
             found > 0 ? DETECTED : NOT_DETECTED, detail.c_str());
}

/* ------------------------------------------------------------------ */
/*  VMware processes                                                   */
/* ------------------------------------------------------------------ */

static void CheckVmwareProcesses()
{
    const wchar_t* procNames[] = {
        L"vmtoolsd.exe", L"vmwaretray.exe", L"vmwareuser.exe",
        L"vmacthlp.exe", L"vmware-vmx.exe", L"VGAuthService.exe"
    };
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        AddCheck("VMware processes", "Processes", PROBE_ERROR,
                 "Could not create process snapshot");
        return;
    }
    int found = 0;
    std::string detail;
    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do {
            for (int i = 0; i < _countof(procNames); i++) {
                if (_wcsicmp(pe.szExeFile, procNames[i]) == 0) {
                    found++;
                    if (!detail.empty()) detail += ", ";
                    detail += WideToUtf8(procNames[i]);
                    break;
                }
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    if (found > 0) {
        char buf[32];
        sprintf_s(buf, "%d running: ", found);
        detail = std::string(buf) + detail;
    } else {
        detail = "none running";
    }
    AddCheck("VMware processes", "Processes",
             found > 0 ? DETECTED : NOT_DETECTED, detail.c_str());
}

static void CheckVBoxProcesses()
{
    const wchar_t* procNames[] = {
        L"VBoxService.exe", L"VBoxTray.exe", L"VBoxControl.exe",
        L"VirtualBox.exe", L"VirtualBoxVM.exe",
    };
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        AddCheck("VirtualBox processes", "Processes", PROBE_ERROR,
                 "Could not create process snapshot");
        return;
    }
    int found = 0;
    std::string detail;
    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do {
            for (int i = 0; i < _countof(procNames); i++) {
                if (_wcsicmp(pe.szExeFile, procNames[i]) == 0) {
                    found++;
                    if (!detail.empty()) detail += ", ";
                    detail += WideToUtf8(procNames[i]);
                    break;
                }
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    if (found > 0) {
        char buf[32];
        sprintf_s(buf, "%d running: ", found);
        detail = std::string(buf) + detail;
    } else {
        detail = "none running";
    }
    AddCheck("VirtualBox processes", "Processes",
             found > 0 ? DETECTED : NOT_DETECTED, detail.c_str());
}

/* ------------------------------------------------------------------ */
/*  MAC address OUI                                                    */
/* ------------------------------------------------------------------ */

static void CheckMacAddressOui()
{
    ULONG bufSize = 0;
    GetAdaptersAddresses(AF_UNSPEC, 0, NULL, NULL, &bufSize);
    if (bufSize == 0) {
        AddCheck("MAC address OUI", "Network", PROBE_ERROR, "No adapters");
        return;
    }
    std::vector<BYTE> raw(bufSize);
    PIP_ADAPTER_ADDRESSES addrs = (PIP_ADAPTER_ADDRESSES)raw.data();
    if (GetAdaptersAddresses(AF_UNSPEC, 0, NULL, addrs, &bufSize) != NO_ERROR) {
        AddCheck("MAC address OUI", "Network", PROBE_ERROR,
                 "GetAdaptersAddresses failed");
        return;
    }
    int found = 0;
    std::string detail;
    for (PIP_ADAPTER_ADDRESSES a = addrs; a; a = a->Next) {
        if (a->PhysicalAddressLength < 3) continue;
        BYTE* m = a->PhysicalAddress;
        bool isVmware = (m[0]==0x00 && m[1]==0x0C && m[2]==0x29) ||
                        (m[0]==0x00 && m[1]==0x50 && m[2]==0x56) ||
                        (m[0]==0x00 && m[1]==0x05 && m[2]==0x69) ||
                        (m[0]==0x00 && m[1]==0x1C && m[2]==0x14);
        bool isVBox = (m[0]==0x08 && m[1]==0x00 && m[2]==0x27);
        if (isVmware || isVBox) {
            found++;
            char ms[24];
            sprintf_s(ms, "%02X:%02X:%02X:%02X:%02X:%02X",
                      m[0],m[1],m[2],m[3],m[4],m[5]);
            if (!detail.empty()) detail += ", ";
            detail += ms;
        }
    }
    AddCheck("MAC address OUI (VM)", "Network",
             found > 0 ? DETECTED : NOT_DETECTED,
             found > 0 ? detail.c_str() : "no VMware/VirtualBox OUI found");
}

/* ------------------------------------------------------------------ */
/*  VMware Tools installed (registry)                                  */
/* ------------------------------------------------------------------ */

static void CheckVmwareToolsInstalled()
{
    std::string path = ReadRegString(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\VMware, Inc.\\VMware Tools", L"InstallPath");
    bool installed = path.find("(could not open") == std::string::npos &&
                     path.find("(value not found)") == std::string::npos;
    AddCheck("VMware Tools installed", "VMware",
             installed ? DETECTED : NOT_DETECTED, path.c_str());
}

static void CheckVBoxGuestAdditions()
{
    std::string path = ReadRegString(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Oracle\\VirtualBox Guest Additions", L"InstallDir");
    bool installed = path.find("(could not open") == std::string::npos &&
                     path.find("(value not found)") == std::string::npos;
    AddCheck("VBox Guest Additions", "VirtualBox",
             installed ? DETECTED : NOT_DETECTED, path.c_str());
}

/* ------------------------------------------------------------------ */
/*  Timing / sleep delta                                               */
/* ------------------------------------------------------------------ */

static void CheckTimingDelta()
{
    LARGE_INTEGER freq, t0, t1;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&t0);
    Sleep(500);
    QueryPerformanceCounter(&t1);

    double elapsedMs = (double)(t1.QuadPart - t0.QuadPart) /
                       (double)freq.QuadPart * 1000.0;
    double deviation = (elapsedMs - 500.0) / 500.0;

    char buf[128];
    sprintf_s(buf, "expected 500ms, measured %.1fms (deviation %.1f%%)",
              elapsedMs, deviation * 100.0);
    bool anomaly = (deviation > 0.5 || deviation < -0.5);
    AddCheck("Timing / sleep delta", "Timing",
             anomaly ? DETECTED : NOT_DETECTED, buf);
}

/* ------------------------------------------------------------------ */
/*  AvmKernel driver probe                                             */
/* ------------------------------------------------------------------ */

static void CheckKernelDriver()
{
    HANDLE hDev = CreateFileW(
        AVM_KERNEL_USER_PATH,
        GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);

    if (hDev == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        char buf[128];
        if (err == ERROR_FILE_NOT_FOUND || err == ERROR_PATH_NOT_FOUND)
            sprintf_s(buf, "device not present (error %lu) - driver not loaded",
                      err);
        else if (err == ERROR_ACCESS_DENIED)
            sprintf_s(buf, "access denied (error %lu) - run as administrator",
                      err);
        else
            sprintf_s(buf, "could not open device (error %lu)", err);
        AddCheck("AvmKernel driver", "Driver", NOT_DETECTED, buf);
        return;
    }

    AVM_STATUS_SNAPSHOT snap = {};
    DWORD returned = 0;
    if (DeviceIoControl(hDev, AVM_IOCTL_GET_STATUS,
                        NULL, 0, &snap, sizeof(snap), &returned, NULL)) {
        char buf[256];
        sprintf_s(buf,
            "mode=%lu checks=0x%08lX targets=%lu events=%lu "
            "nameRules=%lu fileRules=%lu",
            snap.Mode, snap.EnabledChecks, snap.TargetCount,
            snap.EventCount, snap.NameRuleCount, snap.FileRuleCount);
        AddCheck("AvmKernel driver", "Driver", DETECTED, buf);
    } else {
        DWORD err = GetLastError();
        char buf[128];
        sprintf_s(buf, "IOCTL_GET_STATUS failed (error %lu)", err);
        AddCheck("AvmKernel driver", "Driver", PROBE_ERROR, buf);
    }
    CloseHandle(hDev);
}

/* ------------------------------------------------------------------ */
/*  Minifilter probe                                                   */
/* ------------------------------------------------------------------ */

static void CheckMinifilterPathProbe()
{
    /*
     * Open a known VM artifact path.  If the minifilter is loaded and has
     * a hide rule for this path, the open will fail with
     * STATUS_OBJECT_NAME_NOT_FOUND even when the file exists on disk.
     * Compare the result against a plain GetFileAttributes to highlight
     * the discrepancy.
     */
    const wchar_t* probePath =
        L"C:\\Program Files\\VMware\\VMware Tools\\vmtoolsd.exe";

    DWORD attrResult  = GetFileAttributesW(probePath);
    bool  attrExists  = (attrResult != INVALID_FILE_ATTRIBUTES);

    HANDLE hFile = CreateFileW(probePath, GENERIC_READ, FILE_SHARE_READ,
                               NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL,
                               NULL);
    bool openOk = (hFile != INVALID_HANDLE_VALUE);
    DWORD openErr = openOk ? 0 : GetLastError();
    if (openOk) CloseHandle(hFile);

    char buf[256];
    if (attrExists && openOk) {
        sprintf_s(buf, "path exists and is accessible "
                       "(minifilter not hiding this path)");
        AddCheck("Minifilter path probe", "Minifilter", NOT_DETECTED, buf);
    } else if (attrExists && !openOk) {
        sprintf_s(buf, "path exists by attributes but CreateFile "
                       "returned error %lu - minifilter may be intervening",
                  openErr);
        AddCheck("Minifilter path probe", "Minifilter", DETECTED, buf);
    } else {
        sprintf_s(buf, "path not found (VMware Tools not installed, "
                       "or minifilter is hiding it)");
        AddCheck("Minifilter path probe", "Minifilter", NOT_DETECTED, buf);
    }
}

static void CheckMinifilterDirEnum()
{
    WIN32_FIND_DATAW fd;
    HANDLE hFind = FindFirstFileW(L"C:\\Program Files\\VMware\\*", &fd);
    if (hFind != INVALID_HANDLE_VALUE) {
        int count = 0;
        std::string entries;
        do {
            count++;
            if (!entries.empty()) entries += ", ";
            entries += WideToUtf8(fd.cFileName);
        } while (FindNextFileW(hFind, &fd));
        FindClose(hFind);

        char buf[64];
        sprintf_s(buf, "%d entries: ", count);
        std::string full = std::string(buf) + entries;
        AddCheck("Minifilter directory enum", "Minifilter", DETECTED,
                 full.c_str());
    } else {
        AddCheck("Minifilter directory enum", "Minifilter", NOT_DETECTED,
                 "VMware directory not found or empty "
                 "(minifilter may be filtering)");
    }
}

/* ------------------------------------------------------------------ */
/*  Analysis tool process detection                                    */
/* ------------------------------------------------------------------ */

static void CheckAnalysisToolProcesses()
{
    static const wchar_t* toolProcs[] = {
        /* Sysinternals */
        L"procmon.exe", L"procmon64.exe", L"procexp.exe", L"procexp64.exe",
        L"autoruns.exe", L"autoruns64.exe", L"tcpview.exe", L"tcpview64.exe",
        L"Sysmon.exe", L"Sysmon64.exe", L"handle.exe", L"handle64.exe",
        L"listdlls.exe", L"listdlls64.exe", L"vmmap.exe", L"vmmap64.exe",
        L"strings.exe", L"strings64.exe", L"accesschk.exe", L"accesschk64.exe",
        /* Network capture */
        L"wireshark.exe", L"dumpcap.exe", L"tshark.exe",
        L"fiddler.exe", L"NetworkMiner.exe", L"rawcap.exe",
        L"HttpAnalyzerStdV7.exe", L"SmartSniff.exe",
        /* Disassemblers / Decompilers */
        L"ida.exe", L"ida64.exe", L"idaq.exe", L"idaq64.exe",
        L"ghidra.exe", L"ghidraRun.exe", L"ghidraRun.bat",
        L"r2.exe", L"radare2.exe", L"cutter.exe", L"iaito.exe",
        L"binaryninja.exe", L"hopper.exe",
        /* Debuggers */
        L"x64dbg.exe", L"x32dbg.exe", L"ollydbg.exe",
        L"windbg.exe", L"kd.exe", L"cdb.exe", L"ntsd.exe",
        L"dnSpy.exe", L"dotPeek64.exe", L"ilspy.exe",
        /* PE analysis */
        L"pestudio.exe", L"die.exe", L"peid.exe",
        L"exeinfope.exe", L"CFF Explorer.exe",
        L"ResourceHacker.exe",
        /* API / behavior monitoring */
        L"apimonitor-x64.exe", L"apimonitor-x86.exe",
        L"regmon.exe", L"filemon.exe",
        /* Sandbox / forensic frameworks */
        L"volatility.exe", L"vol.exe",
        L"autopsy.exe", L"autopsy64.exe",
        L"FTK Imager.exe",
        L"HashCalc.exe", L"hashdeep.exe", L"md5deep.exe",
        /* Hex editors */
        L"HxD.exe", L"010Editor.exe", L"ImHex.exe",
        /* Misc */
        L"Regshot.exe", L"Regshot-x64-Unicode.exe",
        L"fakenet.exe", L"inetsim.exe",
        L"yara64.exe", L"yara32.exe",
    };
    int found = 0;
    std::string detail;

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pe;
        pe.dwSize = sizeof(pe);
        if (Process32FirstW(snap, &pe)) {
            do {
                for (int i = 0; i < _countof(toolProcs); i++) {
                    if (_wcsicmp(pe.szExeFile, toolProcs[i]) == 0) {
                        found++;
                        if (!detail.empty()) detail += ", ";
                        detail += WideToUtf8(pe.szExeFile);
                        break;
                    }
                }
            } while (Process32NextW(snap, &pe));
        }
        CloseHandle(snap);
    }
    AddCheck("Analysis tool processes", "AnalysisTools",
             found > 0 ? DETECTED : NOT_DETECTED,
             found > 0 ? (std::to_string(found) + " running: " + detail).c_str()
                       : "none detected");
}

/* ------------------------------------------------------------------ */
/*  User activity indicators                                           */
/* ------------------------------------------------------------------ */

static void CheckUserActivity()
{
    int emptyDirs = 0;
    int totalDirs = 0;
    std::string emptyNames;

    struct { const wchar_t* env; const wchar_t* sub; const char* label; } dirs[] = {
        { L"USERPROFILE", L"\\Documents", "Documents" },
        { L"USERPROFILE", L"\\Desktop",   "Desktop" },
        { L"USERPROFILE", L"\\Pictures",  "Pictures" },
        { L"USERPROFILE", L"\\Downloads", "Downloads" },
    };

    for (int i = 0; i < _countof(dirs); i++) {
        wchar_t base[MAX_PATH];
        DWORD len = GetEnvironmentVariableW(dirs[i].env, base, MAX_PATH);
        if (len == 0) continue;
        totalDirs++;
        wcscat_s(base, dirs[i].sub);

        WIN32_FIND_DATAW fd;
        wchar_t pat[MAX_PATH];
        wcscpy_s(pat, base);
        wcscat_s(pat, L"\\*");
        HANDLE h = FindFirstFileW(pat, &fd);
        if (h == INVALID_HANDLE_VALUE) { emptyDirs++; emptyNames += std::string(emptyNames.empty() ? "" : ", ") + dirs[i].label; continue; }

        int fileCount = 0;
        do {
            if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0) continue;
            fileCount++;
        } while (fileCount == 0 && FindNextFileW(h, &fd));
        FindClose(h);
        if (fileCount == 0) {
            emptyDirs++;
            if (!emptyNames.empty()) emptyNames += ", ";
            emptyNames += dirs[i].label;
        }
    }

    if (emptyDirs >= 3) {
        AddCheck("User activity indicators", "UserActivity", DETECTED,
                 ("most user dirs empty: " + emptyNames + " (suggests fresh VM)").c_str());
    } else if (emptyDirs > 0) {
        char buf[128];
        sprintf_s(buf, "%d of %d user dirs empty (%s)", emptyDirs, totalDirs, emptyNames.c_str());
        AddCheck("User activity indicators", "UserActivity", NOT_DETECTED, buf);
    } else {
        AddCheck("User activity indicators", "UserActivity", NOT_DETECTED,
                 "user directories contain files (normal activity)");
    }
}

/* ------------------------------------------------------------------ */
/*  WMI hardware identity (registry-based)                             */
/* ------------------------------------------------------------------ */

static void CheckWmiHardwareIdentity()
{
    /* Motherboard serial/product from SMBIOS registry */
    std::string bbProduct = ReadRegString(HKEY_LOCAL_MACHINE,
        L"HARDWARE\\DESCRIPTION\\System\\BIOS", L"BaseBoardProduct");
    std::string bbMfg = ReadRegString(HKEY_LOCAL_MACHINE,
        L"HARDWARE\\DESCRIPTION\\System\\BIOS", L"BaseBoardManufacturer");

    bool vmIndicator = false;
    std::string detail;

    if (bbMfg.find("VMware") != std::string::npos ||
        bbMfg.find("Intel Corporation") != std::string::npos && bbProduct.find("440BX") != std::string::npos) {
        vmIndicator = true;
        detail = "Manufacturer=" + bbMfg + ", Product=" + bbProduct;
    } else {
        detail = "Manufacturer=" + bbMfg + ", Product=" + bbProduct;
    }

    AddCheck("Hardware identity (baseboard)", "Hardware",
             vmIndicator ? DETECTED : NOT_DETECTED, detail.c_str());
}

/* ------------------------------------------------------------------ */
/*  BIOS serial number check                                           */
/* ------------------------------------------------------------------ */

static void CheckBiosSerial()
{
    /* BIOS serial from SMBIOS via registry */
    std::string biosSerial = ReadRegString(HKEY_LOCAL_MACHINE,
        L"HARDWARE\\DESCRIPTION\\System\\BIOS", L"BIOSReleaseDate");
    std::string sysSerial = ReadRegString(HKEY_LOCAL_MACHINE,
        L"HARDWARE\\DESCRIPTION\\System\\BIOS", L"SystemFamily");

    bool vmIndicator = false;
    std::string detail;

    if (biosSerial.find("VMware") != std::string::npos ||
        sysSerial.find("VMware") != std::string::npos ||
        sysSerial.find("Virtual") != std::string::npos) {
        vmIndicator = true;
    }
    detail = "BIOSReleaseDate=" + biosSerial + ", SystemFamily=" + sysSerial;

    AddCheck("BIOS serial / family", "Hardware",
             vmIndicator ? DETECTED : NOT_DETECTED, detail.c_str());
}

/* ------------------------------------------------------------------ */
/*  Runtime shim status                                                */
/* ------------------------------------------------------------------ */

static void CheckRuntimeShimStatus()
{
    /*
     * The runtime shim (AvmRuntimeShim.dll) is an injected DLL that hooks
     * APIs inside a target process.  From outside we cannot meaningfully
     * probe its hooks, so we report whether the DLL file exists on disk
     * next to the controller.
     */
    const wchar_t* shimPaths[] = {
        L"AvmRuntimeShim.dll",
        L"..\\runtime\\AvmRuntimeShim\\x64\\Release\\AvmRuntimeShim.dll",
        L"..\\runtime\\AvmRuntimeShim\\x64\\Debug\\AvmRuntimeShim.dll",
        L"..\\x64\\Release\\AvmRuntimeShim.dll",
        L"..\\x64\\Debug\\AvmRuntimeShim.dll"
    };
    bool found = false;
    std::string foundPath;
    for (int i = 0; i < _countof(shimPaths); i++) {
        if (GetFileAttributesW(shimPaths[i]) != INVALID_FILE_ATTRIBUTES) {
            found = true;
            foundPath = WideToUtf8(shimPaths[i]);
            break;
        }
    }
    if (found) {
        std::string detail = "DLL found at " + foundPath +
            " (injection must be observed from inside a target process)";
        AddCheck("Runtime shim DLL", "RuntimeShim", DETECTED, detail.c_str());
    } else {
        AddCheck("Runtime shim DLL", "RuntimeShim", NOT_DETECTED,
                 "AvmRuntimeShim.dll not found in expected locations; "
                 "hook interception cannot be tested externally");
    }
}

/* ------------------------------------------------------------------ */
/*  JSON export                                                        */
/* ------------------------------------------------------------------ */

static std::string JsonEscape(const std::string& s)
{
    std::string out;
    out.reserve(s.size() + 16);
    for (size_t i = 0; i < s.size(); i++) {
        char c = s[i];
        switch (c) {
        case '"':  out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\n': out += "\\n";  break;
        case '\r': out += "\\r";  break;
        case '\t': out += "\\t";  break;
        default:   out += c;      break;
        }
    }
    return out;
}

static bool ExportJson(const char* path)
{
    FILE* f = NULL;
    if (fopen_s(&f, path, "w") != 0 || !f) return false;

    int detected = 0, notDetected = 0, errors = 0;
    for (size_t i = 0; i < g_checks.size(); i++) {
        switch (g_checks[i].result) {
        case DETECTED:     detected++;    break;
        case NOT_DETECTED: notDetected++; break;
        case PROBE_ERROR:  errors++;      break;
        }
    }

    fprintf(f, "{\n  \"checks\": [\n");
    for (size_t i = 0; i < g_checks.size(); i++) {
        const ProbeCheck& c = g_checks[i];
        fprintf(f, "    {\n");
        fprintf(f, "      \"name\": \"%s\",\n",     JsonEscape(c.name).c_str());
        fprintf(f, "      \"category\": \"%s\",\n", JsonEscape(c.category).c_str());
        fprintf(f, "      \"result\": \"%s\",\n",   ResultLabel(c.result));
        fprintf(f, "      \"detail\": \"%s\"\n",     JsonEscape(c.detail).c_str());
        fprintf(f, "    }%s\n", (i + 1 < g_checks.size()) ? "," : "");
    }
    fprintf(f, "  ],\n");
    fprintf(f, "  \"summary\": {\n");
    fprintf(f, "    \"total\": %d,\n",        (int)g_checks.size());
    fprintf(f, "    \"detected\": %d,\n",     detected);
    fprintf(f, "    \"not_detected\": %d,\n", notDetected);
    fprintf(f, "    \"errors\": %d\n",        errors);
    fprintf(f, "  }\n");
    fprintf(f, "}\n");
    fclose(f);
    return true;
}

/* ------------------------------------------------------------------ */
/*  Console output                                                     */
/* ------------------------------------------------------------------ */

static void PrintResults()
{
    printf("\n");
    printf("========================================\n");
    printf("  AvmProbeTest - VM Indicator Report\n");
    printf("========================================\n");

    std::string lastCat;
    for (size_t i = 0; i < g_checks.size(); i++) {
        const ProbeCheck& c = g_checks[i];
        if (c.category != lastCat) {
            printf("\n[%s]\n", c.category.c_str());
            lastCat = c.category;
        }
        const char* tag;
        switch (c.result) {
        case DETECTED:     tag = "DETECTED    "; break;
        case NOT_DETECTED: tag = "NOT DETECTED"; break;
        case PROBE_ERROR:  tag = "ERROR       "; break;
        default:           tag = "UNKNOWN     "; break;
        }
        printf("  %-36s  %s\n", c.name.c_str(), tag);
        if (!c.detail.empty())
            printf("    -> %s\n", c.detail.c_str());
    }

    int detected = 0, notDetected = 0, errors = 0;
    for (size_t i = 0; i < g_checks.size(); i++) {
        switch (g_checks[i].result) {
        case DETECTED:     detected++;    break;
        case NOT_DETECTED: notDetected++; break;
        case PROBE_ERROR:  errors++;      break;
        }
    }
    printf("\n========================================\n");
    printf("  Summary: %d checks | %d detected | %d not detected | %d errors\n",
           (int)g_checks.size(), detected, notDetected, errors);
    printf("========================================\n");
}

/* ------------------------------------------------------------------ */
/*  Entry point                                                        */
/* ------------------------------------------------------------------ */

int main(int argc, char** argv)
{
    printf("AvmProbeTest v1.0 - Anti-VM-Awareness Countermeasure Validation\n");
    printf("Running VM indicator checks...\n");

    CheckCpuidHypervisorBit();
    CheckCpuidHypervisorVendor();
    CheckBiosVendor();
    CheckSystemManufacturer();
    CheckSystemProductName();
    CheckVmwareRegistryKeys();
    CheckVBoxRegistryKeys();
    CheckVmwareServices();
    CheckVBoxServices();
    CheckVmwareFiles();
    CheckVmwareDirectories();
    CheckVBoxFiles();
    CheckVBoxDirectories();
    CheckVmwareProcesses();
    CheckVBoxProcesses();
    CheckMacAddressOui();
    CheckVmwareToolsInstalled();
    CheckVBoxGuestAdditions();
    CheckTimingDelta();
    CheckAnalysisToolProcesses();
    CheckUserActivity();
    CheckWmiHardwareIdentity();
    CheckBiosSerial();
    CheckKernelDriver();
    CheckMinifilterPathProbe();
    CheckMinifilterDirEnum();
    CheckRuntimeShimStatus();

    PrintResults();

    const char* jsonPath = NULL;
    for (int i = 1; i < argc; i++) {
        jsonPath = argv[i];
    }
    if (jsonPath) {
        if (ExportJson(jsonPath)) {
            printf("\nJSON exported to: %s\n", jsonPath);
        } else {
            fprintf(stderr, "\nFailed to export JSON to: %s\n", jsonPath);
            return 1;
        }
    }

    return 0;
}
