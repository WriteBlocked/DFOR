# Anti-VM-Awareness Countermeasure Platform

This repository contains a broad MVP for defensive sandbox research. It combines:

1. **AvmKernel**: a KMDF control driver that tracks target processes, stores policy, emits kernel telemetry, and applies safe callback-based concealment.
2. **AvmMiniFilter**: a file-system minifilter that hides or redirects VM and sandbox artifacts and filters directory enumeration results.
3. **AvmRuntimeShim**: an injected helper DLL that hooks selected Win32 and native APIs inside target processes for debugger concealment, timing normalization, process/tool hiding, and registry/file filtering.
4. **AvmController**: a WPF GUI that manages policy, targets, driver status, telemetry, shim injection, and log export.

## Architecture

### KMDF driver

- Non-PnP control device exposed as `\\.\AvmKernel`
- IOCTLs for:
  - policy upload
  - target registration
  - file-rule registration
  - status retrieval
  - batched telemetry fetch
  - runtime-shim event ingestion
- Coverage:
  - target process tracking
  - process create/exit logging
  - suspicious module load logging
  - handle-open monitoring for analysis-tool probing
  - registry artifact open/create blocking
  - shared observe/selective/full modes

### Minifilter

- Filter Manager communication port: `\AvmMiniFilterPort`
- Coverage:
  - pre-create path checks
  - hide-on-open by returning `STATUS_OBJECT_NAME_NOT_FOUND`
  - redirect-on-open by replacing the file object name
  - directory listing filtering in post-directory-control
  - batched telemetry for file probes and directory scrubbing

### Runtime shim

- Injected into target processes by the controller
- Uses IAT patching and `GetProcAddress` interception to cover:
  - `IsDebuggerPresent`
  - `CheckRemoteDebuggerPresent`
  - `NtQueryInformationProcess`
  - `NtSetInformationThread`
  - `QueryPerformanceCounter`
  - `GetTickCount64`
  - `NtDelayExecution`
  - `NtQuerySystemInformation`
  - `RegOpenKeyExW`
  - `RegQueryValueExW`
  - `CreateFileW`
  - `FindFirstFileExW`
  - `FindNextFileW`

### GUI controller

- Driver status view
- Target registration by PID, image name, or path prefix
- Per-check enable/disable toggles
- Observe / selective concealment / full concealment modes
- File rule editor for hide and redirect rules
- Telemetry viewer
- JSON/CSV export
- Runtime shim injection into existing target processes

## Repository Layout

| Path | Purpose |
| --- | --- |
| `shared\avm_shared.h` | Shared kernel/user contracts |
| `kernel\AvmKernel` | KMDF driver source and INF |
| `minifilter\AvmMiniFilter` | Minifilter source and INF |
| `runtime\AvmRuntimeShim` | Injected helper DLL |
| `controller\AvmController` | WPF GUI controller |
| `probe\AvmProbeTest` | VM indicator validation probe |
| `AntiVmCountermeasure.sln` | Visual Studio solution |
| `build.ps1` | Build entry point |

## Build Steps

### Requirements

**To build** (on the development machine):
- Visual Studio 2022 or Build Tools with C++ desktop tools
- Windows Driver Kit (WDK) for KMDF + minifilter builds
- .NET Framework 4.8 developer pack
- Administrator PowerShell

**To install only** (on the target VM — no VS or WDK needed):
- The pre-built files copied to a folder (see Deploy to VM below)
- Administrator PowerShell
- Test signing enabled (`bcdedit /set testsigning on` + reboot)
- Secure Boot disabled, Memory Integrity / HVCI disabled

### Quick Start

```powershell
# --- On the BUILD machine (has VS + WDK) ---

# Build and sign
.\build.ps1

# Build, sign, AND install locally
.\build.ps1 -Install

# --- On the TARGET VM (no VS/WDK needed) ---

# Install pre-built drivers (auto-detects no build tools, skips build)
.\build.ps1 -Install
```

### Deploy to VM

After building on the dev machine, copy these files to a single folder on the VM:

| File | Source Path |
| --- | --- |
| `AvmKernel.sys` | `x64\Release\` |
| `AvmMiniFilter.sys` | `x64\Release\` |
| `HillerTestDriver.cer` | project root |
| `AvmController.exe` | `controller\AvmController\bin\Release\` |
| `AvmProbeTest.exe` | `x64\Release\` |
| `build.ps1` | project root |

Then on the VM, open an **Administrator PowerShell** in that folder and run:

```powershell
.\build.ps1 -Install
```

The script auto-detects that Visual Studio is not installed and skips
the build/sign steps, using the pre-signed files directly.

### What build.ps1 Does

**Build mode** (VS + WDK present):
1. Finds MSBuild and verifies WDK is available
2. Builds all 5 projects
3. Creates/reuses a self-signed code-signing certificate
4. Signs both `.sys` driver files
5. With `-Install`: also imports cert, creates services, sets registry keys, starts drivers

**Install-only mode** (no VS/WDK — target VM):
1. Verifies `.sys` files and `.cer` exist in the script directory
2. Checks test signing is enabled
3. Imports the certificate into Root and TrustedPublisher stores
4. Creates and starts the kernel driver service
5. Creates minifilter service with correct Filter Manager registry keys
6. Launches the controller GUI

### Manual Build

Or open `AntiVmCountermeasure.sln` in Visual Studio and build **Release | x64**.

## Documentation

| Document | Description |
| --- | --- |
| [HOW_IT_WORKS.md](HOW_IT_WORKS.md) | Complete architecture explanation (high and low level), demo instructions |
| [CONTROLLER_GUIDE.md](CONTROLLER_GUIDE.md) | How to use the controller GUI |
| [PROJECT_SPEC.md](PROJECT_SPEC.md) | Original project specification |
| [IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md) | Implementation plan and phases |

## Driver Loading

Build output provides:

- `AvmKernel.sys`
- `AvmMiniFilter.sys`
- `AvmRuntimeShim.dll`
- `AvmController.exe`
- `AvmProbeTest.exe`

### Automated (Recommended)

```powershell
# On the target VM with VS + WDK installed:
.\build.ps1 -Install
```

### Manual Setup

If you built on a different machine and copied files to the VM:

```powershell
# 1. Enable test signing (reboot required)
bcdedit /set testsigning on

# 2. Import the certificate
Import-Certificate -FilePath .\HillerTestDriver.cer -CertStoreLocation Cert:\LocalMachine\Root
Import-Certificate -FilePath .\HillerTestDriver.cer -CertStoreLocation Cert:\LocalMachine\TrustedPublisher

# 3. Install kernel driver
Copy-Item .\AvmKernel.sys C:\Windows\System32\drivers\ -Force
sc.exe create AvmKernel type= kernel start= demand binPath= system32\drivers\AvmKernel.sys
sc.exe start AvmKernel

# 4. Install minifilter
Copy-Item .\AvmMiniFilter.sys C:\Windows\System32\drivers\ -Force
sc.exe create AvmMiniFilter type= filesys start= demand binPath= system32\drivers\AvmMiniFilter.sys group= "FSFilter Activity Monitor" depend= FltMgr

# 5. Set minifilter instance registry keys
# For Windows 10/11 pre-24H2:
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AvmMiniFilter\Instances" /v DefaultInstance /t REG_SZ /d "AvmMiniFilter Instance" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AvmMiniFilter\Instances\AvmMiniFilter Instance" /v Altitude /t REG_SZ /d "328766" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AvmMiniFilter\Instances\AvmMiniFilter Instance" /v Flags /t REG_DWORD /d 0 /f

# For Windows 11 24H2+, use Parameters\Instances instead of Instances

# 6. Start minifilter
sc.exe start AvmMiniFilter
fltmc filters  # verify AvmMiniFilter appears

# 7. Launch controller
.\AvmController.exe
```

## Usage

1. Start the controller.
2. Add one or more targets by PID, image name, or path prefix.
3. Select the operating mode.
4. Toggle countermeasure categories individually.
5. Add hide or redirect file rules for VM or sandbox artifacts.
6. Apply policy.
7. Inject the runtime shim into the target process.
8. Watch telemetry from the kernel driver, minifilter, and runtime shim in the grid.
9. Export logs to JSON or CSV.

## Example Scenarios

### Debugger concealment

- Enable **Debugger concealment**
- Inject the runtime shim into the target
- Calls to `IsDebuggerPresent`, `CheckRemoteDebuggerPresent`, and `NtQueryInformationProcess` are logged and spoofed in concealment modes

### File artifact hiding

- Add a hide rule for a suspicious path such as a VirtualBox or VMware artifact
- Apply policy
- The minifilter returns not found on create/open and logs the event

### Directory filtering

- Enable **Directory listing filtering**
- Add hide rules that identify suspicious artifact names
- Directory enumeration results have matching entries removed

### Process/tool hiding

- Enable **Process/tool concealment**
- The runtime shim filters `NtQuerySystemInformation(SystemProcessInformation)`
- The KMDF driver logs and can reduce handle access when a target probes hidden analysis tools

## Limitations

- The MVP avoids kernel patching and SSDT hooks by design; direct-syscall and kernel-resident malware are out of scope.
- The runtime shim relies on IAT and `GetProcAddress` interception, so pre-resolved function pointers and custom syscall stubs are not fully covered.
- The minifilter directory scrubber currently focuses on common directory information classes.
- Driver signing, INF packaging, and deployment are left in developer/test mode rather than production hardening.
- The local environment used to generate this source tree did not expose MSBuild, the .NET SDK, or the WDK on PATH, so the included solution and build script are ready for a proper Windows driver toolchain but could not be built in-place here.

## AvmProbeTest — Validation Probe

`AvmProbeTest` is a lightweight console executable that checks whether common VM indicators are visible on the current machine and probes the AvmKernel driver, minifilter, and runtime shim.

### Building

`AvmProbeTest` is part of the solution and builds with everything else:

```powershell
.\build.ps1 -Configuration Release -Platform x64
```

Or build the **AvmProbeTest** project individually in Visual Studio (Release | x64).  
The output is `probe\AvmProbeTest\x64\Release\AvmProbeTest.exe`.

### Running

```powershell
# Basic run — prints results to the console
.\AvmProbeTest.exe

# Export results to JSON
.\AvmProbeTest.exe results.json
```

Run as **Administrator** for full coverage — some checks (SCM service enumeration, kernel driver IOCTL) require elevation.

### Checks Performed

| # | Check | Category | What it means |
|---|-------|----------|---------------|
| 1 | **CPUID hypervisor bit** | CPUID | Leaf 1 ECX bit 31 — set by any hypervisor that advertises itself. |
| 2 | **CPUID hypervisor vendor** | CPUID | Leaf 0x40000000 — returns "VMwareVMware", "Microsoft Hv", etc. |
| 3 | **BIOS vendor** | BIOS/Registry | `HKLM\HARDWARE\DESCRIPTION\System\BIOS\BIOSVendor` — matches VM vendors. |
| 4 | **System manufacturer** | BIOS/Registry | `SystemManufacturer` — "VMware, Inc.", "Microsoft Corporation", etc. |
| 5 | **System product name** | BIOS/Registry | `SystemProductName` — "VMware Virtual Platform", "Virtual Machine", etc. |
| 6 | **VMware registry keys** | Registry | Checks for VMware Tools, VGAuth, vmci, vmhgfs, vmmouse, VMTools service keys. |
| 7 | **VMware services/drivers** | Services | Queries the SCM for vmci, vmhgfs, vmmouse, vmx\_svga, vmxnet, VMTools, etc. |
| 8 | **VMware files** | Files | Looks for vmci.sys, vmhgfs.sys, vmtoolsd.exe, etc. on disk. |
| 9 | **VMware directories** | Files | Checks for `C:\Program Files\VMware` and sub-directories. |
| 10 | **VMware processes** | Processes | Enumerates running processes for vmtoolsd.exe, vmwaretray.exe, etc. |
| 11 | **MAC address OUI** | Network | Scans adapters for VMware OUIs (00:0C:29, 00:50:56, 00:05:69). |
| 12 | **VMware Tools installed** | VMware | Registry `InstallPath` under `VMware, Inc.\VMware Tools`. |
| 13 | **Timing / sleep delta** | Timing | Sleeps 500 ms and measures actual elapsed time via QPC; flags deviation > 50%. |
| 14 | **AvmKernel driver** | Driver | Opens `\\.\AvmKernel` and issues `IOCTL_GET_STATUS` to read the status snapshot. |
| 15 | **Minifilter path probe** | Minifilter | Opens a known VM artifact path; if the minifilter is hiding it the open will fail even though the file exists. |
| 16 | **Minifilter directory enum** | Minifilter | Enumerates `C:\Program Files\VMware\*`; the minifilter's directory filter may remove entries. |
| 17 | **Runtime shim DLL** | RuntimeShim | Checks whether `AvmRuntimeShim.dll` exists in expected locations. Shim hooks can only be observed from inside an injected target process. |

### Using AvmProbeTest to Validate Platform Components

**Kernel driver (`AvmKernel`)**  
Load the driver, then run `AvmProbeTest`. Check #14 should report `DETECTED` with the current policy snapshot. If the driver is not loaded it reports `NOT DETECTED`.

**Minifilter (`AvmMiniFilter`)**  
Load the minifilter and add a hide rule for a VM artifact path (e.g., `C:\Program Files\VMware\VMware Tools\vmtoolsd.exe`). Run `AvmProbeTest` — check #15 should show that CreateFile was blocked while GetFileAttributes still sees the file (indicating minifilter intervention). Check #16 should show fewer directory entries if the filter is removing them.

**Controller (`AvmController`)**  
Use the controller GUI to configure policy, add targets, and toggle countermeasures. Re-run `AvmProbeTest` to verify that the kernel driver status snapshot (check #14) reflects the policy you configured.

**Runtime shim (`AvmRuntimeShim`)**  
The shim hooks APIs inside the injected target process; `AvmProbeTest` cannot directly observe those hooks from outside. Check #17 reports whether the DLL file exists. To validate shim behavior, inject it into a target process and observe telemetry through the controller or the kernel driver's event queue.
