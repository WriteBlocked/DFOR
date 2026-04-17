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
| `AntiVmCountermeasure.sln` | Visual Studio solution |
| `build.ps1` | Build entry point |

## Build Steps

### Requirements

- Visual Studio 2022 or Build Tools
- Windows Driver Kit (WDK) for KMDF + minifilter builds
- .NET Framework 4.8 developer pack / desktop build tools

### Build

```powershell
.\build.ps1 -Configuration Release -Platform x64
```

Or open `AntiVmCountermeasure.sln` in Visual Studio and build **Release | x64**.

## Driver Loading

Build output should provide:

- `AvmKernel.sys`
- `AvmKernel.inf`
- `AvmMiniFilter.sys`
- `AvmMiniFilter.inf`
- `AvmRuntimeShim.dll`
- `AvmController.exe`

Typical test-signing/dev flow:

1. Enable test signing on the analysis VM.
2. Install `AvmKernel.inf`.
3. Install `AvmMiniFilter.inf`.
4. Start the minifilter instance with Filter Manager if it is not started automatically.
5. Place `AvmRuntimeShim.dll` next to `AvmController.exe`.
6. Launch `AvmController.exe` as administrator.

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
