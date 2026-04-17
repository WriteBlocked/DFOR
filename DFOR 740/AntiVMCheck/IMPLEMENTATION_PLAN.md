# Anti-VM-Awareness Countermeasure Platform Implementation Plan

## Architecture

The MVP will use four cooperating binaries:

1. **AvmKernel**: KMDF driver that owns policy state, target registration, kernel telemetry, and IOCTL control.
2. **AvmMiniFilter**: file-system minifilter that hides or redirects VM and sandbox artifacts and filters directory enumeration output.
3. **AvmRuntimeShim**: injected helper DLL that hooks selected Win32 and native APIs inside target processes to provide debugger concealment, timing normalization, native API filtering, process/tool hiding, and registry/file spoofing.
4. **AvmController**: graphical user-mode controller that manages drivers, target registration, mode selection, per-check policy toggles, telemetry viewing, and log export.

The drivers satisfy the mandatory kernel and minifilter deliverables. The runtime shim is an internal helper used to broaden behavior coverage without unsafe kernel patching.

## Communication Model

- **Controller ↔ KMDF driver**: IOCTL device interface for initialize, policy upload, target registration, telemetry polling, and runtime-shim event submission.
- **Controller ↔ Minifilter**: Filter Manager communication port for policy/rule upload and file-event polling.
- **Runtime shim ↔ KMDF driver**: IOCTL device interface for policy snapshot reads and telemetry submission from hooked APIs.

## Phases

### Phase 1: Shared contracts and project structure
- Create solution layout, shared include/contracts, common enums, and event/policy structures.
- Add build scripts and placeholder INF/project files needed by Visual Studio + WDK builds.

### Phase 2: Kernel driver
- Control device and IOCTL dispatch.
- Policy storage: operating mode, per-check flags, hidden process/tool names, suspicious registry prefixes, hidden device names.
- Target matching by PID, image name, or image path prefix.
- Telemetry ring buffer with batched fetch.
- Kernel callbacks:
  - process create/exit tracking
  - image load tracking
  - object-handle monitoring for process/thread probing
  - registry callbacks for VM artifact key opens/queries
- Countermeasure coverage:
  - observe-only mode
  - selective concealment based on enabled flags
  - full concealment using expanded default deny/hide lists

### Phase 3: Minifilter
- Communication port and shared policy cache.
- Pre-create path checks for VM/sandbox artifacts.
- Actions:
  - return not found
  - redirect to benign file via file-name replacement
  - remove suspicious names from directory listings in post-directory-control
- File-system telemetry queue for GUI polling.

### Phase 4: Runtime shim
- Injected x64 DLL with hook set for:
  - `IsDebuggerPresent`
  - `CheckRemoteDebuggerPresent`
  - `NtQueryInformationProcess`
  - `NtSetInformationThread`
  - `QueryPerformanceCounter`
  - `GetTickCount64`
  - `NtDelayExecution`
  - `NtQuerySystemInformation`
  - `RegOpenKeyExW` / `NtOpenKey`
  - `RegQueryValueExW` / `NtQueryValueKey`
  - `CreateFileW` / `NtCreateFile`
  - `FindFirstFileExW` / `FindNextFileW`
- Each hook will log telemetry and apply spoof/hide/redirect behavior from the kernel policy snapshot.

### Phase 5: GUI controller
- Native Windows GUI with:
  - driver status pane
  - target registration controls
  - per-check toggle list
  - mode selector
  - telemetry/event table
  - policy/rule editor for hidden files and redirect pairs
  - JSON/CSV export
- Driver and minifilter communication clients.
- Runtime-shim injection for launched or existing target processes.

### Phase 6: Integration
- Shared defaults and policy serialization across all components.
- Poll-and-display telemetry from both drivers.
- Confirm GUI toggles change kernel and minifilter behavior.
- Demonstrate several behaviors together: debugger concealment, process/tool hiding, timing normalization, and VM artifact hiding.

### Phase 7: Validation and documentation
- Provide build steps and standard Visual Studio/WDK solution files.
- Add README with architecture, build/load instructions, GUI usage, example scenarios, and known limitations.

## Objective Coverage Map

| Objective | Planned coverage |
| --- | --- |
| Target process tracking | Kernel target table + GUI registration by PID/name/path |
| Debugger checks | Runtime shim hooks + kernel telemetry + selectable spoofing |
| Timing checks | Runtime shim timing hooks + normalization policy |
| Native API usage | Runtime shim `ntdll` hooks + kernel event ingestion |
| Process/module/tool enumeration | `NtQuerySystemInformation` filtering + kernel image/handle callbacks |
| Driver/device probing | Kernel registry/device-name policy + hooked file/device opens |
| File artifact hiding | Minifilter hide/redirect + shim file-open redirection |
| Directory listing filtering | Minifilter post-enumeration scrub + shim Win32 find filtering |
| Telemetry | Shared event structures, batched polling, GUI event viewer, export |
| Multiple modes | Observe / selective concealment / full concealment in shared policy |
| Per-check enable/disable | Bitmask-based policy toggles exposed in GUI |
| Safe fallback | Default observe mode when controller is absent or policy invalid |

## Deliverables

- Visual Studio solution with separate KMDF, minifilter, runtime shim, and controller projects
- Shared headers/contracts
- Build scripts
- README
