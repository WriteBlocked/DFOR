# Anti-VM-Awareness Countermeasure Platform — How It Works

This document explains the Anti-VM-Awareness Countermeasure Platform at both a high level and a low level. It is intended for classroom presentation, peer review, and anyone who clones the repository and wants to understand the system before running it.

---

## Table of Contents

1. [What This Project Does](#1-what-this-project-does)
2. [High-Level Architecture](#2-high-level-architecture)
3. [Component Summary](#3-component-summary)
4. [Low-Level Technical Details](#4-low-level-technical-details)
5. [Communication Flow](#5-communication-flow)
6. [What Gets Hidden and How](#6-what-gets-hidden-and-how)
7. [Operating Modes](#7-operating-modes)
8. [Demo Instructions](#8-demo-instructions)
9. [Validating with AvmProbeTest](#9-validating-with-avmprobetest)
10. [Limitations and Scope](#10-limitations-and-scope)
11. [Glossary](#11-glossary)

---

## 1. What This Project Does

Modern malware frequently checks whether it is running inside a virtual machine (VM) or sandbox. If it detects a VM, it may refuse to execute, behave differently, or exit immediately. This makes analysis harder for researchers and forensic investigators.

This platform **intercepts and conceals** the indicators that malware uses to detect VMs. It operates at multiple levels of the Windows operating system:

- **Kernel level**: A kernel driver intercepts registry key access to VM-related entries.
- **File system level**: A minifilter driver hides VM-related files and removes them from directory listings.
- **User level**: A runtime shim DLL can be injected into target processes to intercept API calls that reveal VM status.
- **Control level**: A WPF GUI application manages everything — policy, targets, rules, and telemetry.

The result: a process running inside a VMware VM can be made to believe it is running on bare metal.

---

## 2. High-Level Architecture

```
┌─────────────────────────────────────────┐
│         AvmController (WPF GUI)         │
│  - Policy configuration                │
│  - Target process selection             │
│  - File rule management                 │
│  - Real-time telemetry viewer           │
│  - Log export (JSON/CSV)               │
└────────┬──────────────────┬─────────────┘
         │ DeviceIoControl  │ FilterSendMessage
         │ (IOCTLs)         │ (Filter Manager port)
         ▼                  ▼
┌─────────────────┐  ┌──────────────────────┐
│   AvmKernel     │  │   AvmMiniFilter      │
│   (Kernel       │  │   (File System        │
│    Driver)      │  │    Minifilter)        │
│                 │  │                      │
│ • Policy store  │  │ • PreCreate callback │
│ • Registry      │  │   (hide files)       │
│   callback      │  │ • PostDirControl     │
│   (CmRegister)  │  │   (filter listings)  │
│ • Target        │  │ • Comm port for      │
│   tracking      │  │   policy updates     │
│ • Telemetry     │  │ • Telemetry batch    │
│   batch queue   │  │   queue              │
└─────────────────┘  └──────────────────────┘

         ┌──────────────────────┐
         │  AvmRuntimeShim.dll  │
         │  (Injected DLL)      │
         │                      │
         │ • IAT hook patching  │
         │ • API interception   │
         │ • Reports events     │
         │   back to kernel     │
         └──────────────────────┘
```

### Data Flow Summary

1. The **controller** sends policy, targets, and file rules to both drivers.
2. The **kernel driver** blocks registry key access to VM-related keys (VMware, Inc., vmci, VMTools, etc.).
3. The **minifilter** intercepts file open operations and directory listings, hiding VMware artifacts.
4. The **runtime shim** hooks user-mode APIs inside a specific target process to spoof debugger checks, timing, and process enumeration.
5. All components report telemetry events back to the controller for display.

---

## 3. Component Summary

### AvmKernel (Kernel Driver)

| Aspect | Detail |
|--------|--------|
| Type | WDM kernel-mode driver (non-PnP) |
| Device path | `\\.\AvmKernel` |
| Communication | IOCTLs via `DeviceIoControl` |
| Primary function | Registry callback interception, policy storage, telemetry |
| Key file | `kernel\AvmKernel\driver.c` |

### AvmMiniFilter (File System Minifilter)

| Aspect | Detail |
|--------|--------|
| Type | Windows Filter Manager minifilter |
| Communication port | `\AvmMiniFilterPort` |
| Altitude | 328766 (FSFilter Activity Monitor) |
| Primary function | Hide files on open, filter directory listings |
| Key file | `minifilter\AvmMiniFilter\filter.c` |

### AvmRuntimeShim (Runtime Shim DLL)

| Aspect | Detail |
|--------|--------|
| Type | x64 DLL injected into target processes |
| Technique | IAT patching + `GetProcAddress` interception |
| Primary function | Spoof API results (debugger, timing, process list, registry, files) |
| Key file | `runtime\AvmRuntimeShim\shim.c` |

### AvmController (GUI Controller)

| Aspect | Detail |
|--------|--------|
| Type | WPF desktop application (.NET Framework 4.8) |
| Language | C# |
| Primary function | Configuration UI, telemetry viewer, log export |
| Key files | `controller\AvmController\MainWindow.xaml`, `MainWindow.xaml.cs`, `DriverClients.cs` |

### AvmProbeTest (Validation Probe)

| Aspect | Detail |
|--------|--------|
| Type | Console executable (C++) |
| Primary function | Enumerate VM indicators and report what is visible vs. hidden |
| Key file | `probe\AvmProbeTest\main.cpp` |

---

## 4. Low-Level Technical Details

### 4.1 Kernel Driver — Registry Callback

The kernel driver uses `CmRegisterCallbackEx` to register a callback at altitude `42000`. This callback is invoked by Windows every time any process attempts to open, create, or query a registry key or value.

**Key Blocking (Pre-operation):**

1. Windows calls `AvmRegistryCallback` with a `REG_NOTIFY_CLASS` indicating the operation type.
2. For `RegNtPreCreateKeyEx` and `RegNtPreOpenKeyEx`, the callback extracts the **leaf component** of the registry key path.
3. It compares this leaf against a hardcoded list of 16 VMware-related key names:
   - `VMware, Inc.`, `VMware Tools`, `VMware VGAuth`
   - `vmci`, `vmhgfs`, `vmmouse`, `VMTools`, `vmvss`
   - `vm3dmp`, `vmrawdsk`, `vmusbmouse`, `VGAuth`
   - `vm3dmp-debug`, `vm3dmp-stats`, `vm3dmp_loader`, `vmxnet3`
4. If a match is found:
   - In **Observe** mode: logs the access attempt but allows it
   - In **Selective** mode: blocks access only for targeted PIDs
   - In **Full** mode: blocks access for all user-mode processes (PID > 4)
5. Blocking is done by returning `STATUS_OBJECT_NAME_NOT_FOUND` from the callback, which makes Windows report that the key does not exist.

**Value Spoofing (Post-operation):**

1. For `RegNtPostQueryValueKey`, the callback runs *after* the value has been read.
2. It uses `CmCallbackGetKeyObjectIDEx` to resolve the full registry key path.
3. It checks whether the key path ends with `\BIOS` or `\SystemInformation`.
4. If a match is found, it compares the value name against a spoof table:

   | Value Name | Original (VMware) | Spoofed |
   |---|---|---|
   | BIOSVendor | Phoenix Technologies LTD / VMware | Dell Inc. |
   | SystemManufacturer | VMware, Inc. | Dell Inc. |
   | SystemProductName | VMware20,1 | OptiPlex 7090 |
   | BIOSVersion | INTEL - ... VMW... | 2.18.0 |
   | BaseBoardManufacturer | Intel Corp / VMware | Dell Inc. |
   | BaseBoardProduct | 440BX Desktop ... | 0XHGX6 |

5. The spoofed value is written directly into the caller's output buffer (in-place overwrite).
6. This works because post-callbacks run in the same thread context as the caller, with the output buffer still mapped.

**Key code location:** `kernel\AvmKernel\driver.c`

### 4.2 Minifilter — File Hiding (PreCreate)

The minifilter registers a `PreCreate` callback that runs before any file open/create operation completes.

**How it works:**

1. When a process calls `CreateFile` (or equivalent), the minifilter's `AvmPreCreate` is invoked.
2. It calls `FltGetFileNameInformation` to get the normalized file path.
3. It compares the path against:
   - **User-configured file rules** (sent from the controller)
   - **Built-in default paths** (10 hardcoded VMware artifact paths)
4. Path matching uses **suffix comparison**: the drive letter is stripped from the rule path, then the remainder is compared against the end of the normalized name. This handles volume device prefixes like `\Device\HarddiskVolume3`.
5. If matched, the minifilter:
   - Sets `Data->IoStatus.Status = STATUS_OBJECT_NAME_NOT_FOUND`
   - Returns `FLT_PREOP_COMPLETE` (short-circuits the I/O, file system never sees the request)
   - Logs a telemetry event

**Result:** The calling process gets `ERROR_FILE_NOT_FOUND` as if the file does not exist.

**Key code location:** `minifilter\AvmMiniFilter\filter.c`, lines 328–387

### 4.3 Minifilter — Directory Filtering (PostDirControl)

The minifilter registers a `PostDirControl` callback that runs after a directory listing has been filled by the file system.

**How it works:**

1. When a process calls `FindFirstFile`/`FindNextFile` or `NtQueryDirectoryFile`, Windows fills a buffer with directory entries.
2. After the file system populates the buffer, `AvmPostDirControl` inspects each entry.
3. It supports 6 directory information classes:
   - `FileDirectoryInformation`
   - `FileBothDirectoryInformation`
   - `FileFullDirectoryInformation`
   - `FileIdBothDirectoryInformation`
   - `FileIdFullDirectoryInformation`
   - `FileNamesInformation`
4. For each entry, it extracts the file name and checks it against rules using `AvmShouldHideEntry_Locked`, which:
   - Extracts the file-name component from each rule path
   - Compares it to the directory entry name (case-insensitive)
   - Verifies the parent directory matches the rule's parent path
5. To remove an entry from the linked list:
   - **First entry**: shifts the entire buffer forward
   - **Middle entry**: bridges the `NextEntryOffset` to skip the hidden entry
   - **Last entry**: sets the previous entry's `NextEntryOffset` to 0
   - **All entries hidden**: returns `STATUS_NO_MORE_FILES`

**Result:** The calling process never sees the hidden file/directory names in enumeration results.

**Key code location:** `minifilter\AvmMiniFilter\filter.c`, lines 407–556

### 4.4 IOCTL Communication

The kernel driver exposes a device object at `\\.\AvmKernel`. The controller opens this with `CreateFile` and uses `DeviceIoControl` to send structured commands.

| IOCTL Code | Function | Direction |
|------------|----------|-----------|
| `0x801` | SET_POLICY | Controller → Driver |
| `0x802` | GET_STATUS | Driver → Controller |
| `0x803` | CLEAR_TARGETS | Controller → Driver |
| `0x804` | ADD_TARGET | Controller → Driver |
| `0x805` | CLEAR_NAME_RULES | Controller → Driver |
| `0x806` | ADD_NAME_RULE | Controller → Driver |
| `0x807` | FETCH_EVENTS | Driver → Controller |
| `0x808` | SUBMIT_RUNTIME_EVENT | Shim → Driver |
| `0x809` | HEARTBEAT | Bidirectional |
| `0x80A` | CLEAR_FILE_RULES | Controller → Driver |
| `0x80B` | ADD_FILE_RULE | Controller → Driver |
| `0x80C` | GET_POLICY | Driver → Controller |
| `0x80D` | LOAD_DEFAULTS | Controller → Driver |

All IOCTLs use `METHOD_BUFFERED` — Windows copies the input/output buffer to/from kernel space automatically.

### 4.5 Minifilter Communication Port

The minifilter creates a Filter Manager communication port at `\AvmMiniFilterPort`. The controller connects using `FilterConnectCommunicationPort` and sends messages using `FilterSendMessage`.

Messages use a header-based protocol:

| Message ID | Function |
|------------|----------|
| 1 | SET_POLICY (includes policy, targets, and file rules in one message) |
| 2 | FETCH_EVENTS |
| 3 | GET_STATUS |

The SET_POLICY message is a single large binary payload (~67 KB) containing:
- Message header (8 bytes)
- Policy structure (32 bytes)
- Target count + 64 target entries
- File rule count + 32 file rules

### 4.6 Shared Data Structures

All components share the same data structures defined in `shared\avm_shared.h`:

- **AVM_POLICY** (32 bytes): Version, mode, enabled checks, concealment mask
- **AVM_TARGET_ENTRY** (528 bytes): Target kind (PID/name/path), process ID, pattern string
- **AVM_FILE_RULE** (1048 bytes): Action (hide/redirect), match path, redirect path
- **AVM_EVENT_RECORD**: Source, kind, action, PID, TID, timestamp, mechanism, original/spoofed text
- **AVM_EVENT_BATCH**: Count + array of 64 event records

---

## 5. Communication Flow

### When You Click "Apply Policy" in the Controller

```
1. Controller reads GUI state:
   - Mode (Observe/Selective/Full)
   - Enabled check flags (8 checkboxes → bitmask)
   - Target list
   - File rules

2. Controller → Kernel Driver (via IOCTL):
   a. SET_POLICY       → updates policy struct
   b. CLEAR_TARGETS    → removes old targets
   c. ADD_TARGET ×N    → adds each target
   d. CLEAR_FILE_RULES → removes old rules
   e. ADD_FILE_RULE ×N → adds each rule

3. Controller → Minifilter (via FilterSendMessage):
   a. SET_POLICY message → sends policy + targets + rules in one message

4. Both drivers immediately start using the new policy.
```

### When a Process Tries to Open a VM File

```
1. Process calls CreateFile("C:\Windows\System32\drivers\vmci.sys")
2. I/O Manager sends IRP_MJ_CREATE down the file system stack
3. Minifilter's AvmPreCreate is invoked (before the file system sees it)
4. Minifilter checks:
   - Is AvmCheckFileArtifacts enabled? Yes
   - Is this process targeted? (depends on mode)
   - Does the path match a hide rule? Yes (vmci.sys)
5. Minifilter returns STATUS_OBJECT_NAME_NOT_FOUND
6. Process receives ERROR_FILE_NOT_FOUND
7. Minifilter logs a telemetry event
```

### When a Process Enumerates a VM Directory

```
1. Process calls FindFirstFile("C:\Program Files\VMware\*")
2. File system fills buffer with: ., .., VMware Tools
3. Minifilter's AvmPostDirControl inspects the buffer
4. "VMware Tools" matches a hide rule → entry is removed from buffer
5. Process sees only: ., ..
6. Minifilter logs a telemetry event
```

### When a Process Opens a VM Registry Key

```
1. Process calls RegOpenKeyEx(HKLM\...\Services\vmci)
2. Configuration Manager invokes AvmRegistryCallback
3. Callback extracts leaf: "vmci"
4. "vmci" matches the block list
5. Callback returns STATUS_OBJECT_NAME_NOT_FOUND
6. Process receives ERROR_FILE_NOT_FOUND
7. Kernel driver logs a telemetry event
```

---

## 6. What Gets Hidden and How

### Registry Keys (Kernel Driver)

The kernel driver blocks access to registry keys whose **leaf name** matches any of these entries:

**VMware Keys:**

| Blocked Leaf Name | What It Is |
|-------------------|------------|
| VMware, Inc. | VMware vendor key |
| VMware Tools | VMware Tools config |
| VMware VGAuth | VMware guest authentication |
| vmci | VM Communication Interface driver |
| vmhgfs | VMware Host-Guest File System |
| vmmouse | VMware mouse driver |
| VMTools | VMware Tools service |
| vmvss | VMware VSS provider |
| vm3dmp | VMware SVGA 3D display driver |
| vmrawdsk | VMware raw disk driver |
| vmusbmouse | VMware USB mouse |
| VGAuth | VGAuth service |
| vm3dmp-debug | VM3DMP debug service |
| vm3dmp-stats | VM3DMP stats service |
| vm3dmp_loader | VM3DMP loader |
| vmxnet3 | VMware network adapter |

**VirtualBox Keys:**

| Blocked Leaf Name | What It Is |
|-------------------|------------|
| VBoxGuest | VirtualBox Guest Additions driver |
| VBoxMouse | VirtualBox mouse integration |
| VBoxSF | VirtualBox shared folders |
| VBoxVideo | VirtualBox video driver |
| VBoxService | VirtualBox guest service |
| VBoxTray | VirtualBox tray applet |
| VBoxWddm | VirtualBox WDDM display driver |
| Oracle | Oracle vendor key (parent of VBox GA) |
| VirtualBox | VirtualBox root key |
| VirtualBox Guest Additions | VBox Guest Additions config |

### Files and Directories (Minifilter)

The minifilter hides these paths by default (plus any user-added rules):

**VMware Files:**

| Hidden Path | Type |
|-------------|------|
| `C:\Windows\System32\drivers\vmci.sys` | Driver file |
| `C:\Windows\System32\drivers\vmhgfs.sys` | Driver file |
| `C:\Windows\System32\drivers\vmmouse.sys` | Driver file |
| `C:\Windows\System32\drivers\vm3dmp.sys` | Driver file |
| `C:\Windows\System32\drivers\vmxnet.sys` | Driver file |
| `C:\Windows\System32\drivers\vmx_svga.sys` | Driver file |
| `C:\Windows\System32\drivers\vm3dmp_loader.sys` | Driver file |
| `C:\Windows\System32\drivers\vmrawdsk.sys` | Driver file |
| `C:\Windows\System32\drivers\vmusbmouse.sys` | Driver file |
| `C:\Windows\System32\drivers\vmxnet3.sys` | Driver file |
| `C:\Program Files\VMware\VMware Tools\vmtoolsd.exe` | Executable |
| `C:\Program Files\VMware\VMware Tools\VMwareToolboxCmd.exe` | Executable |
| `C:\Program Files\VMware` | Directory |
| `C:\Program Files\VMware\VMware Tools` | Directory |

**VirtualBox Files:**

| Hidden Path | Type |
|-------------|------|
| `C:\Windows\System32\drivers\VBoxGuest.sys` | Driver file |
| `C:\Windows\System32\drivers\VBoxMouse.sys` | Driver file |
| `C:\Windows\System32\drivers\VBoxSF.sys` | Driver file |
| `C:\Windows\System32\drivers\VBoxVideo.sys` | Driver file |
| `C:\Windows\System32\drivers\VBoxWddm.sys` | Driver file |
| `C:\Windows\System32\VBoxControl.exe` | Executable |
| `C:\Windows\System32\VBoxService.exe` | Executable |
| `C:\Windows\System32\VBoxTray.exe` | Executable |
| `C:\Windows\System32\VBoxDisp.dll` | Library |
| `C:\Windows\System32\VBoxHook.dll` | Library |
| `C:\Windows\System32\VBoxOGL.dll` | Library |
| `C:\Program Files\Oracle\VirtualBox Guest Additions` | Directory |
| `C:\Program Files\Oracle` | Directory |

**Analysis Tool Paths:**

| Hidden Path | Type |
|-------------|------|
| `C:\Program Files\Wireshark` | Network analyzer |
| `C:\Program Files\IDA Pro` | Disassembler |
| `C:\Program Files\IDA Free` | Disassembler |
| `C:\Program Files\Ghidra` | Reverse engineering |
| `C:\Program Files\x64dbg` | Debugger |
| `C:\Program Files\Fiddler` | HTTP debugger |
| `C:\Program Files\pestudio` | PE analyzer |
| `C:\Program Files\Detect It Easy` | PE identifier |
| `C:\Program Files\HxD` | Hex editor |
| `C:\Program Files\Cutter` | RE framework |
| `C:\Program Files\Regshot` | Registry diff tool |
| `C:\Program Files\Volatility` | Memory forensics |
| `C:\Program Files\Autopsy` | Digital forensics |
| `C:\Program Files\FTK Imager` | Forensic imager |
| `C:\Program Files\YARA` | Pattern matcher |
| `C:\Tools` | Common analysis tools dir |
| *(plus more — see filter.c for full list)* | |

### Registry Values (Kernel Driver — Value Spoofing)

The kernel driver spoofs these BIOS/hardware identity values when queried by any targeted process:

| Registry Key | Value Name | Spoofed To |
|---|---|---|
| `HARDWARE\DESCRIPTION\System\BIOS` | BIOSVendor | Dell Inc. |
| `HARDWARE\DESCRIPTION\System\BIOS` | SystemManufacturer | Dell Inc. |
| `HARDWARE\DESCRIPTION\System\BIOS` | SystemProductName | OptiPlex 7090 |
| `HARDWARE\DESCRIPTION\System\BIOS` | BIOSVersion | 2.18.0 |
| `HARDWARE\DESCRIPTION\System\BIOS` | BaseBoardManufacturer | Dell Inc. |
| `HARDWARE\DESCRIPTION\System\BIOS` | BaseBoardProduct | 0XHGX6 |
| `HARDWARE\DESCRIPTION\System\BIOS` | BIOSReleaseDate | 09/17/2023 |
| `HARDWARE\DESCRIPTION\System\BIOS` | SystemFamily | OptiPlex |
| `HARDWARE\DESCRIPTION\System\SystemInformation` | BIOSVersion | 2.18.0 |
| `HARDWARE\DESCRIPTION\System\SystemInformation` | SystemManufacturer | Dell Inc. |
| `HARDWARE\DESCRIPTION\System\SystemInformation` | SystemProductName | OptiPlex 7090 |

> These spoofs cover both VMware values ("VMware, Inc.") and VirtualBox values ("innotek GmbH", "Oracle Corporation", "VirtualBox") — any VM-specific string in these keys is replaced with the Dell equivalent.

### System-Level Spoofing (build.ps1 -Install)

The install script applies these one-time system modifications:

| Action | What It Does |
|--------|-------------|
| **MAC address spoofing** | Finds network adapters with VMware OUI prefixes (00:0C:29, 00:50:56, 00:05:69, 00:1C:14) or VirtualBox OUI (08:00:27), replaces with Dell OUI (D4:BE:D9:xx:xx:xx) via the NetworkAddress registry key, restarts adapter |
| **BIOS value overwrite** | Writes spoofed Dell values directly to `HKLM\HARDWARE\DESCRIPTION\System\BIOS` (volatile — resets on reboot) |
| **User activity simulation** | Creates realistic-looking documents, desktop shortcuts, Chrome profile directory, and Recent file entries so the VM doesn't appear freshly provisioned |
| **Analysis tool detection** | Warns if common forensic tools (Wireshark, Process Monitor, IDA, x64dbg, etc.) are running |

### User-Mode API Hooks (Runtime Shim)

When injected into a target process, the shim intercepts:

| API | What It Conceals |
|-----|-----------------|
| `IsDebuggerPresent` | Returns FALSE |
| `CheckRemoteDebuggerPresent` | Returns FALSE |
| `NtQueryInformationProcess` | Hides debug flags |
| `NtSetInformationThread` | Blocks HideFromDebugger |
| `QueryPerformanceCounter` | Normalizes timing |
| `GetTickCount64` | Normalizes timing |
| `NtDelayExecution` | Normalizes sleep timing |
| `NtQuerySystemInformation` | Filters process list |
| `RegOpenKeyExW` | Blocks VM registry keys |
| `RegQueryValueExW` | Blocks VM registry values |
| `CreateFileW` | Blocks VM file access |
| `FindFirstFileExW` | Filters directory results |
| `FindNextFileW` | Filters directory results |

---

## 7. Operating Modes

| Mode | Registry | Files | Directory | Targeting |
|------|----------|-------|-----------|-----------|
| **Observe** | Log only | Pass through | Pass through | N/A |
| **Selective** | Block for targets | Hide for targets | Filter for targets | PID/name/path |
| **Full** | Block for all (PID > 4) | Hide for all (PID > 4) | Filter for all (PID > 4) | Automatic |

- **Observe**: Best for baseline measurement. All access is logged but nothing is hidden.
- **Selective Concealment**: Hides artifacts only for processes you explicitly target. System processes and other applications see normal results.
- **Full Concealment**: Hides artifacts for all user-mode processes. Most effective but most likely to cause side effects (e.g., VMware Tools may malfunction if its own files are hidden from it).

---

## 8. Demo Instructions

### Prerequisites

- A Windows VM running on VMware (the target environment)
- Visual Studio 2022 with WDK installed (for building, can be on host or VM)
- Administrator access on the VM
- Test-signing enabled: `bcdedit /set testsigning on` (requires reboot)
- Secure Boot disabled
- Memory Integrity / HVCI disabled

### Step 1: Build and Deploy

**Option A — Build and install on the VM (requires VS + WDK on the VM):**

```powershell
.\build.ps1 -Install
```

**Option B — Build on host, deploy to VM (no VS/WDK needed on the VM):**

1. On the host machine: `.\build.ps1`
2. Copy `AvmKernel.sys`, `AvmMiniFilter.sys`, `HillerTestDriver.cer`, `AvmController.exe`, `AvmProbeTest.exe`, and `build.ps1` to a folder on the VM.
3. On the VM (Admin PowerShell): `.\build.ps1 -Install`

The install script auto-detects the absence of build tools and skips
the build/sign steps, using the pre-signed files directly.

### Step 2: Run Baseline Probe

Before enabling any concealment, run the probe to see what VM indicators are visible:

```powershell
.\AvmProbeTest.exe baseline.json
```

Expected result: Most checks report **DETECTED** (CPUID, BIOS, registry, files, services, etc.).

### Step 3: Enable Full Concealment

1. Open AvmController.exe (it should launch automatically from build.ps1)
2. Click **Refresh** to verify both drivers are connected
3. Set mode to **Full Concealment**
4. Ensure all 8 check boxes are enabled
5. Click **Apply Policy**

### Step 4: Run Post-Concealment Probe

```powershell
.\AvmProbeTest.exe after.json
```

Expected changes:

| Check | Before | After |
|-------|--------|-------|
| VMware registry keys | DETECTED (6/6 found) | NOT DETECTED (0 found) |
| BIOS vendor | DETECTED (VMware, Inc.) | NOT DETECTED (Dell Inc.) |
| System manufacturer | DETECTED (VMware, Inc.) | NOT DETECTED (Dell Inc.) |
| System product name | DETECTED (VMware20,1) | NOT DETECTED (OptiPlex 7090) |
| VMware files | DETECTED (6/8 found) | NOT DETECTED (0 found) |
| VMware directories | DETECTED (2/3 found) | NOT DETECTED (0 found) |
| MAC address OUI | DETECTED (00:0C:29:...) | NOT DETECTED (D4:BE:D9:...) |
| Minifilter path probe | NOT DETECTED | NOT DETECTED (hidden) |
| Minifilter directory enum | DETECTED (3 entries) | NOT DETECTED (entries filtered) |
| User activity | DETECTED (empty dirs) | NOT DETECTED (files created) |

Checks that **will not change** (hardware-level, require hypervisor config):
- CPUID hypervisor bit and vendor (fix via VMX settings — see below)
- Running VMware services (RPC-based, runtime shim needed)
- Running VMware processes (runtime shim needed)

### Step 5: Show Telemetry

In the controller:
1. Watch the Telemetry grid fill with events as the probe runs
2. You'll see entries like:
   - `CmCallback` / `vmci` / `blocked` — registry key blocked
   - `PreCreate` / `vmci.sys` / `hidden` — file hidden
   - `PostDirControl` / `entries-filtered` / `hidden` — directory entries removed
3. Click **Export Logs** to save telemetry as JSON

### Step 6: Demo Custom File Rules

1. In the **File Rules** panel, type a custom path in the Match Path box:
   ```
   C:\Windows\System32\drivers\vmxnet3.sys
   ```
2. Click **Add Hide Rule**
3. Click **Apply Policy**
4. Run `.\AvmProbeTest.exe` again — the custom path is now also hidden

### Step 7: Compare JSON Reports

```powershell
# Compare baseline vs. after concealment
# Open baseline.json and after.json side by side
# Each check shows "status": "detected" or "status": "not_detected"
```

### Step 8: Demo Observe Mode

1. Switch the mode to **Observe**
2. Click **Apply Policy**
3. Run `.\AvmProbeTest.exe` — all indicators are visible again
4. But the telemetry grid shows every access was **logged**

This demonstrates the difference between passive monitoring and active concealment.

### Step 9: Clean Up

```powershell
# Stop and remove drivers
sc.exe stop AvmMiniFilter
sc.exe stop AvmKernel
sc.exe delete AvmMiniFilter
sc.exe delete AvmKernel
```

---

## 9. Validating with AvmProbeTest

AvmProbeTest performs 27 checks across multiple categories:

| # | Category | Check | What It Tests |
|---|----------|-------|---------------|
| 1 | CPUID | Hypervisor bit | ECX bit 31 of CPUID leaf 1 |
| 2 | CPUID | Hypervisor vendor | CPUID leaf 0x40000000 vendor string |
| 3 | BIOS | BIOS vendor | Registry `BIOSVendor` value |
| 4 | BIOS | System manufacturer | Registry `SystemManufacturer` value |
| 5 | BIOS | System product name | Registry `SystemProductName` value |
| 6 | Registry | VMware registry keys | 6 specific registry key paths |
| 7 | Registry | VirtualBox registry keys | 6 VirtualBox-specific key paths |
| 8 | Services | VMware services | 10 service names via SCM |
| 9 | Services | VirtualBox services | 6 VirtualBox service names via SCM |
| 10 | Files | VMware files | 8 file paths on disk |
| 11 | Files | VMware directories | 3 directory paths |
| 12 | Files | VirtualBox files | 11 VBox file paths on disk |
| 13 | Files | VirtualBox directories | 2 Oracle/VBox directory paths |
| 14 | Processes | VMware processes | Process enumeration for known names |
| 15 | Processes | VirtualBox processes | VBoxService.exe, VBoxTray.exe, etc. |
| 16 | Network | MAC address OUI | VMware and VirtualBox OUI prefixes |
| 17 | VMware | VMware Tools path | Registry install path check |
| 18 | VirtualBox | VBox Guest Additions | Registry install path check |
| 19 | Timing | Sleep delta | 500ms sleep accuracy measurement |
| 20 | AnalysisTools | Analysis tool processes | 60+ forensic/analysis tool process names |
| 21 | UserActivity | User activity indicators | Empty Documents/Desktop/Pictures/Downloads |
| 22 | Hardware | Hardware identity (baseboard) | BaseBoardManufacturer and BaseBoardProduct |
| 23 | Hardware | BIOS serial / family | BIOSReleaseDate and SystemFamily |
| 24 | Driver | AvmKernel status | IOCTL to `\\.\AvmKernel` |
| 25 | Minifilter | Path probe | CreateFile on a known VM artifact |
| 26 | Minifilter | Directory enum | FindFirstFile on VMware/VBox directory |
| 27 | Runtime | Shim DLL presence | File existence check for shim DLL |

### Interpreting Results

- **DETECTED**: The VM indicator is visible — the check found what it was looking for
- **NOT DETECTED**: The VM indicator is not visible — either the artifact genuinely doesn't exist, or a countermeasure is hiding it
- **ERROR**: The check could not run (permission issue, API failure, etc.)

### Which Components Affect Which Checks

| Check | AvmKernel | AvmMiniFilter | AvmRuntimeShim |
|-------|-----------|---------------|----------------|
| CPUID | — | — | ✓ (if hooked) |
| BIOS/Registry | ✓ (registry callback) | — | ✓ (RegOpenKeyEx hook) |
| VMware registry keys | ✓ (registry callback) | — | ✓ (RegOpenKeyEx hook) |
| VirtualBox registry keys | ✓ (registry callback) | — | ✓ (RegOpenKeyEx hook) |
| VMware services | — | — | — |
| VirtualBox services | — | — | — |
| VMware files | — | ✓ (PreCreate) | ✓ (CreateFileW hook) |
| VMware directories | — | ✓ (PostDirControl) | ✓ (FindFirstFile hook) |
| VirtualBox files | — | ✓ (PreCreate) | ✓ (CreateFileW hook) |
| VirtualBox directories | — | ✓ (PostDirControl) | ✓ (FindFirstFile hook) |
| VMware processes | — | — | ✓ (NtQuerySystemInfo hook) |
| VirtualBox processes | — | — | ✓ (NtQuerySystemInfo hook) |
| MAC address | — | — | — |
| VMware Tools | ✓ (registry callback) | — | ✓ (RegOpenKeyEx hook) |
| VBox Guest Additions | ✓ (registry callback) | — | ✓ (RegOpenKeyEx hook) |
| Timing | — | — | ✓ (QPC/GetTickCount hook) |
| Analysis tools | — | ✓ (PreCreate hides paths) | — |
| Driver status | ✓ (IOCTL) | — | — |
| Minifilter probe | — | ✓ (PreCreate) | — |
| Minifilter enum | — | ✓ (PostDirControl) | — |
| Runtime shim | — | — | — (just file check) |

---

## 10. Limitations and Scope

### What This System Can Hide

✅ Registry keys related to VMware and VirtualBox services and tools
✅ Registry values — BIOS vendor, manufacturer, product (spoofed to Dell via kernel callback)
✅ VMware and VirtualBox driver files and executables on disk
✅ VMware and VirtualBox entries in directory listings
✅ MAC address (changed via build.ps1 to non-VMware/VBox OUI)
✅ BIOS registry values (direct overwrite via build.ps1, kernel-level spoofing via callback)
✅ User activity artifacts (fake documents, browser profile, shortcuts)
✅ Analysis tool file paths (Wireshark, IDA, Ghidra, x64dbg, Autopsy, etc. hidden by minifilter)
✅ Debugger presence (via runtime shim)
✅ Timing anomalies (via runtime shim)
✅ VMware/VirtualBox processes in process enumeration (via runtime shim)
✅ Hardware baseboard identity (kernel registry value spoofing)

### What This System Cannot Hide (and Workarounds)

❌ **CPUID hypervisor bit**: This is a hardware-level indicator set by the hypervisor.

**Workaround:** Edit the VM's `.vmx` configuration file to add:
```
cpuid.1.ecx = "---0----------------------------"
hypervisor.cpuid.v0 = "FALSE"
```
This clears CPUID bit 31 and removes the "VMwareVMware" vendor string. The VM must be powered off before editing the VMX file.

❌ **Running VMware services**: Services like `vmci`, `vmhgfs`, `VMTools` are queried via the Service Control Manager (SCM), which uses RPC—not registry reads. The kernel registry callback cannot intercept SCM queries.

**Workaround:** Disable unnecessary VMware services:
```powershell
sc.exe config VMTools start=disabled
sc.exe config vmvss start=disabled
sc.exe stop VMTools
sc.exe stop vmvss
```

❌ **Running VMware processes**: Processes like `vmtoolsd.exe` and `VGAuthService.exe` appear in process snapshots. The runtime shim can hide them from `NtQuerySystemInformation` inside a target process, but the kernel driver does not terminate or hide processes system-wide.

❌ **Direct syscalls**: If malware uses direct syscall stubs (inline `syscall` instructions) instead of going through ntdll.dll, the runtime shim's IAT hooks are bypassed.

❌ **Kernel-level malware**: The system does not modify the SSDT or patch kernel memory. Rootkit-level malware operating in ring 0 can bypass all concealment.

### Design Philosophy

The system deliberately avoids dangerous techniques like SSDT hooking or kernel patching. It uses only documented, supported Windows APIs:
- `CmRegisterCallbackEx` for registry interception
- Filter Manager callbacks for file system interception
- IAT patching for user-mode API hooking

This makes the system safer and more stable, at the cost of being bypassable by sophisticated malware that uses direct syscalls.

---

## 11. Glossary

| Term | Definition |
|------|-----------|
| **CPUID** | x86 instruction that returns processor identification info; hypervisors set bit 31 of ECX |
| **IAT** | Import Address Table; the table in a PE file listing imported function addresses; patching it redirects calls |
| **IOCTL** | I/O Control Code; a mechanism for user-mode programs to send commands to kernel drivers |
| **KMDF** | Kernel-Mode Driver Framework; Microsoft's framework for building kernel drivers |
| **Minifilter** | A file system filter driver that uses the Windows Filter Manager for I/O interception |
| **Filter Manager** | Windows component that manages minifilter drivers and routes file system I/O through them |
| **OUI** | Organizationally Unique Identifier; the first 3 bytes of a MAC address identifying the manufacturer |
| **PreCreate** | A minifilter callback invoked before a file create/open operation reaches the file system |
| **PostDirControl** | A minifilter callback invoked after a directory query has been completed by the file system |
| **Registry callback** | A kernel callback registered via `CmRegisterCallbackEx` that intercepts registry operations |
| **SMBIOS** | System Management BIOS; firmware tables containing system manufacturer, model, and serial number |
| **SSDT** | System Service Descriptor Table; kernel table mapping syscall numbers to handler functions |
| **Test signing** | A Windows mode (`bcdedit /set testsigning on`) that allows loading drivers signed with test certificates |
| **WDK** | Windows Driver Kit; Microsoft's toolkit for building Windows kernel drivers |
| **WPF** | Windows Presentation Foundation; Microsoft's UI framework for desktop applications |
