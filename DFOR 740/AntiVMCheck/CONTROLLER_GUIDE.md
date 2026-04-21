# Anti-VM Countermeasure Controller – User Guide

This guide explains how to use the **AvmController** WPF GUI to configure and monitor the Anti-VM-Awareness Countermeasure Platform.

---

## Prerequisites

| Requirement | Details |
|---|---|
| Operating System | Windows 10/11 x64 (or Server 2016+) |
| Kernel driver | `AvmKernel.sys` loaded via `sc create` or test-signing + `bcdedit` |
| Minifilter driver | `AvmMiniFilter.sys` loaded via `fltmc load AvmMiniFilter` |
| Admin privileges | Required to communicate with the kernel driver and minifilter |

### Loading the Drivers (One-Time Setup)

```powershell
# Enable test signing (reboot required)
bcdedit /set testsigning on

# Install the kernel driver
sc create AvmKernel type= kernel binPath= "C:\path\to\AvmKernel.sys" start= demand
sc start AvmKernel

# Install and load the minifilter
# Copy AvmMiniFilter.sys to C:\Windows\System32\drivers\
# Install the minifilter INF or use:
fltmc load AvmMiniFilter
```

---

## Launching the Controller

1. Build the solution in **Release | x64** configuration.
2. Navigate to `x64\Release\` and run **AvmController.exe** as Administrator.
3. The main window opens with four sections:
   - **Driver Status** (top bar)
   - **Targets** (left panel)
   - **Modes and Checks** (center panel)
   - **File Rules** (right panel)
   - **Telemetry** (bottom grid)

---

## UI Overview

### 1. Driver Status Bar

Located at the top of the window. Shows real-time connection status:

| Element | Description |
|---|---|
| **Kernel: connected/disconnected** | Whether the controller can reach `\\.\AvmKernel` |
| **Targets: N  Events: N** | Current kernel driver target count and pending events |
| **Minifilter: connected/disconnected** | Whether the controller can reach `\AvmMiniFilterPort` |
| **Rules: N  Events: N** | Current minifilter file-rule count and pending events |
| **Refresh** button | Polls both drivers for current status |
| **Apply Policy** button | Sends the current configuration to both drivers |

> **Tip:** Click **Refresh** immediately after launching to verify both drivers are reachable.

### 2. Targets Panel (Left)

Controls which processes receive countermeasure protection.

| Control | Usage |
|---|---|
| **Kind** dropdown | Choose targeting mode: `PID`, `Image Name`, or `Image Path Prefix` |
| **Value** text box | Enter the PID number, executable name (e.g., `malware.exe`), or path prefix |
| **Add Target** button | Adds the target to the list (sent on next **Apply Policy**) |
| **Inject Shim** button | Attempts to inject the runtime shim DLL into the target process |
| **Target list** | Shows currently configured targets; items persist until cleared |

**Examples:**
- To protect PID 1234: select `PID`, type `1234`, click **Add Target**
- To protect all instances of a program: select `Image Name`, type `sample.exe`, click **Add Target**

> **Note:** In **Full Concealment** mode, targets are ignored — all user-mode processes (PID > 4) are protected. Targets matter only in **Selective Concealment** mode.

### 3. Modes and Checks Panel (Center)

#### Operating Modes

| Mode | Behavior |
|---|---|
| **Observe** | Logs all VM indicator access but does **not** block or hide anything. Use this for baseline measurement. |
| **Selective Concealment** | Actively hides VM artifacts **only** for processes in the target list. Other processes see normal results. |
| **Full Concealment** | Actively hides VM artifacts for **all** user-mode processes (PID > 4). No targeting needed. |

#### Check Toggles

Each checkbox enables or disables a specific countermeasure category:

| Check | What It Does |
|---|---|
| **Debugger concealment** | Intercepts debugger-detection APIs (IsDebuggerPresent, NtQueryInformationProcess) |
| **Timing normalization** | Normalizes timing checks (RDTSC, QueryPerformanceCounter) to hide VM overhead |
| **Native API monitoring** | Monitors and intercepts low-level NT API calls used for VM detection |
| **Process/tool concealment** | Hides VM-related processes (vmtoolsd.exe, VGAuthService.exe) from process enumeration |
| **Driver/device probe filtering** | Hides VM-related device drivers from device enumeration |
| **Registry artifact hiding** | Blocks access to VM-related registry keys (VMware, Inc., vmci, VMTools, etc.) |
| **File artifact hiding** | Returns "not found" for VM-related files (vmci.sys, vmtoolsd.exe, etc.) |
| **Directory listing filtering** | Removes VM-related entries from directory listings |

> **Recommendation:** For maximum concealment, leave all checks enabled and use **Full Concealment** mode.

### 4. File Rules Panel (Right)

Add custom file-system rules beyond the built-in defaults.

| Control | Usage |
|---|---|
| **Match Path** text box | Full path to hide or redirect (e.g., `C:\Windows\System32\drivers\vmci.sys`) |
| **Redirect Path** text box | (Optional) Path to show instead when redirecting |
| **Add Hide Rule** button | Adds a rule that makes the file appear nonexistent |
| **Add Redirect Rule** button | Adds a rule that redirects file access to another path |
| **Remove Selected** button | Removes the selected rule from the list |
| **Clear Rules** button | Removes all custom file rules |
| **Export Logs** button | Saves all telemetry events to a JSON or CSV file |
| **Rules list** | Shows currently configured rules; select a rule to remove it |

**Adding a custom file path to hide:**
1. Type the full path in the **Match Path** box (e.g., `C:\Windows\System32\drivers\vmxnet3.sys`)
2. Click **Add Hide Rule**
3. The rule appears in the list below
4. Click **Apply Policy** to push the rule to both drivers
5. The file will now appear nonexistent to any targeted process

**Removing a rule:**
1. Click on the rule in the rules list to select it
2. Click **Remove Selected**
3. Click **Apply Policy** to update both drivers

**Built-in defaults:** When no custom rules are configured, the minifilter automatically hides common VMware artifacts:
- `C:\Windows\System32\drivers\vmci.sys`
- `C:\Windows\System32\drivers\vmhgfs.sys`
- `C:\Windows\System32\drivers\vmmouse.sys`
- `C:\Windows\System32\drivers\vm3dmp.sys`
- `C:\Program Files\VMware\VMware Tools\vmtoolsd.exe`
- `C:\Program Files\VMware\VMware Tools\VMwareToolboxCmd.exe`
- `C:\Program Files\VMware` (directory)
- `C:\Program Files\VMware\VMware Tools` (directory)

### 5. Telemetry Grid (Bottom)

Real-time event log showing all intercepted operations:

| Column | Description |
|---|---|
| **Time** | Timestamp of the event |
| **Source** | Which component generated it: `Kernel`, `MiniFilter`, or `Runtime` |
| **Type** | Event category (RegistryProbe, FileProbe, DirectoryEnum, PolicyUpdate, etc.) |
| **PID** | Process ID that triggered the event |
| **TID** | Thread ID |
| **Mechanism** | The specific API or callback that was intercepted |
| **Original** | The original value or path that was requested |
| **Spoofed** | The value returned (e.g., "blocked", "hidden", "observed") |
| **Image** | Image path of the process (when available) |

Events refresh automatically when you click **Refresh** or **Apply Policy**.

---

## Step-by-Step Workflow

### Quick Start: Full VM Concealment

1. **Load both drivers** (see Prerequisites above)
2. **Launch AvmController.exe** as Administrator
3. Click **Refresh** — verify both "Kernel" and "Minifilter" show "connected"
4. Set mode to **Full Concealment**
5. Ensure all check boxes are enabled (they are by default)
6. Click **Apply Policy**
7. The status bar should update to show the active configuration

### Selective Concealment for a Specific Process

1. Load drivers and launch the controller
2. Set mode to **Selective Concealment**
3. In the Targets panel:
   - Select **PID** from the dropdown
   - Enter the PID of the process you want to protect
   - Click **Add Target**
4. Click **Apply Policy**
5. Only the targeted process will see concealed VM artifacts

### Adding Custom Hide Rules

1. In the File Rules panel, enter a path in the **Match Path** box
   - Example: `C:\Windows\System32\drivers\vmxnet3.sys`
2. Click **Add Hide Rule**
3. Click **Apply Policy** to push the rule to both drivers

### Exporting Telemetry

1. Click **Refresh** to fetch the latest events
2. Click **Export Logs** in the File Rules panel
3. Choose a save location — events are written as JSON

---

## Validating with AvmProbeTest

Use the probe executable to verify that countermeasures are working:

```powershell
# Before enabling countermeasures (baseline)
.\AvmProbeTest.exe baseline.json

# After enabling Full Concealment + Apply Policy
.\AvmProbeTest.exe after.json
```

**Expected changes after enabling Full Concealment:**

| Check | Before | After |
|---|---|---|
| VMware registry keys | DETECTED | NOT DETECTED |
| VMware files | DETECTED | NOT DETECTED |
| VMware directories | DETECTED | NOT DETECTED |
| Minifilter path probe | NOT DETECTED | NOT DETECTED (file hidden) |
| Minifilter directory enum | DETECTED | NOT DETECTED (entries filtered) |
| Kernel driver status | mode=0/2, checks=0xFF | mode=2, checks=0xFF, fileRules>0 |

> **Note:** CPUID hypervisor bit, BIOS vendor, MAC address, and running processes are **not** hidden by the kernel driver or minifilter — these require the runtime shim (DLL injection) or are hardware-level indicators.

---

## Troubleshooting

| Problem | Solution |
|---|---|
| "Kernel: disconnected" | Verify `AvmKernel.sys` is loaded: `sc query AvmKernel` |
| "Minifilter: disconnected" | Verify minifilter is loaded: `fltmc` |
| Apply Policy fails | Run AvmController as Administrator |
| No telemetry events | Click **Refresh**; ensure mode is not **Observe** for block/hide events |
| Probe still shows DETECTED after Apply Policy | Ensure you ran AvmProbeTest.exe **after** clicking Apply Policy; check that the mode is Full Concealment |
| Registry keys still visible | The kernel driver's registry callback blocks key open/create operations; `reg query` should fail for blocked keys |
| Files still visible | Verify the minifilter is loaded and the File artifact hiding check is enabled |
| System instability | Switch to **Observe** mode and click **Apply Policy** to disable active concealment |

---

## Architecture Reference

```
┌──────────────────────────┐
│   AvmController (GUI)    │
│   WPF / C# / .NET        │
└─────┬──────────┬─────────┘
      │ IOCTL    │ FilterSendMessage
      ▼          ▼
┌───────────┐  ┌──────────────┐
│ AvmKernel │  │AvmMiniFilter │
│ (KMDF)    │  │ (FltMgr)     │
│           │  │              │
│ Registry  │  │ PreCreate    │
│ Callback  │  │ PostDirCtrl  │
│           │  │ Comm Port    │
└───────────┘  └──────────────┘
```

- **AvmKernel** intercepts registry key access via `CmRegisterCallbackEx`
- **AvmMiniFilter** intercepts file creates (PreCreate) and directory listings (PostDirControl)
- Both drivers share the same policy, target, and file-rule structures defined in `shared\avm_shared.h`
- The controller sends identical policy snapshots to both drivers on **Apply Policy**
