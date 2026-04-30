# How It Works

This file explains the project in plain language.

## Big Picture

Malware often checks for clues that it is running inside a virtual machine. This project tries to hide some of those clues so the malware behaves more like it would on a normal computer.

The project does that in three layers:

1. `AvmKernel.sys` handles registry-related concealment and stores the active policy.
2. `AvmMiniFilter.sys` hides selected files and folders.
3. `AvmRuntimeShim.dll` hooks API calls inside a target process.

The controller sends settings to these components and shows the telemetry they produce.

## Simple Example

If a program looks for `C:\Windows\System32\drivers\vmci.sys`, the project can make that file appear to be missing.

If a program reads BIOS strings from the registry, the project can return a normal-looking system identity instead of a VMware-looking one.

If a program is launched through the controller with the shim, some user-mode API calls can also be intercepted before the program sees the real answer.

## The Four Main Pieces

### `AvmController.exe`

The controller is the UI.

You use it to:

- refresh driver status
- choose the concealment mode
- apply policy
- add target processes when using selective concealment
- launch a target with the shim
- watch telemetry

### `AvmKernel.sys`

The kernel driver is the policy and registry layer.

It can:

- store the current concealment mode
- block selected registry keys
- spoof selected BIOS and system identity values
- receive telemetry from the runtime shim

### `AvmMiniFilter.sys`

The minifilter is the file-hiding layer.

It can:

- hide selected files when a process tries to open them
- remove selected names from directory listings

This is why a program may get `file not found` even when the file really exists on disk.

### `AvmRuntimeShim.dll`

The runtime shim is the process-level layer.

It is injected into a target process when you use `Launch with Shim` in the controller.

It can intercept selected API calls such as:

- registry access
- file access
- service checks
- firmware queries
- debugger checks
- some timing-related calls

This part only affects the process that was launched with the shim.

## What Happens When You Click Apply Policy

When you click `Apply Policy` in the controller:

1. The controller reads the current UI settings.
2. It sends the policy to the kernel driver.
3. It sends the policy to the minifilter.
4. Both drivers begin using the new settings right away.

In `Full Concealment`, the drivers try to apply concealment broadly to user-mode processes.

In `Selective Concealment`, the target list matters. A target is the process that should receive concealment. For example, you would add the malware sample or test program, not `vmci.sys` or `VMware Tools`.

## What Happens When You Use Launch With Shim

When you use `Launch with Shim`:

1. The controller starts the target process in a suspended state.
2. It injects `AvmRuntimeShim.dll`.
3. It resumes the process.
4. It captures the console output and shows it in a window.

This is important because many checks happen very early in program startup. If the shim is not loaded before the program starts running, those early checks can be missed.

## Telemetry

Telemetry is a record of what the project intercepted.

Typical examples:

- a registry key open was blocked
- a file open was denied
- a BIOS value was spoofed
- a firmware query was changed

The telemetry view in the controller is meant to answer one simple question:

"What did the target ask for, and what did the project return instead?"

## Modes

### Observe

Nothing is hidden. The project mainly logs what would have happened.

### Selective Concealment

Only selected target processes get concealment.

### Full Concealment

Concealment is applied broadly to user-mode processes. This is the normal demo mode.

## What This Project Is Good At

It is most useful for:

- registry-based VM checks
- file and directory artifact checks
- some BIOS and firmware string checks
- some user-mode API-based checks

## Limits

This project does not solve every anti-VM technique.

- It has only been tested on VMware.
- Some checks happen below the level this project intercepts.
- Some checks are only hidden inside a shimmed process.
- Running a tool directly is different from launching it through the controller.
- In current testing, the runtime shim path is still unstable and may fail before producing output.
- Timing and hypervisor-level signals are still hard to hide from inside the guest.
- User-mode hooks can be bypassed by direct syscalls or kernel-level code.
