# AvmController Guide

Run `AvmController.exe` as Administrator. You can also begin by using `.\build.ps1 -Install`.

## Before You Start

Make sure:

- `AvmKernel.sys` is installed and running
- `AvmMiniFilter.sys` is installed and running
- `AvmRuntimeShim.dll` is next to `AvmController.exe`

The normal install command is:

```powershell
.\build.ps1 -Install
```

## Main Workflow

1. Open the controller.
2. Click `Refresh`.
3. Confirm the kernel driver and minifilter show as connected.
4. Leave the mode set to `Full Concealment`.
5. Click `Apply Policy`.
6. Use `Launch with Shim` to start your test program.

## Modes

### Observe

The project logs activity but does not try to hide anything.

### Selective Concealment

Only the targets you add are meant to receive concealment.

### Full Concealment

The project applies concealment broadly to user-mode processes. This is the simplest mode to use for testing.

## Targets

You can target a process by:

- PID
- image name
- image path prefix

Targets are the processes that should receive concealment.

Examples:

- the malware sample you are running
- `AvmProbeTest.exe`
- `pafish64.exe`

Targets are not the VM artifacts you want to hide. They are the programs you want to hide those artifacts from.

If you are using `Full Concealment`, you usually do not need to manage targets manually.

## Telemetry

The telemetry panel shows what the project intercepted.

Current columns:

- `Time`
- `Source`
- `PID`
- `Original`
- `Spoofed`
- `Process`

You can:

- filter the list with the text box
- sort by newest first
- sort by oldest first
- clear the list

## Launch With Shim

Use `Launch with Shim` when you want the runtime shim to affect the target process.

This matters for checks that happen inside the process, such as:

- API-based registry checks
- API-based file checks
- some service checks
- some firmware string checks
- debugger-related checks

If you run a program directly from `cmd.exe`, the runtime shim is not active unless you inject it separately.

## Inject Shim

`Inject Shim` is for an already-running process by PID.

This can work, but it is less reliable for programs that do their checks right at startup. `Launch with Shim` is the safer choice for testing. 

Note: I did not perform extensive testing with this option. It could have stability issues or cause a test program/malware sample to act unpredictably.

## File Rules

You can add custom file rules if you want to hide extra paths.

Common use:

1. Enter a full path in `Match Path`
2. Add a hide rule
3. Click `Apply Policy`

## If Something Looks Wrong

- If the drivers show disconnected, reinstall with `.\build.ps1 -Install`
- If the shim seems inactive, make sure you launched the target through `Launch with Shim`
- If telemetry is empty, rerun the target after applying policy
