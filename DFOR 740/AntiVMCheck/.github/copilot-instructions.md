\# Copilot Repository Instructions



You are working inside a multi-project repository. Only operate inside the current project folder.



\## Scope Rules

\- Never request access outside the current working directory

\- Never modify other school projects in the repository

\- All files must be created or modified within this project folder only

\- Do not reference parent directories or external repositories



\## Project Goal

This project builds an Anti-VM-Awareness Countermeasure Platform for defensive sandbox research.



The system consists of:

1\. Kernel-mode driver (ring 0)

2\. File system minifilter driver

3\. User-mode controller with GUI



All components must integrate and function together.



\## Development Priorities

1\. Kernel driver (highest priority)

2\. Minifilter driver

3\. User-mode GUI controller



Favor low-level functionality first, then build control and interface layers.



\## Coverage Requirement

Do not implement only a single proof-of-concept feature.



You must aim to cover as many objectives from PROJECT\_SPEC.md as possible:

\- Debugger detection/concealment

\- Timing checks

\- Native API monitoring

\- Process/module enumeration

\- File-system artifact hiding

\- VM artifact detection

\- Telemetry generation



If full implementations are not feasible, implement partial working versions instead of skipping features.



\## Implementation Rules

\- Build a working MVP, not scaffolding

\- Do not leave core functionality as TODOs or stubs

\- Prefer simple, working implementations over complex designs

\- Keep dependencies minimal

\- Ensure code compiles and runs



\## Kernel \& Driver Expectations

\- Use Windows-native driver models where appropriate

\- Implement IOCTL-based communication with user mode

\- Support per-process targeting

\- Generate structured telemetry events



\## Minifilter Expectations

\- Intercept file operations

\- Hide or modify file system artifacts

\- Filter directory listings



\## User-Mode Program Expectations

\- Must provide a GUI (not just CLI)

\- Must communicate with drivers

\- Must allow:

&#x20; - enabling/disabling specific countermeasures

&#x20; - selecting operating modes

&#x20; - viewing telemetry

&#x20; - exporting logs



\## GUI Requirements

The GUI should include:

\- Driver status

\- Target process controls

\- Toggle switches for countermeasure categories

\- Mode selection controls

\- Event/telemetry viewer

\- Log export functionality



\## Behavior Rules

\- Do not stop for clarification unless completely blocked

\- If something is unclear, choose a reasonable implementation and proceed

\- After major changes:

&#x20; - ensure the project builds or runs

&#x20; - fix issues before continuing



\## Output Expectations

After each major step, summarize:

\- files changed

\- what works

\- what remains



\## Required Technology Choices



Use the following implementation choices unless the repository already contains a different working setup:



\- Kernel-mode driver must use KMDF

\- File system component must be a Windows minifilter driver using Filter Manager

\- Do NOT implement the kernel driver as raw WDM unless absolutely required by an existing project constraint

\- User-mode controller should use C# WPF for the GUI unless an existing project already uses another Windows GUI framework



\## Driver Architecture Rules



The project must have three separate components:

1\. KMDF kernel driver

2\. Minifilter driver

3\. User-mode GUI controller



Do not merge the KMDF driver and minifilter into one project.

Keep communication explicit and simple:

\- user mode ↔ KMDF driver via IOCTL

\- user mode ↔ minifilter via communication port or a clearly documented alternative

\- shared headers/contracts for event and policy structures



\## Build Expectations



Generate buildable Visual Studio project structure for all three components.

Include:

\- solution file

\- project files

\- shared include folder

\- README with build and load steps



Use simple, stable implementation patterns that are likely to compile successfully.

