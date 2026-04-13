# edr_driver

`driver_module` branch currently tracks the pure process + registry edition of the HostGuard kernel driver.

## Scope

This repository contains the kernel-side enforcement module used by HostGuard:

- synchronous process creation verdicting through the process communication port
- registry pre-operation interception and blocking
- kernel event queue for registry and response telemetry
- runtime status reporting and config synchronization
- kernel-assisted terminate response IOCTL

## Current protection surface

Included in this branch:

- process create callback
- registry callback
- process port communication with user mode
- registry event telemetry

Removed from this branch:

- driver verdict port
- driver blacklist and trie matching
- image notify callback for driver load telemetry
- file rules and file interception callbacks

The driver still registers with FltMgr because the communication port is built on that path, but this branch does not enable file-operation callbacks.

## Repository layout

- `PebMonitor.cpp`: driver entry, global state, communication port lifecycle
- `MonitorCallbacks.cpp`: process and registry callbacks
- `IoctlDispatch.cpp`: device control handlers and runtime status query
- `Common/PebMonitorShared.h`: shared ABI with HostGuard

## Build

Recommended environment:

- Visual Studio 2022 with WDK
- `Legacy2012 | x64`
- `SignMode=Off` for unsigned local build validation

Output binary:

- `x64\\Legacy2012\\DriverModule.sys`

## Integration contract

This branch is intended to pair with the `edr_hostguard` repository on its `edr_detect` branch. Both sides share the reduced ABI in `Common/PebMonitorShared.h`, which now exposes only process and registry related protocol fields.
