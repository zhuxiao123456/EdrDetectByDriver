# edr_hostguard

`edr_detect` branch currently tracks the pure process + registry edition of HostGuard.

## Scope

This repository contains the user-mode controller for the lightweight HostGuard deployment model:

- loads and manages the paired kernel driver
- pushes process verdict and registry rule configuration to the driver
- receives process creation verdict requests through the process communication port
- pulls registry and response telemetry events from the driver
- supports kernel-assisted terminate response for already running processes

## Current protection surface

Included in this branch:

- process creation verdicting
- process allow rules
- registry block rules
- registry allow rules
- runtime status and telemetry query

Removed from this branch:

- driver blacklist and driver verdict port
- driver load interception
- file rules and file interception
- image-load based suspicious driver telemetry

## Repository layout

- `HostGuard.cpp`: service and CLI entry, process verdict loop, event handling
- `RuleManager.*`: JSON rule loading and runtime snapshots
- `DriverUtils.*`: driver/service install and IOCTL helpers
- `Common/PebMonitorShared.h`: shared ABI with the kernel driver

## Build

Recommended environment:

- Visual Studio 2022
- `Legacy2012 | x64` configuration
- `nlohmann.json` NuGet package restored under `packages/`

Output binary:

- `x64\\Legacy2012\\HostGuard.exe`

## Rules

This branch expects process and registry rules only. The active schema is centered on:

- `process_rules`
- `process_allow_rules`
- `registry_rules`
- `registry_allow_rules`
- `process_verdict`
- `response`

Driver and file specific rule sections from older branches are intentionally not used here.
