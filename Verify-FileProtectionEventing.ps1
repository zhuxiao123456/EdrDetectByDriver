param(
    [string]$RepoRoot = $PSScriptRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$requiredFiles = @(
    (Join-Path $RepoRoot 'Common\PebMonitorShared.h'),
    (Join-Path $RepoRoot 'PebMonitor.h'),
    (Join-Path $RepoRoot 'MonitorCallbacks.cpp'),
    (Join-Path $RepoRoot 'FileProtection.cpp')
)

foreach ($path in $requiredFiles) {
    if (-not (Test-Path $path)) {
        throw "Required file not found: $path"
    }
}

$sharedHeaderText = Get-Content (Join-Path $RepoRoot 'Common\PebMonitorShared.h') -Raw
$pebMonitorHeaderText = Get-Content (Join-Path $RepoRoot 'PebMonitor.h') -Raw
$monitorCallbacksText = Get-Content (Join-Path $RepoRoot 'MonitorCallbacks.cpp') -Raw
$fileProtectionText = Get-Content (Join-Path $RepoRoot 'FileProtection.cpp') -Raw

if ($sharedHeaderText -notmatch 'DRIVER_EVENT_TYPE_BLOCKED_FILE_OPERATION') {
    throw 'Common\PebMonitorShared.h must define DRIVER_EVENT_TYPE_BLOCKED_FILE_OPERATION.'
}

if ($pebMonitorHeaderText -notmatch 'QueueDriverEventNode') {
    throw 'PebMonitor.h must declare QueueDriverEventNode for reusable driver event emission.'
}

if ($monitorCallbacksText -notmatch 'VOID\s+QueueDriverEventNode') {
    throw 'MonitorCallbacks.cpp must expose QueueDriverEventNode.'
}

if ($fileProtectionText -notmatch 'DRIVER_EVENT_TYPE_BLOCKED_FILE_OPERATION') {
    throw 'FileProtection.cpp must emit DRIVER_EVENT_TYPE_BLOCKED_FILE_OPERATION.'
}

if ($fileProtectionText -notmatch 'QueueDriverEventNode') {
    throw 'FileProtection.cpp must enqueue a blocked-file event through QueueDriverEventNode.'
}

if ($fileProtectionText -notmatch 'driver_self_protection') {
    throw 'FileProtection.cpp must tag the blocked-file event with a stable rule identifier.'
}

if ($fileProtectionText -notmatch 'STATUS_ACCESS_DENIED') {
    throw 'FileProtection.cpp must still complete the blocked open with STATUS_ACCESS_DENIED.'
}

Write-Host '[+] File protection eventing checks passed.'
