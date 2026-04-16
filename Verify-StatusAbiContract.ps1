param(
    [string]$RepoRoot = $PSScriptRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$sharedHeaderPath = Join-Path $RepoRoot 'Common\PebMonitorShared.h'
$ioctlDispatchPath = Join-Path $RepoRoot 'IoctlDispatch.cpp'

if (-not (Test-Path $sharedHeaderPath)) {
    throw "Shared header not found: $sharedHeaderPath"
}

if (-not (Test-Path $ioctlDispatchPath)) {
    throw "IoctlDispatch.cpp not found: $ioctlDispatchPath"
}

$sharedHeaderText = Get-Content $sharedHeaderPath -Raw
$ioctlDispatchText = Get-Content $ioctlDispatchPath -Raw

if ($sharedHeaderText -notmatch 'PEBMONITOR_ABI_VERSION') {
    throw 'PEBMONITOR_ABI_VERSION is missing from Common\PebMonitorShared.h.'
}

if ($sharedHeaderText -notmatch 'typedef struct _DRIVER_RUNTIME_STATUS\s*\{\s*ULONG\s+AbiVersion;') {
    throw 'DRIVER_RUNTIME_STATUS must start with AbiVersion.'
}

$requiredRuntimeStatusFields = @(
    'PolicyEpoch',
    'FastPathHitCount',
    'CacheHitCount',
    'CacheMissCount',
    'CacheFlushCount',
    'SlowPathCount'
)

foreach ($field in $requiredRuntimeStatusFields) {
    if ($sharedHeaderText -notmatch ('\b' + [regex]::Escape($field) + '\b')) {
        throw "DRIVER_RUNTIME_STATUS is missing field: $field"
    }
}

if ($sharedHeaderText -notmatch 'FIELD_OFFSET\s*\(\s*DRIVER_RUNTIME_STATUS\s*,\s*AbiVersion\s*\)\s*==\s*0') {
    throw 'DRIVER_RUNTIME_STATUS must assert AbiVersion offset 0.'
}

if ($ioctlDispatchText -notmatch 'runtimeStatus->AbiVersion\s*=\s*PEBMONITOR_ABI_VERSION') {
    throw 'FillDriverRuntimeStatus must set AbiVersion.'
}

if ($ioctlDispatchText -notmatch 'runtimeStatus->PolicyEpoch') {
    throw 'FillDriverRuntimeStatus must populate PolicyEpoch.'
}

Write-Host '[+] Driver ABI/runtime status contract checks passed.'
