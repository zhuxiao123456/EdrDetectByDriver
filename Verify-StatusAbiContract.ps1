param(
    [string]$RepoRoot = $PSScriptRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$sharedHeaderPath = Join-Path $RepoRoot 'Common\PebMonitorShared.h'
$driverUtilsPath = Join-Path $RepoRoot 'DriverUtils.cpp'
$hostGuardPath = Join-Path $RepoRoot 'HostGuard.cpp'
$runtimeCountersTestPath = Join-Path $RepoRoot 'StatusRuntimeCountersTests.ps1'

foreach ($path in @($sharedHeaderPath, $driverUtilsPath, $hostGuardPath)) {
    if (-not (Test-Path $path)) {
        throw "Required file not found: $path"
    }
}

$sharedHeaderText = Get-Content $sharedHeaderPath -Raw
$driverUtilsText = Get-Content $driverUtilsPath -Raw
$hostGuardText = Get-Content $hostGuardPath -Raw

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

if ($driverUtilsText -notmatch 'PEBMONITOR_ABI_IS_COMPAT\s*\(\s*outStatus\.AbiVersion\s*\)') {
    throw 'QueryDriverStatus must validate AbiVersion compatibility.'
}

if ($hostGuardText -notmatch 'status\.PolicyEpoch') {
    throw 'HostGuard status logging must include PolicyEpoch.'
}

if ($hostGuardText -notmatch 'status\.FastPathHitCount') {
    throw 'HostGuard status logging must include FastPathHitCount.'
}

if ($hostGuardText -notmatch 'status\.CacheHitCount') {
    throw 'HostGuard status logging must include CacheHitCount.'
}

if ($hostGuardText -notmatch 'status-json') {
    throw 'HostGuard must expose a status-json command for runtime counter regression validation.'
}

if ($hostGuardText -notmatch '--json') {
    throw 'HostGuard status command must support a --json switch.'
}

if ($hostGuardText -notmatch 'fast_path_hit_count') {
    throw 'HostGuard JSON status output must include fast_path_hit_count.'
}

if ($hostGuardText -notmatch 'cache_hit_count') {
    throw 'HostGuard JSON status output must include cache_hit_count.'
}

if ($hostGuardText -notmatch 'slow_path_count') {
    throw 'HostGuard JSON status output must include slow_path_count.'
}

if (-not (Test-Path $runtimeCountersTestPath)) {
    throw 'StatusRuntimeCountersTests.ps1 must exist for runtime counter regression validation.'
}

Write-Host '[+] HostGuard ABI/runtime status contract checks passed.'
