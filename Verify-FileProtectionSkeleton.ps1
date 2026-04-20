param(
    [string]$RepoRoot = $PSScriptRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$requiredPaths = @(
    (Join-Path $RepoRoot 'FileProtection.h'),
    (Join-Path $RepoRoot 'FileProtection.cpp'),
    (Join-Path $RepoRoot 'MonitorCallbacks.cpp'),
    (Join-Path $RepoRoot 'PebMonitor.h'),
    (Join-Path $RepoRoot 'PebMonitor.cpp'),
    (Join-Path $RepoRoot 'DriverModule.vcxproj'),
    (Join-Path $RepoRoot 'DriverModule.vcxproj.filters')
)

foreach ($path in $requiredPaths) {
    if (-not (Test-Path $path)) {
        throw "Required file not found: $path"
    }
}

$fileProtectionHeaderText = Get-Content (Join-Path $RepoRoot 'FileProtection.h') -Raw
$fileProtectionSourceText = Get-Content (Join-Path $RepoRoot 'FileProtection.cpp') -Raw
$monitorCallbacksText = Get-Content (Join-Path $RepoRoot 'MonitorCallbacks.cpp') -Raw
$pebMonitorHeaderText = Get-Content (Join-Path $RepoRoot 'PebMonitor.h') -Raw
$pebMonitorSourceText = Get-Content (Join-Path $RepoRoot 'PebMonitor.cpp') -Raw
$vcxprojText = Get-Content (Join-Path $RepoRoot 'DriverModule.vcxproj') -Raw
$filtersText = Get-Content (Join-Path $RepoRoot 'DriverModule.vcxproj.filters') -Raw

if ($fileProtectionHeaderText -notmatch 'InitializeFileProtectionState') {
    throw 'FileProtection.h must declare InitializeFileProtectionState.'
}

if ($fileProtectionHeaderText -notmatch 'CleanupFileProtectionState') {
    throw 'FileProtection.h must declare CleanupFileProtectionState.'
}

if ($fileProtectionHeaderText -notmatch 'FileProtectionPreCreate') {
    throw 'FileProtection.h must declare FileProtectionPreCreate.'
}

if ($fileProtectionSourceText -notmatch 'DriverModule\.sys') {
    throw 'FileProtection.cpp must protect DriverModule.sys by full path.'
}

if ($fileProtectionSourceText -notmatch 'FltGetFileNameInformation') {
    throw 'FileProtection.cpp must query normalized file names through FltGetFileNameInformation.'
}

if ($fileProtectionSourceText -notmatch 'STATUS_ACCESS_DENIED') {
    throw 'FileProtection.cpp must deny dangerous protected-file opens with STATUS_ACCESS_DENIED.'
}

if ($monitorCallbacksText -notmatch 'IRP_MJ_CREATE') {
    throw 'MonitorCallbacks.cpp must register an IRP_MJ_CREATE minifilter callback.'
}

if ($monitorCallbacksText -notmatch 'FileProtectionPreCreate') {
    throw 'MonitorCallbacks.cpp must wire FileProtectionPreCreate into g_FilterOperationCallbacks.'
}

if ($pebMonitorHeaderText -notmatch 'FileProtection\.h') {
    throw 'PebMonitor.h must include FileProtection.h.'
}

if ($pebMonitorSourceText -notmatch 'InitializeFileProtectionState') {
    throw 'PebMonitor.cpp must initialize file protection state during DriverEntry.'
}

if ($pebMonitorSourceText -notmatch 'CleanupFileProtectionState') {
    throw 'PebMonitor.cpp must clean up file protection state during unload/cleanup.'
}

if ($vcxprojText -notmatch 'FileProtection\.cpp') {
    throw 'DriverModule.vcxproj must compile FileProtection.cpp.'
}

if ($vcxprojText -notmatch 'FileProtection\.h') {
    throw 'DriverModule.vcxproj must include FileProtection.h.'
}

if ($filtersText -notmatch 'FileProtection\.cpp') {
    throw 'DriverModule.vcxproj.filters must list FileProtection.cpp.'
}

if ($filtersText -notmatch 'FileProtection\.h') {
    throw 'DriverModule.vcxproj.filters must list FileProtection.h.'
}

Write-Host '[+] File protection skeleton checks passed.'
