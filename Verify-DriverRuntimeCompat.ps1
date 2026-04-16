param(
    [string]$RepoRoot = $PSScriptRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$pebMonitorPath = Join-Path $RepoRoot 'PebMonitor.cpp'
$apiCompatHeaderPath = Join-Path $RepoRoot 'ApiCompatibility.h'
$apiCompatSourcePath = Join-Path $RepoRoot 'ApiCompatibility.cpp'

if (-not (Test-Path $pebMonitorPath)) {
    throw "PebMonitor.cpp not found: $pebMonitorPath"
}
if (-not (Test-Path $apiCompatHeaderPath)) {
    throw "ApiCompatibility.h not found: $apiCompatHeaderPath"
}
if (-not (Test-Path $apiCompatSourcePath)) {
    throw "ApiCompatibility.cpp not found: $apiCompatSourcePath"
}

$pebMonitorText = Get-Content $pebMonitorPath -Raw
$apiCompatHeaderText = Get-Content $apiCompatHeaderPath -Raw
$apiCompatSourceText = Get-Content $apiCompatSourcePath -Raw

if ($pebMonitorText -match 'ExInitializeDriverRuntime\s*\(') {
    throw 'Direct ExInitializeDriverRuntime call remains in PebMonitor.cpp.'
}

if ($apiCompatHeaderText -notmatch 'PFN_EX_INITIALIZE_DRIVER_RUNTIME') {
    throw 'PFN_EX_INITIALIZE_DRIVER_RUNTIME is missing from ApiCompatibility.h.'
}

if ($apiCompatHeaderText -notmatch 'TryInitializeDriverRuntimeCompat') {
    throw 'TryInitializeDriverRuntimeCompat declaration is missing from ApiCompatibility.h.'
}

if ($apiCompatSourceText -notmatch 'MmGetSystemRoutineAddress') {
    throw 'ApiCompatibility.cpp does not appear to use MmGetSystemRoutineAddress.'
}

if ($apiCompatSourceText -notmatch 'ExInitializeDriverRuntime') {
    throw 'ApiCompatibility.cpp does not resolve ExInitializeDriverRuntime dynamically.'
}

Write-Host '[+] Driver runtime compatibility checks passed.'
