param(
    [string]$RepoRoot = $PSScriptRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$requiredFiles = @(
    (Join-Path $RepoRoot 'FileProtection.h'),
    (Join-Path $RepoRoot 'FileProtection.cpp'),
    (Join-Path $RepoRoot 'PebMonitor.cpp')
)

foreach ($path in $requiredFiles) {
    if (-not (Test-Path $path)) {
        throw "Required file not found: $path"
    }
}

$headerText = Get-Content (Join-Path $RepoRoot 'FileProtection.h') -Raw
$sourceText = Get-Content (Join-Path $RepoRoot 'FileProtection.cpp') -Raw
$pebMonitorText = Get-Content (Join-Path $RepoRoot 'PebMonitor.cpp') -Raw

if ($headerText -notmatch 'CanonicalProtectedDriverPath') {
    throw 'FileProtection.h must store a canonical protected-driver path in FILE_PROTECTION_STATE.'
}

if ($sourceText -notmatch '\\\\SystemRoot\\\\System32\\\\drivers\\\\DriverModule\.sys') {
    throw 'FileProtection.cpp must resolve the protected driver through the \\SystemRoot path.'
}

if ($sourceText -notmatch 'FltCreateFileEx2|FltCreateFileEx') {
    throw 'FileProtection.cpp must open the protected driver during initialization to bind a canonical target.'
}

if ($sourceText -notmatch 'FltGetFileNameInformationUnsafe') {
    throw 'FileProtection.cpp must capture a canonical normalized file name through FltGetFileNameInformationUnsafe.'
}

if ($sourceText -notmatch 'RtlEqualUnicodeString\(') {
    throw 'FileProtection.cpp must compare protected targets with an exact RtlEqualUnicodeString check.'
}

$registerIndex = $pebMonitorText.IndexOf('FltRegisterFilter')
$initIndex = $pebMonitorText.IndexOf('InitializeFileProtectionState')

if ($registerIndex -lt 0) {
    throw 'PebMonitor.cpp must call FltRegisterFilter.'
}

if ($initIndex -lt 0) {
    throw 'PebMonitor.cpp must initialize file protection state.'
}

if ($initIndex -lt $registerIndex) {
    throw 'PebMonitor.cpp must initialize file protection state only after FltRegisterFilter succeeds.'
}

Write-Host '[+] File protection canonical-target checks passed.'
