param(
    [string]$RepoRoot = $PSScriptRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$requiredFiles = @(
    (Join-Path $RepoRoot 'FileProtection.h'),
    (Join-Path $RepoRoot 'FileProtection.cpp'),
    (Join-Path $RepoRoot 'MonitorCallbacks.cpp')
)

foreach ($path in $requiredFiles) {
    if (-not (Test-Path $path)) {
        throw "Required file not found: $path"
    }
}

$headerText = Get-Content (Join-Path $RepoRoot 'FileProtection.h') -Raw
$fileProtectionText = Get-Content (Join-Path $RepoRoot 'FileProtection.cpp') -Raw
$monitorCallbacksText = Get-Content (Join-Path $RepoRoot 'MonitorCallbacks.cpp') -Raw

if ($headerText -notmatch 'FileProtectionPreSetInformation') {
    throw 'FileProtection.h must declare FileProtectionPreSetInformation.'
}

if ($monitorCallbacksText -notmatch 'IRP_MJ_SET_INFORMATION') {
    throw 'MonitorCallbacks.cpp must register an IRP_MJ_SET_INFORMATION minifilter callback.'
}

if ($monitorCallbacksText -notmatch 'FileProtectionPreSetInformation') {
    throw 'MonitorCallbacks.cpp must wire FileProtectionPreSetInformation into g_FilterOperationCallbacks.'
}

if ($fileProtectionText -notmatch 'Parameters\.SetFileInformation\.FileInformationClass') {
    throw 'FileProtection.cpp must inspect SetFileInformation.FileInformationClass.'
}

if ($fileProtectionText -notmatch 'FileDispositionInformation') {
    throw 'FileProtection.cpp must explicitly block FileDispositionInformation deletes.'
}

if ($fileProtectionText -notmatch 'FileRenameInformation') {
    throw 'FileProtection.cpp must explicitly block FileRenameInformation renames.'
}

if ($fileProtectionText -notmatch 'InfoClass') {
    throw 'FileProtection.cpp must stamp blocked set-information events with an InfoClass value.'
}

if ($fileProtectionText -notmatch 'STATUS_ACCESS_DENIED') {
    throw 'FileProtection.cpp must deny protected-file set-information requests with STATUS_ACCESS_DENIED.'
}

Write-Host '[+] File protection set-information checks passed.'
