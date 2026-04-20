param(
    [string]$RepoRoot = $PSScriptRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$pebMonitorPath = Join-Path $RepoRoot 'PebMonitor.cpp'
if (-not (Test-Path $pebMonitorPath)) {
    throw "PebMonitor.cpp not found: $pebMonitorPath"
}

$pebMonitorText = Get-Content $pebMonitorPath -Raw

$cleanupMatch = [regex]::Match(
    $pebMonitorText,
    'Cleanup:\s*[\s\S]*?return status;',
    [System.Text.RegularExpressions.RegexOptions]::Singleline)

if (-not $cleanupMatch.Success) {
    throw 'DriverEntry cleanup block was not found in PebMonitor.cpp.'
}

$cleanupText = $cleanupMatch.Value

if ($cleanupText -notmatch 'ExWaitForRundownProtectionRelease\s*\(\s*&g_RundownRef\s*\)') {
    throw 'DriverEntry cleanup must wait for rundown protection release before tearing down shared state.'
}

$waitIndex = $cleanupText.IndexOf('ExWaitForRundownProtectionRelease')
$ruleStoreIndex = $cleanupText.IndexOf('CleanupRuleStoreState')
$decisionCacheIndex = $cleanupText.IndexOf('CleanupDecisionCacheState')
$fastPathIndex = $cleanupText.IndexOf('CleanupFastPathState')

foreach ($pair in @(
    @{ Wait = $waitIndex; Target = $ruleStoreIndex; Name = 'CleanupRuleStoreState' },
    @{ Wait = $waitIndex; Target = $decisionCacheIndex; Name = 'CleanupDecisionCacheState' },
    @{ Wait = $waitIndex; Target = $fastPathIndex; Name = 'CleanupFastPathState' }
)) {
    if ($pair.Target -lt 0) {
        throw "DriverEntry cleanup is missing $($pair.Name)."
    }

    if ($pair.Wait -gt $pair.Target) {
        throw "DriverEntry cleanup must wait for rundown before $($pair.Name)."
    }
}

if ($pebMonitorText -notmatch 'ExInitializeRundownProtection\s*\(\s*&g_RundownRef\s*\)') {
    throw 'PebMonitor.cpp must initialize g_RundownRef before the cleanup verifier is meaningful.'
}

Write-Host '[+] Driver cleanup rundown checks passed.'
