param(
    [string]$RepoRoot = $PSScriptRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ruleStoreHeaderPath = Join-Path $RepoRoot 'RuleStore.h'
$ruleStoreSourcePath = Join-Path $RepoRoot 'RuleStore.cpp'
$pebMonitorHeaderPath = Join-Path $RepoRoot 'PebMonitor.h'
$ioctlDispatchPath = Join-Path $RepoRoot 'IoctlDispatch.cpp'
$monitorCallbacksPath = Join-Path $RepoRoot 'MonitorCallbacks.cpp'

foreach ($path in @(
    $ruleStoreHeaderPath,
    $ruleStoreSourcePath,
    $pebMonitorHeaderPath,
    $ioctlDispatchPath,
    $monitorCallbacksPath
)) {
    if (-not (Test-Path $path)) {
        throw "Required file not found: $path"
    }
}

$ruleStoreHeaderText = Get-Content $ruleStoreHeaderPath -Raw
$ruleStoreSourceText = Get-Content $ruleStoreSourcePath -Raw
$pebMonitorHeaderText = Get-Content $pebMonitorHeaderPath -Raw
$ioctlDispatchText = Get-Content $ioctlDispatchPath -Raw
$monitorCallbacksText = Get-Content $monitorCallbacksPath -Raw

if ($ruleStoreHeaderText -notmatch 'MAX_CONTAINS_RULES') {
    throw 'MAX_CONTAINS_RULES is missing from RuleStore.h.'
}

if ($ruleStoreHeaderText -notmatch 'typedef struct _RULE_STORE') {
    throw 'RULE_STORE definition is missing from RuleStore.h.'
}

if ($ruleStoreHeaderText -notmatch 'ContainsRuleCount') {
    throw 'RULE_STORE must track ContainsRuleCount.'
}

if ($ruleStoreHeaderText -notmatch 'AcquireRuleStoreSnapshot') {
    throw 'AcquireRuleStoreSnapshot declaration is missing from RuleStore.h.'
}

if ($ruleStoreHeaderText -notmatch 'ApplyRegistryRuleUpdate') {
    throw 'ApplyRegistryRuleUpdate declaration is missing from RuleStore.h.'
}

if ($ruleStoreSourceText -notmatch 'MAX_CONTAINS_RULES') {
    throw 'RuleStore.cpp must enforce MAX_CONTAINS_RULES.'
}

if ($ruleStoreSourceText -notmatch 'InterlockedExchangePointer') {
    throw 'RuleStore.cpp must use InterlockedExchangePointer for atomic store swaps.'
}

if ($ruleStoreSourceText -notmatch 'WaitForRuleStoreReferencesToDrain') {
    throw 'RuleStore.cpp must wait for old store references to drain before free.'
}

if ($pebMonitorHeaderText -match 'g_RegistryRules\s*\[') {
    throw 'PebMonitor.h must no longer expose g_RegistryRules[] directly.'
}

if ($ioctlDispatchText -match 'g_RegistryRules\[') {
    throw 'IoctlDispatch.cpp must no longer write g_RegistryRules[] directly.'
}

if ($monitorCallbacksText -match 'g_RegistryRules\[') {
    throw 'MonitorCallbacks.cpp must no longer read g_RegistryRules[] directly.'
}

if ($monitorCallbacksText -notmatch 'AcquireRuleStoreSnapshot') {
    throw 'MonitorCallbacks.cpp must acquire rule store snapshots before matching.'
}

Write-Host '[+] RuleStore refactor checks passed.'
