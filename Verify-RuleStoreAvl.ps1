param(
    [string]$RepoRoot = $PSScriptRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ruleStoreHeaderPath = Join-Path $RepoRoot 'RuleStore.h'
$ruleStoreSourcePath = Join-Path $RepoRoot 'RuleStore.cpp'
$monitorCallbacksPath = Join-Path $RepoRoot 'MonitorCallbacks.cpp'

foreach ($path in @($ruleStoreHeaderPath, $ruleStoreSourcePath, $monitorCallbacksPath)) {
    if (-not (Test-Path $path)) {
        throw "Required file not found: $path"
    }
}

$ruleStoreHeaderText = Get-Content $ruleStoreHeaderPath -Raw
$ruleStoreSourceText = Get-Content $ruleStoreSourcePath -Raw
$monitorCallbacksText = Get-Content $monitorCallbacksPath -Raw

if ($ruleStoreHeaderText -notmatch 'RULE_STORE_EXACT_KEY') {
    throw 'RuleStore.h must define RULE_STORE_EXACT_KEY.'
}

if ($ruleStoreHeaderText -notmatch 'RTL_AVL_TABLE\s+ExactRuleTable') {
    throw 'RuleStore.h must expose an RTL_AVL_TABLE exact-rule index.'
}

if ($ruleStoreHeaderText -notmatch 'FindExactRegistryRuleMatch') {
    throw 'RuleStore.h must declare FindExactRegistryRuleMatch.'
}

if ($ruleStoreSourceText -notmatch 'RtlInitializeGenericTableAvl') {
    throw 'RuleStore.cpp must initialize an AVL table for exact rules.'
}

if ($ruleStoreSourceText -notmatch 'RtlInsertElementGenericTableAvl') {
    throw 'RuleStore.cpp must populate the exact-rule AVL table.'
}

if ($ruleStoreSourceText -notmatch 'RtlLookupElementGenericTableAvl') {
    throw 'RuleStore.cpp must look up exact rules through the AVL table.'
}

if ($monitorCallbacksText -notmatch 'FindExactRegistryRuleMatch') {
    throw 'MonitorCallbacks.cpp must query the exact-rule AVL helper before fallback scans.'
}

Write-Host '[+] RuleStore AVL checks passed.'
