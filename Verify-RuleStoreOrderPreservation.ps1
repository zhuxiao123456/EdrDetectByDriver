param(
    [string]$RepoRoot = $PSScriptRoot
)

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

foreach ($field in @(
    'ExactRuleOrdinals',
    'PrefixRuleOrdinals',
    'SuffixRuleOrdinals',
    'ContainsRuleOrdinals'
)) {
    if ($ruleStoreHeaderText -notmatch $field) {
        throw "RuleStore.h must track original ordinals via $field."
    }
}

if ($ruleStoreSourceText -notmatch 'CopyRuleStoreToFlatBuffer') {
    throw 'RuleStore.cpp must rebuild flat rule buffers from the bucketed store.'
}

if ($ruleStoreSourceText -notmatch 'ExactRuleOrdinals' -or
    $ruleStoreSourceText -notmatch 'PrefixRuleOrdinals' -or
    $ruleStoreSourceText -notmatch 'SuffixRuleOrdinals' -or
    $ruleStoreSourceText -notmatch 'ContainsRuleOrdinals') {
    throw 'RuleStore.cpp must preserve per-bucket original ordinals when flattening and rebuilding.'
}

if ($ruleStoreSourceText -notmatch 'matchedOrdinal') {
    throw 'RuleStore.cpp must surface the matched exact-rule ordinal.'
}

if ($monitorCallbacksText -notmatch 'bestOrdinal') {
    throw 'MonitorCallbacks.cpp must choose the earliest matching rule across all buckets.'
}

if ($monitorCallbacksText -notmatch 'MatchRegistryRuleArrayWithOrdinal') {
    throw 'MonitorCallbacks.cpp must evaluate bucket matches together with their original ordinals.'
}

Write-Host '[+] RuleStore order-preservation checks passed.'
