param(
    [string]$RepoRoot = $PSScriptRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ruleStoreSourcePath = Join-Path $RepoRoot 'RuleStore.cpp'
if (-not (Test-Path $ruleStoreSourcePath)) {
    throw "RuleStore.cpp not found: $ruleStoreSourcePath"
}

$ruleStoreSourceText = Get-Content $ruleStoreSourcePath -Raw
$match = [regex]::Match(
    $ruleStoreSourceText,
    'NTSTATUS ApplyRegistryRuleUpdate\([\s\S]*?\n\}',
    [System.Text.RegularExpressions.RegexOptions]::Singleline)

if (-not $match.Success) {
    throw 'ApplyRegistryRuleUpdate definition was not found in RuleStore.cpp.'
}

$functionText = $match.Value

if ($functionText -notmatch 'AcquireRuleStoreSnapshot') {
    throw 'ApplyRegistryRuleUpdate must snapshot the current rule store before rebuilding.'
}

if ($functionText -notmatch 'currentStore\s*!=\s*snapshot') {
    throw 'ApplyRegistryRuleUpdate must detect target store races before swapping.'
}

if ($functionText -notmatch 'retryUpdate\s*=\s*TRUE') {
    throw 'ApplyRegistryRuleUpdate must retry when the target store changes during rebuild.'
}

$buildIndex = $functionText.IndexOf('BuildRuleStoreFromRules')
$lockIndex = $functionText.IndexOf('AcquireExclusiveResourceLock')
if ($buildIndex -lt 0 -or $lockIndex -lt 0) {
    throw 'ApplyRegistryRuleUpdate must both build a new store and acquire the exclusive swap lock.'
}

if ($buildIndex -gt $lockIndex) {
    throw 'ApplyRegistryRuleUpdate must build replacement stores before taking the exclusive swap lock.'
}

Write-Host '[+] RuleStore atomic-update checks passed.'
