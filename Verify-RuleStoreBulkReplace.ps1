param(
    [string]$RepoRoot = $PSScriptRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$sharedHeaderPath = Join-Path $RepoRoot 'Common\PebMonitorShared.h'
$ruleStoreHeaderPath = Join-Path $RepoRoot 'RuleStore.h'
$ruleStoreSourcePath = Join-Path $RepoRoot 'RuleStore.cpp'
$ioctlDispatchPath = Join-Path $RepoRoot 'IoctlDispatch.cpp'

foreach ($path in @($sharedHeaderPath, $ruleStoreHeaderPath, $ruleStoreSourcePath, $ioctlDispatchPath)) {
    if (-not (Test-Path $path)) {
        throw "Required file not found: $path"
    }
}

$sharedHeaderText = Get-Content $sharedHeaderPath -Raw
$ruleStoreHeaderText = Get-Content $ruleStoreHeaderPath -Raw
$ruleStoreSourceText = Get-Content $ruleStoreSourcePath -Raw
$ioctlDispatchText = Get-Content $ioctlDispatchPath -Raw

if ($sharedHeaderText -notmatch 'IOCTL_REPLACE_REGISTRY_RULES') {
    throw 'PebMonitorShared.h must define IOCTL_REPLACE_REGISTRY_RULES.'
}

if ($sharedHeaderText -notmatch 'IOCTL_REPLACE_REGISTRY_ALLOW_RULES') {
    throw 'PebMonitorShared.h must define IOCTL_REPLACE_REGISTRY_ALLOW_RULES.'
}

if ($sharedHeaderText -notmatch 'REGISTRY_RULE_BATCH_UPDATE') {
    throw 'PebMonitorShared.h must define REGISTRY_RULE_BATCH_UPDATE.'
}

if ($ruleStoreHeaderText -notmatch 'ReplaceRegistryRuleStore') {
    throw 'RuleStore.h must declare ReplaceRegistryRuleStore.'
}

if ($ruleStoreSourceText -notmatch 'ReplaceRegistryRuleStore') {
    throw 'RuleStore.cpp must implement ReplaceRegistryRuleStore.'
}

if ($ioctlDispatchText -notmatch 'IOCTL_REPLACE_REGISTRY_RULES') {
    throw 'IoctlDispatch.cpp must handle IOCTL_REPLACE_REGISTRY_RULES.'
}

if ($ioctlDispatchText -notmatch 'IOCTL_REPLACE_REGISTRY_ALLOW_RULES') {
    throw 'IoctlDispatch.cpp must handle IOCTL_REPLACE_REGISTRY_ALLOW_RULES.'
}

if ($ioctlDispatchText -notmatch 'ReplaceRegistryRuleStore') {
    throw 'IoctlDispatch.cpp must route bulk updates through ReplaceRegistryRuleStore.'
}

Write-Host '[+] RuleStore bulk-replace checks passed.'
