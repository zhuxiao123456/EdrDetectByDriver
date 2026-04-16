param(
    [string]$RepoRoot = $PSScriptRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$requiredFiles = @(
    'FastPath.h',
    'FastPath.cpp',
    'DecisionCache.h',
    'DecisionCache.cpp',
    'PebMonitor.h',
    'PebMonitor.cpp',
    'MonitorCallbacks.cpp',
    'IoctlDispatch.cpp',
    'RuleStore.cpp'
)

foreach ($relativePath in $requiredFiles) {
    $fullPath = Join-Path $RepoRoot $relativePath
    if (-not (Test-Path $fullPath)) {
        throw "Required file not found: $fullPath"
    }
}

$fastPathHeaderText = Get-Content (Join-Path $RepoRoot 'FastPath.h') -Raw
$fastPathSourceText = Get-Content (Join-Path $RepoRoot 'FastPath.cpp') -Raw
$decisionCacheHeaderText = Get-Content (Join-Path $RepoRoot 'DecisionCache.h') -Raw
$decisionCacheSourceText = Get-Content (Join-Path $RepoRoot 'DecisionCache.cpp') -Raw
$pebMonitorHeaderText = Get-Content (Join-Path $RepoRoot 'PebMonitor.h') -Raw
$pebMonitorSourceText = Get-Content (Join-Path $RepoRoot 'PebMonitor.cpp') -Raw
$monitorCallbacksText = Get-Content (Join-Path $RepoRoot 'MonitorCallbacks.cpp') -Raw
$ioctlDispatchText = Get-Content (Join-Path $RepoRoot 'IoctlDispatch.cpp') -Raw
$ruleStoreSourceText = Get-Content (Join-Path $RepoRoot 'RuleStore.cpp') -Raw

if ($fastPathHeaderText -notmatch 'FASTPATH_TRUSTED_ENTRY') {
    throw 'FastPath.h must define FASTPATH_TRUSTED_ENTRY.'
}

if ($fastPathHeaderText -notmatch 'EvaluateFastPathProcessCreateAllow') {
    throw 'FastPath.h must declare EvaluateFastPathProcessCreateAllow.'
}

if ($fastPathHeaderText -notmatch 'RemoveFastPathTrustedProcess') {
    throw 'FastPath.h must declare RemoveFastPathTrustedProcess.'
}

if ($decisionCacheHeaderText -notmatch 'DECISION_CACHE_KEY') {
    throw 'DecisionCache.h must define DECISION_CACHE_KEY.'
}

if ($decisionCacheHeaderText -notmatch 'PolicyEpoch') {
    throw 'DECISION_CACHE_KEY must contain PolicyEpoch.'
}

if ($decisionCacheHeaderText -notmatch 'CreateTime') {
    throw 'DECISION_CACHE_KEY must contain CreateTime.'
}

if ($decisionCacheHeaderText -notmatch 'FlushDecisionCacheForProcess') {
    throw 'DecisionCache.h must declare FlushDecisionCacheForProcess.'
}

if ($decisionCacheSourceText -notmatch 'RememberAllowedProcessCreateDecision') {
    throw 'DecisionCache.cpp must implement RememberAllowedProcessCreateDecision.'
}

if ($pebMonitorHeaderText -notmatch 'g_FastPathHitCount') {
    throw 'PebMonitor.h must expose g_FastPathHitCount.'
}

if ($pebMonitorHeaderText -notmatch 'g_DecisionCacheHitCount') {
    throw 'PebMonitor.h must expose g_DecisionCacheHitCount.'
}

if ($pebMonitorHeaderText -notmatch 'g_SlowPathCount') {
    throw 'PebMonitor.h must expose g_SlowPathCount.'
}

if ($pebMonitorSourceText -notmatch 'InitializeFastPathState') {
    throw 'PebMonitor.cpp must initialize fast path state.'
}

if ($pebMonitorSourceText -notmatch 'InitializeDecisionCacheState') {
    throw 'PebMonitor.cpp must initialize decision cache state.'
}

if ($pebMonitorSourceText -notmatch 'RegisterFastPathTrustedProcess') {
    throw 'PebMonitor.cpp must register the connected user-mode client into the fast path state.'
}

if ($monitorCallbacksText -notmatch 'EvaluateFastPathProcessCreateAllow') {
    throw 'MonitorCallbacks.cpp must query fast path allow before slow path.'
}

if ($monitorCallbacksText -notmatch 'TryGetDecisionCacheAllow') {
    throw 'MonitorCallbacks.cpp must query decision cache allow before slow path.'
}

if ($monitorCallbacksText -notmatch 'RememberAllowedProcessCreateDecision') {
    throw 'MonitorCallbacks.cpp must cache slow-path allow decisions.'
}

if ($monitorCallbacksText -notmatch 'FlushDecisionCacheForProcess') {
    throw 'MonitorCallbacks.cpp must flush decision cache entries on process exit.'
}

if ($monitorCallbacksText -notmatch 'RemoveFastPathTrustedProcess') {
    throw 'MonitorCallbacks.cpp must remove fast path trusted entries on process exit.'
}

if ($ruleStoreSourceText -notmatch 'FlushDecisionCache') {
    throw 'RuleStore.cpp must flush the decision cache after rule updates.'
}

if ($ioctlDispatchText -match 'runtimeStatus->FastPathHitCount\s*=\s*0') {
    throw 'IoctlDispatch.cpp must not hardcode FastPathHitCount to zero.'
}

if ($ioctlDispatchText -match 'runtimeStatus->CacheHitCount\s*=\s*0') {
    throw 'IoctlDispatch.cpp must not hardcode CacheHitCount to zero.'
}

if ($ioctlDispatchText -match 'runtimeStatus->SlowPathCount\s*=\s*runtimeStatus->ProcessVerdictRequestCount') {
    throw 'IoctlDispatch.cpp must populate SlowPathCount from dedicated counter state.'
}

Write-Host '[+] Fast path / decision cache skeleton checks passed.'
