$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$ruleManagerHeader = Join-Path $repoRoot 'RuleManager.h'
$ruleManagerSource = Join-Path $repoRoot 'RuleManager.cpp'
$hostGuardSource = Join-Path $repoRoot 'HostGuard.cpp'

function Assert-Contains {
    param(
        [string]$Path,
        [string]$Pattern,
        [string]$Message
    )

    if (-not (Select-String -Path $Path -Pattern $Pattern -Quiet)) {
        throw $Message
    }
}

Assert-Contains $ruleManagerHeader 'RegistryRuleClassStats' 'Missing RegistryRuleClassStats in RuleManager.h'
Assert-Contains $ruleManagerHeader 'MAX_REGISTRY_CONTAINS_RULES' 'Missing MAX_REGISTRY_CONTAINS_RULES limit in RuleManager.h'
Assert-Contains $ruleManagerHeader 'registryRuleClassStats' 'Missing registryRuleClassStats in RuleConfiguration'
Assert-Contains $ruleManagerHeader 'registryAllowRuleClassStats' 'Missing registryAllowRuleClassStats in RuleConfiguration'

Assert-Contains $ruleManagerSource 'ClassifyRegistryRuleValueMatchType' 'Missing wildcard match-type classifier in RuleManager.cpp'
Assert-Contains $ruleManagerSource 'CountCompiledRulesByMatchType' 'Missing compiled rule match-type counter in RuleManager.cpp'
Assert-Contains $ruleManagerSource 'contains match count exceeds limit' 'Missing contains limit enforcement in RuleManager.cpp'

if (Select-String -Path $ruleManagerSource -Pattern 'registry_rules exceed kernel capacity' -Quiet) {
    throw 'Legacy MAX_REGISTRY_RULE_COUNT hard cap is still enforced in RuleManager.cpp'
}

Assert-Contains $hostGuardSource 'LogRegistryRuleClassStats' 'Missing registry classification logging in HostGuard.cpp'

Write-Host '[+] Registry rule classification checks passed.'
