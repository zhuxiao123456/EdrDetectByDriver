#pragma once

#include <fltKernel.h>

#include "Shared.h"

#define MAX_CONTAINS_RULES 16UL

typedef struct _RULE_STORE_EXACT_KEY {
    ULONG Operation;
    ULONG MatchFlags;
    WCHAR ProcessName[MAX_RULE_LENGTH];
    WCHAR KeyPath[MAX_REG_PATH_LENGTH];
    WCHAR InfoClass[MAX_RULE_LENGTH];
    WCHAR ValueName[MAX_RULE_LENGTH];
    WCHAR ValueData[MAX_RULE_LENGTH];
} RULE_STORE_EXACT_KEY, *PRULE_STORE_EXACT_KEY;

typedef struct _RULE_STORE_EXACT_NODE {
    RULE_STORE_EXACT_KEY Key;
    ULONG RuleRefCount;
    PREGISTRY_RULE* RuleRefs;
} RULE_STORE_EXACT_NODE, *PRULE_STORE_EXACT_NODE;

typedef struct _RULE_STORE {
    volatile LONG ReferenceCount;
    ULONG TotalRuleCount;
    ULONG ExactRuleCount;
    ULONG ExactRuleNodeCount;
    ULONG PrefixRuleCount;
    ULONG SuffixRuleCount;
    ULONG ContainsRuleCount;
    BOOLEAN ExactRuleTableInitialized;
    RTL_AVL_TABLE ExactRuleTable;
    PREGISTRY_RULE ExactRules;
    PREGISTRY_RULE PrefixRules;
    PREGISTRY_RULE SuffixRules;
    PREGISTRY_RULE ContainsRules;
} RULE_STORE, *PRULE_STORE;
typedef PRULE_STORE* PPRULE_STORE;

NTSTATUS InitializeRuleStoreState();
VOID CleanupRuleStoreState();
VOID AcquireRuleStoreSnapshot(_In_ PRULE_STORE volatile* currentStore, _Outptr_result_maybenull_ PPRULE_STORE snapshot);
VOID ReleaseRuleStoreSnapshot(_In_opt_ PRULE_STORE snapshot);
ULONG GetRuleStoreTotalRuleCount(_In_opt_ const RULE_STORE* store);
const REGISTRY_RULE* FindExactRegistryRuleMatch(
    _In_opt_ const RULE_STORE* store,
    _In_ ULONG operation,
    _In_opt_z_ PCWSTR processName,
    _In_opt_z_ PCWSTR keyPath,
    _In_opt_z_ PCWSTR infoClass,
    _In_opt_z_ PCWSTR valueName,
    _In_opt_z_ PCWSTR valueData);
NTSTATUS ReplaceRegistryRuleStore(
    _Inout_ PRULE_STORE volatile* targetStore,
    _In_reads_opt_(ruleCount) const REGISTRY_RULE* rules,
    _In_ ULONG ruleCount,
    _Out_opt_ PULONG newRuleCount);
NTSTATUS ApplyRegistryRuleUpdate(
    _Inout_ PRULE_STORE volatile* targetStore,
    _In_opt_ const REGISTRY_RULE* rule,
    _In_ BOOLEAN clearStore,
    _Out_opt_ PULONG newRuleCount);
