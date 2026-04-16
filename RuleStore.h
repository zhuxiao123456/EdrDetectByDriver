#pragma once

#include <fltKernel.h>

#include "Shared.h"

#define MAX_CONTAINS_RULES 16UL

typedef struct _RULE_STORE {
    volatile LONG ReferenceCount;
    ULONG TotalRuleCount;
    ULONG ExactRuleCount;
    ULONG PrefixRuleCount;
    ULONG SuffixRuleCount;
    ULONG ContainsRuleCount;
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
NTSTATUS ApplyRegistryRuleUpdate(
    _Inout_ PRULE_STORE volatile* targetStore,
    _In_opt_ const REGISTRY_RULE* rule,
    _In_ BOOLEAN clearStore,
    _Out_opt_ PULONG newRuleCount);
