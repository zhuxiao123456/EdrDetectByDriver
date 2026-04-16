#define POOL_ZERO_DOWN_LEVEL_SUPPORT
#include "PebMonitor.h"

namespace {
    const ULONG kRuleStorePoolTag = 'tSrR';
    const ULONG kRuleArrayPoolTag = 'rArR';

    enum RULE_STORE_BUCKET : ULONG {
        RuleStoreBucketExact = 0,
        RuleStoreBucketPrefix = 1,
        RuleStoreBucketSuffix = 2,
        RuleStoreBucketContains = 3,
        RuleStoreBucketInvalid = 0xFFFFFFFFUL
    };

    static LONG ReadInterlockedStoreRefCount(_In_ volatile LONG* value) {
        return InterlockedCompareExchange(value, 0, 0);
    }

    static BOOLEAN IsValidMatchType(_In_ ULONG matchType) {
        return
            matchType == REGISTRY_MATCH_TYPE_EXACT ||
            matchType == REGISTRY_MATCH_TYPE_PREFIX ||
            matchType == REGISTRY_MATCH_TYPE_SUFFIX ||
            matchType == REGISTRY_MATCH_TYPE_CONTAINS;
    }

    static ULONG PromoteBucketForMatchType(_In_ ULONG currentBucket, _In_ ULONG matchType) {
        ULONG candidateBucket = RuleStoreBucketInvalid;

        switch (matchType) {
        case REGISTRY_MATCH_TYPE_EXACT:
            candidateBucket = RuleStoreBucketExact;
            break;
        case REGISTRY_MATCH_TYPE_PREFIX:
            candidateBucket = RuleStoreBucketPrefix;
            break;
        case REGISTRY_MATCH_TYPE_SUFFIX:
            candidateBucket = RuleStoreBucketSuffix;
            break;
        case REGISTRY_MATCH_TYPE_CONTAINS:
            candidateBucket = RuleStoreBucketContains;
            break;
        default:
            return RuleStoreBucketInvalid;
        }

        return (candidateBucket > currentBucket) ? candidateBucket : currentBucket;
    }

    static ULONG ClassifyRegistryRuleBucket(_In_ const REGISTRY_RULE* rule) {
        if (rule == NULL) {
            return RuleStoreBucketInvalid;
        }

        ULONG bucket = RuleStoreBucketExact;

        if ((rule->MatchFlags & REGISTRY_MATCH_FLAG_PROCESS_NAME) != 0) {
            if (!IsValidMatchType(rule->ProcessNameMatchType)) {
                return RuleStoreBucketInvalid;
            }
            bucket = PromoteBucketForMatchType(bucket, rule->ProcessNameMatchType);
        }

        if ((rule->MatchFlags & REGISTRY_MATCH_FLAG_KEY_PATH) != 0) {
            if (!IsValidMatchType(rule->KeyPathMatchType)) {
                return RuleStoreBucketInvalid;
            }
            bucket = PromoteBucketForMatchType(bucket, rule->KeyPathMatchType);
        }

        if ((rule->MatchFlags & REGISTRY_MATCH_FLAG_INFO_CLASS) != 0) {
            if (!IsValidMatchType(rule->InfoClassMatchType)) {
                return RuleStoreBucketInvalid;
            }
            bucket = PromoteBucketForMatchType(bucket, rule->InfoClassMatchType);
        }

        if ((rule->MatchFlags & REGISTRY_MATCH_FLAG_VALUE_NAME) != 0) {
            if (!IsValidMatchType(rule->ValueNameMatchType)) {
                return RuleStoreBucketInvalid;
            }
            bucket = PromoteBucketForMatchType(bucket, rule->ValueNameMatchType);
        }

        if ((rule->MatchFlags & REGISTRY_MATCH_FLAG_VALUE_DATA) != 0) {
            if (!IsValidMatchType(rule->ValueDataMatchType)) {
                return RuleStoreBucketInvalid;
            }
            bucket = PromoteBucketForMatchType(bucket, rule->ValueDataMatchType);
        }

        return bucket;
    }

    static PREGISTRY_RULE AllocateRuleArray(_In_ ULONG ruleCount) {
        if (ruleCount == 0) {
            return NULL;
        }

        SIZE_T allocationSize = sizeof(REGISTRY_RULE) * (SIZE_T)ruleCount;
        PREGISTRY_RULE rules = (PREGISTRY_RULE)ExAllocatePoolZero(NonPagedPoolNx, allocationSize, kRuleArrayPoolTag);
        return rules;
    }

    static VOID FreeRuleArray(_In_opt_ PREGISTRY_RULE rules) {
        if (rules != NULL) {
            ExFreePoolWithTag(rules, kRuleArrayPoolTag);
        }
    }

    static VOID FreeRuleStore(_In_opt_ PRULE_STORE store) {
        if (store == NULL) {
            return;
        }

        FreeRuleArray(store->ExactRules);
        FreeRuleArray(store->PrefixRules);
        FreeRuleArray(store->SuffixRules);
        FreeRuleArray(store->ContainsRules);
        ExFreePoolWithTag(store, kRuleStorePoolTag);
    }

    static VOID WaitForRuleStoreReferencesToDrain(_In_opt_ PRULE_STORE store) {
        if (store == NULL) {
            return;
        }

        LARGE_INTEGER waitInterval = {};
        waitInterval.QuadPart = -10 * 1000;

        while (ReadInterlockedStoreRefCount(&store->ReferenceCount) != 0) {
            KeDelayExecutionThread(KernelMode, FALSE, &waitInterval);
        }
    }

    static NTSTATUS BuildRuleStoreFromRules(
        _In_reads_opt_(ruleCount) const REGISTRY_RULE* rules,
        _In_ ULONG ruleCount,
        _Outptr_result_maybenull_ PRULE_STORE* outStore) {
        if (outStore == NULL) {
            return STATUS_INVALID_PARAMETER;
        }

        *outStore = NULL;
        if (ruleCount == 0) {
            return STATUS_SUCCESS;
        }

        ULONG exactCount = 0;
        ULONG prefixCount = 0;
        ULONG suffixCount = 0;
        ULONG containsCount = 0;

        for (ULONG index = 0; index < ruleCount; ++index) {
            ULONG bucket = ClassifyRegistryRuleBucket(&rules[index]);
            switch (bucket) {
            case RuleStoreBucketExact:
                ++exactCount;
                break;
            case RuleStoreBucketPrefix:
                ++prefixCount;
                break;
            case RuleStoreBucketSuffix:
                ++suffixCount;
                break;
            case RuleStoreBucketContains:
                ++containsCount;
                break;
            default:
                return STATUS_INVALID_PARAMETER;
            }
        }

        if (containsCount > MAX_CONTAINS_RULES) {
            return STATUS_INVALID_PARAMETER;
        }

        PRULE_STORE store = (PRULE_STORE)ExAllocatePoolZero(NonPagedPoolNx, sizeof(RULE_STORE), kRuleStorePoolTag);
        if (store == NULL) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        store->TotalRuleCount = ruleCount;
        store->ExactRuleCount = exactCount;
        store->PrefixRuleCount = prefixCount;
        store->SuffixRuleCount = suffixCount;
        store->ContainsRuleCount = containsCount;
        store->ExactRules = AllocateRuleArray(exactCount);
        store->PrefixRules = AllocateRuleArray(prefixCount);
        store->SuffixRules = AllocateRuleArray(suffixCount);
        store->ContainsRules = AllocateRuleArray(containsCount);

        if ((exactCount != 0 && store->ExactRules == NULL) ||
            (prefixCount != 0 && store->PrefixRules == NULL) ||
            (suffixCount != 0 && store->SuffixRules == NULL) ||
            (containsCount != 0 && store->ContainsRules == NULL)) {
            FreeRuleStore(store);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        ULONG exactIndex = 0;
        ULONG prefixIndex = 0;
        ULONG suffixIndex = 0;
        ULONG containsIndex = 0;

        for (ULONG index = 0; index < ruleCount; ++index) {
            ULONG bucket = ClassifyRegistryRuleBucket(&rules[index]);
            switch (bucket) {
            case RuleStoreBucketExact:
                store->ExactRules[exactIndex++] = rules[index];
                break;
            case RuleStoreBucketPrefix:
                store->PrefixRules[prefixIndex++] = rules[index];
                break;
            case RuleStoreBucketSuffix:
                store->SuffixRules[suffixIndex++] = rules[index];
                break;
            case RuleStoreBucketContains:
                store->ContainsRules[containsIndex++] = rules[index];
                break;
            default:
                FreeRuleStore(store);
                return STATUS_INVALID_PARAMETER;
            }
        }

        *outStore = store;
        return STATUS_SUCCESS;
    }

    static ULONG CopyRuleStoreToFlatBuffer(
        _In_opt_ const RULE_STORE* store,
        _Out_writes_opt_(bufferCapacity) PREGISTRY_RULE buffer,
        _In_ ULONG bufferCapacity) {
        if (store == NULL || buffer == NULL || bufferCapacity == 0) {
            return 0;
        }

        ULONG copied = 0;

        auto copyBucket = [&](PREGISTRY_RULE source, ULONG count) {
            if (source == NULL || count == 0) {
                return;
            }

            RtlCopyMemory(&buffer[copied], source, sizeof(REGISTRY_RULE) * (SIZE_T)count);
            copied += count;
        };

        copyBucket(store->ExactRules, store->ExactRuleCount);
        copyBucket(store->PrefixRules, store->PrefixRuleCount);
        copyBucket(store->SuffixRules, store->SuffixRuleCount);
        copyBucket(store->ContainsRules, store->ContainsRuleCount);
        return copied;
    }
}

NTSTATUS InitializeRuleStoreState() {
    g_RegistryBlockRuleStore = NULL;
    g_RegistryAllowRuleStore = NULL;
    g_PolicyEpoch = 0;
    return STATUS_SUCCESS;
}

VOID CleanupRuleStoreState() {
    PRULE_STORE blockStore = NULL;
    PRULE_STORE allowStore = NULL;

    AcquireExclusiveResourceLock(&g_RuleStoreStateLock);
    blockStore = (PRULE_STORE)InterlockedExchangePointer((PVOID*)&g_RegistryBlockRuleStore, NULL);
    allowStore = (PRULE_STORE)InterlockedExchangePointer((PVOID*)&g_RegistryAllowRuleStore, NULL);
    ReleaseExclusiveResourceLock(&g_RuleStoreStateLock);

    WaitForRuleStoreReferencesToDrain(blockStore);
    WaitForRuleStoreReferencesToDrain(allowStore);
    FreeRuleStore(blockStore);
    FreeRuleStore(allowStore);
}

VOID AcquireRuleStoreSnapshot(_In_ PRULE_STORE volatile* currentStore, _Outptr_result_maybenull_ PPRULE_STORE snapshot) {
    if (snapshot == NULL) {
        return;
    }

    *snapshot = NULL;
    if (currentStore == NULL) {
        return;
    }

    AcquireSharedResourceLock(&g_RuleStoreStateLock);
    PRULE_STORE store = (PRULE_STORE)(*currentStore);
    if (store != NULL) {
        InterlockedIncrement(&store->ReferenceCount);
    }
    ReleaseSharedResourceLock(&g_RuleStoreStateLock);

    *snapshot = store;
}

VOID ReleaseRuleStoreSnapshot(_In_opt_ PRULE_STORE snapshot) {
    if (snapshot != NULL) {
        InterlockedDecrement(&snapshot->ReferenceCount);
    }
}

ULONG GetRuleStoreTotalRuleCount(_In_opt_ const RULE_STORE* store) {
    return (store != NULL) ? store->TotalRuleCount : 0;
}

NTSTATUS ApplyRegistryRuleUpdate(
    _Inout_ PRULE_STORE volatile* targetStore,
    _In_opt_ const REGISTRY_RULE* rule,
    _In_ BOOLEAN clearStore,
    _Out_opt_ PULONG newRuleCount) {
    if (targetStore == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!clearStore && rule == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    NTSTATUS status = STATUS_SUCCESS;
    PRULE_STORE oldStore = NULL;
    PRULE_STORE newStore = NULL;
    PREGISTRY_RULE flatRules = NULL;
    ULONG oldCount = 0;
    ULONG combinedRuleCount = 0;

    AcquireExclusiveResourceLock(&g_RuleStoreStateLock);

    oldStore = (PRULE_STORE)(*targetStore);
    oldCount = GetRuleStoreTotalRuleCount(oldStore);
    combinedRuleCount = clearStore ? 0 : oldCount + ((rule != NULL) ? 1 : 0);

    if (combinedRuleCount != 0) {
        flatRules = AllocateRuleArray(combinedRuleCount);
        if (flatRules == NULL) {
            status = STATUS_INSUFFICIENT_RESOURCES;
            goto Cleanup;
        }

        ULONG copiedRules = 0;
        if (!clearStore && oldStore != NULL) {
            copiedRules = CopyRuleStoreToFlatBuffer(oldStore, flatRules, combinedRuleCount);
        }

        if (!clearStore && rule != NULL) {
            flatRules[copiedRules] = *rule;
        }

        status = BuildRuleStoreFromRules(flatRules, combinedRuleCount, &newStore);
        if (!NT_SUCCESS(status)) {
            goto Cleanup;
        }
    }

    oldStore = (PRULE_STORE)InterlockedExchangePointer((PVOID*)targetStore, newStore);
    newStore = NULL;
    InterlockedIncrement((volatile LONG*)&g_PolicyEpoch);

    if (newRuleCount != NULL) {
        *newRuleCount = combinedRuleCount;
    }

Cleanup:
    ReleaseExclusiveResourceLock(&g_RuleStoreStateLock);

    FreeRuleArray(flatRules);
    FreeRuleStore(newStore);

    if (NT_SUCCESS(status) && oldStore != NULL) {
        WaitForRuleStoreReferencesToDrain(oldStore);
        FreeRuleStore(oldStore);
    }

    return status;
}
