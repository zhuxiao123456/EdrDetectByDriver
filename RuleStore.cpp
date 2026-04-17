#define POOL_ZERO_DOWN_LEVEL_SUPPORT
#include "PebMonitor.h"

namespace {
    const ULONG kRuleStorePoolTag = 'tSrR';
    const ULONG kRuleArrayPoolTag = 'rArR';
    const ULONG kExactRuleNodePoolTag = 'nExR';
    const ULONG kExactRuleRefPoolTag = 'fExR';

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

    static BOOLEAN IsNullOrEmptyWide(_In_opt_z_ PCWSTR text) {
        return text == NULL || text[0] == L'\0';
    }

    static BOOLEAN TryParseUnsignedInteger(_In_opt_z_ PCWSTR text, _Out_ ULONGLONG* value) {
        if (text == NULL || value == NULL) {
            return FALSE;
        }

        while (*text == L' ' || *text == L'\t') {
            ++text;
        }

        if (*text == L'\0') {
            return FALSE;
        }

        ULONGLONG result = 0;
        int base = 10;
        if (text[0] == L'0' && (text[1] == L'x' || text[1] == L'X')) {
            base = 16;
            text += 2;
        }

        if (*text == L'\0') {
            return FALSE;
        }

        while (*text != L'\0') {
            WCHAR ch = *text++;
            if (ch == L' ' || ch == L'\t') {
                break;
            }

            unsigned int digit = 0xFFFFFFFFU;
            if (ch >= L'0' && ch <= L'9') {
                digit = ch - L'0';
            }
            else if (base == 16 && ch >= L'a' && ch <= L'f') {
                digit = 10 + (ch - L'a');
            }
            else if (base == 16 && ch >= L'A' && ch <= L'F') {
                digit = 10 + (ch - L'A');
            }
            else {
                return FALSE;
            }

            if (digit >= (unsigned int)base) {
                return FALSE;
            }

            const ULONGLONG maxUlonglong = ~((ULONGLONG)0);
            ULONGLONG maxBeforeMulAdd =
                (maxUlonglong - (ULONGLONG)digit) / (ULONGLONG)base;
            if (result > maxBeforeMulAdd) {
                return FALSE;
            }

            result = (result * base) + digit;
        }

        *value = result;
        return TRUE;
    }

    static RTL_GENERIC_COMPARE_RESULTS CompareUnsignedLongField(_In_ ULONG left, _In_ ULONG right) {
        if (left < right) {
            return GenericLessThan;
        }

        if (left > right) {
            return GenericGreaterThan;
        }

        return GenericEqual;
    }

    static RTL_GENERIC_COMPARE_RESULTS CompareInsensitiveTextOrder(
        _In_opt_z_ PCWSTR left,
        _In_opt_z_ PCWSTR right) {
        const WCHAR* leftText = (left != NULL) ? left : L"";
        const WCHAR* rightText = (right != NULL) ? right : L"";

        while (*leftText != L'\0' && *rightText != L'\0') {
            WCHAR leftCh = RtlDowncaseUnicodeChar(*leftText);
            WCHAR rightCh = RtlDowncaseUnicodeChar(*rightText);
            if (leftCh < rightCh) {
                return GenericLessThan;
            }
            if (leftCh > rightCh) {
                return GenericGreaterThan;
            }

            ++leftText;
            ++rightText;
        }

        if (*leftText == L'\0' && *rightText == L'\0') {
            return GenericEqual;
        }

        return (*leftText == L'\0') ? GenericLessThan : GenericGreaterThan;
    }

    static RTL_GENERIC_COMPARE_RESULTS CompareExactTextField(
        _In_opt_z_ PCWSTR left,
        _In_opt_z_ PCWSTR right) {
        ULONGLONG leftNumericValue = 0;
        ULONGLONG rightNumericValue = 0;
        BOOLEAN leftIsNumeric = TryParseUnsignedInteger(left, &leftNumericValue);
        BOOLEAN rightIsNumeric = TryParseUnsignedInteger(right, &rightNumericValue);

        if (leftIsNumeric && rightIsNumeric) {
            if (leftNumericValue < rightNumericValue) {
                return GenericLessThan;
            }
            if (leftNumericValue > rightNumericValue) {
                return GenericGreaterThan;
            }
            return GenericEqual;
        }

        if (leftIsNumeric != rightIsNumeric) {
            return leftIsNumeric ? GenericLessThan : GenericGreaterThan;
        }

        return CompareInsensitiveTextOrder(left, right);
    }

    static VOID CopyTextToFixedBuffer(
        _Out_writes_(bufferLength) WCHAR* destination,
        _In_ SIZE_T bufferLength,
        _In_opt_z_ PCWSTR source) {
        if (destination == NULL || bufferLength == 0) {
            return;
        }

        destination[0] = L'\0';
        if (IsNullOrEmptyWide(source)) {
            return;
        }

        NTSTATUS status = RtlStringCchCopyW(destination, bufferLength, source);
        if (!NT_SUCCESS(status)) {
            destination[bufferLength - 1] = L'\0';
        }
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

    static ULONG NormalizeExactMatchFlags(_In_ const REGISTRY_RULE* rule) {
        if (rule == NULL) {
            return 0;
        }

        ULONG normalizedFlags = 0;

        if ((rule->MatchFlags & REGISTRY_MATCH_FLAG_PROCESS_NAME) != 0 &&
            !IsNullOrEmptyWide(rule->ProcessName)) {
            normalizedFlags |= REGISTRY_MATCH_FLAG_PROCESS_NAME;
        }

        if ((rule->MatchFlags & REGISTRY_MATCH_FLAG_KEY_PATH) != 0 &&
            !IsNullOrEmptyWide(rule->KeyPath)) {
            normalizedFlags |= REGISTRY_MATCH_FLAG_KEY_PATH;
        }

        if ((rule->MatchFlags & REGISTRY_MATCH_FLAG_INFO_CLASS) != 0 &&
            !IsNullOrEmptyWide(rule->InfoClass)) {
            normalizedFlags |= REGISTRY_MATCH_FLAG_INFO_CLASS;
        }

        if ((rule->MatchFlags & REGISTRY_MATCH_FLAG_VALUE_NAME) != 0 &&
            !IsNullOrEmptyWide(rule->ValueName)) {
            normalizedFlags |= REGISTRY_MATCH_FLAG_VALUE_NAME;
        }

        if ((rule->MatchFlags & REGISTRY_MATCH_FLAG_VALUE_DATA) != 0 &&
            !IsNullOrEmptyWide(rule->ValueData)) {
            normalizedFlags |= REGISTRY_MATCH_FLAG_VALUE_DATA;
        }

        return normalizedFlags;
    }

    static VOID BuildExactRuleKeyFromRule(
        _In_ const REGISTRY_RULE* rule,
        _Out_ PRULE_STORE_EXACT_KEY key) {
        RtlZeroMemory(key, sizeof(*key));
        if (rule == NULL) {
            return;
        }

        key->Operation = rule->Operation;
        key->MatchFlags = NormalizeExactMatchFlags(rule);

        if ((key->MatchFlags & REGISTRY_MATCH_FLAG_PROCESS_NAME) != 0) {
            CopyTextToFixedBuffer(key->ProcessName, RTL_NUMBER_OF(key->ProcessName), rule->ProcessName);
        }

        if ((key->MatchFlags & REGISTRY_MATCH_FLAG_KEY_PATH) != 0) {
            CopyTextToFixedBuffer(key->KeyPath, RTL_NUMBER_OF(key->KeyPath), rule->KeyPath);
        }

        if ((key->MatchFlags & REGISTRY_MATCH_FLAG_INFO_CLASS) != 0) {
            CopyTextToFixedBuffer(key->InfoClass, RTL_NUMBER_OF(key->InfoClass), rule->InfoClass);
        }

        if ((key->MatchFlags & REGISTRY_MATCH_FLAG_VALUE_NAME) != 0) {
            CopyTextToFixedBuffer(key->ValueName, RTL_NUMBER_OF(key->ValueName), rule->ValueName);
        }

        if ((key->MatchFlags & REGISTRY_MATCH_FLAG_VALUE_DATA) != 0) {
            CopyTextToFixedBuffer(key->ValueData, RTL_NUMBER_OF(key->ValueData), rule->ValueData);
        }
    }

    static VOID BuildExactLookupKey(
        _In_ ULONG operation,
        _In_ ULONG matchFlags,
        _In_opt_z_ PCWSTR processName,
        _In_opt_z_ PCWSTR keyPath,
        _In_opt_z_ PCWSTR infoClass,
        _In_opt_z_ PCWSTR valueName,
        _In_opt_z_ PCWSTR valueData,
        _Out_ PRULE_STORE_EXACT_KEY key) {
        RtlZeroMemory(key, sizeof(*key));

        key->Operation = operation;
        key->MatchFlags = matchFlags;

        if ((matchFlags & REGISTRY_MATCH_FLAG_PROCESS_NAME) != 0) {
            CopyTextToFixedBuffer(key->ProcessName, RTL_NUMBER_OF(key->ProcessName), processName);
        }

        if ((matchFlags & REGISTRY_MATCH_FLAG_KEY_PATH) != 0) {
            CopyTextToFixedBuffer(key->KeyPath, RTL_NUMBER_OF(key->KeyPath), keyPath);
        }

        if ((matchFlags & REGISTRY_MATCH_FLAG_INFO_CLASS) != 0) {
            CopyTextToFixedBuffer(key->InfoClass, RTL_NUMBER_OF(key->InfoClass), infoClass);
        }

        if ((matchFlags & REGISTRY_MATCH_FLAG_VALUE_NAME) != 0) {
            CopyTextToFixedBuffer(key->ValueName, RTL_NUMBER_OF(key->ValueName), valueName);
        }

        if ((matchFlags & REGISTRY_MATCH_FLAG_VALUE_DATA) != 0) {
            CopyTextToFixedBuffer(key->ValueData, RTL_NUMBER_OF(key->ValueData), valueData);
        }
    }

    static RTL_GENERIC_COMPARE_RESULTS CompareExactRuleKey(
        _In_ const RULE_STORE_EXACT_KEY* left,
        _In_ const RULE_STORE_EXACT_KEY* right) {
        RTL_GENERIC_COMPARE_RESULTS compareResult = CompareUnsignedLongField(left->Operation, right->Operation);
        if (compareResult != GenericEqual) {
            return compareResult;
        }

        compareResult = CompareUnsignedLongField(left->MatchFlags, right->MatchFlags);
        if (compareResult != GenericEqual) {
            return compareResult;
        }

        compareResult = CompareExactTextField(left->ProcessName, right->ProcessName);
        if (compareResult != GenericEqual) {
            return compareResult;
        }

        compareResult = CompareExactTextField(left->KeyPath, right->KeyPath);
        if (compareResult != GenericEqual) {
            return compareResult;
        }

        compareResult = CompareExactTextField(left->InfoClass, right->InfoClass);
        if (compareResult != GenericEqual) {
            return compareResult;
        }

        compareResult = CompareExactTextField(left->ValueName, right->ValueName);
        if (compareResult != GenericEqual) {
            return compareResult;
        }

        return CompareExactTextField(left->ValueData, right->ValueData);
    }

    static RTL_GENERIC_COMPARE_RESULTS NTAPI CompareExactRuleNode(
        _In_ RTL_AVL_TABLE* table,
        _In_ PVOID firstStruct,
        _In_ PVOID secondStruct) {
        UNREFERENCED_PARAMETER(table);

        const RULE_STORE_EXACT_NODE* left = (const RULE_STORE_EXACT_NODE*)firstStruct;
        const RULE_STORE_EXACT_NODE* right = (const RULE_STORE_EXACT_NODE*)secondStruct;
        return CompareExactRuleKey(&left->Key, &right->Key);
    }

    static PVOID NTAPI AllocateExactRuleNode(
        _In_ RTL_AVL_TABLE* table,
        _In_ CLONG byteSize) {
        UNREFERENCED_PARAMETER(table);
        return ExAllocatePoolZero(NonPagedPoolNx, (SIZE_T)byteSize, kExactRuleNodePoolTag);
    }

    static VOID NTAPI FreeExactRuleNode(
        _In_ RTL_AVL_TABLE* table,
        _In_ __drv_freesMem(Mem) _Post_invalid_ PVOID buffer) {
        UNREFERENCED_PARAMETER(table);

        if (buffer == NULL) {
            return;
        }

        PRULE_STORE_EXACT_NODE node = (PRULE_STORE_EXACT_NODE)buffer;
        if (node->RuleRefs != NULL) {
            ExFreePoolWithTag(node->RuleRefs, kExactRuleRefPoolTag);
            node->RuleRefs = NULL;
        }

        ExFreePoolWithTag(node, kExactRuleNodePoolTag);
    }

    static VOID InitializeExactRuleTable(_Inout_ PRULE_STORE store) {
        if (store == NULL) {
            return;
        }

        RtlInitializeGenericTableAvl(
            &store->ExactRuleTable,
            CompareExactRuleNode,
            AllocateExactRuleNode,
            FreeExactRuleNode,
            NULL);
        store->ExactRuleTableInitialized = TRUE;
    }

    static VOID DestroyExactRuleTable(_Inout_ PRULE_STORE store) {
        if (store == NULL || !store->ExactRuleTableInitialized) {
            return;
        }

        while (!RtlIsGenericTableEmptyAvl(&store->ExactRuleTable)) {
            PRULE_STORE_EXACT_NODE node =
                (PRULE_STORE_EXACT_NODE)RtlGetElementGenericTableAvl(&store->ExactRuleTable, 0);
            if (node == NULL) {
                break;
            }

            RtlDeleteElementGenericTableAvl(&store->ExactRuleTable, node);
        }

        store->ExactRuleNodeCount = 0;
        store->ExactRuleTableInitialized = FALSE;
    }

    static NTSTATUS AppendExactRuleReference(
        _Inout_ PRULE_STORE_EXACT_NODE node,
        _In_ PREGISTRY_RULE ruleRef) {
        if (node == NULL || ruleRef == NULL) {
            return STATUS_INVALID_PARAMETER;
        }

        SIZE_T newCount = (SIZE_T)node->RuleRefCount + 1;
        SIZE_T allocationSize = sizeof(PREGISTRY_RULE) * newCount;
        PREGISTRY_RULE* newRuleRefs =
            (PREGISTRY_RULE*)ExAllocatePoolZero(NonPagedPoolNx, allocationSize, kExactRuleRefPoolTag);
        if (newRuleRefs == NULL) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        if (node->RuleRefs != NULL && node->RuleRefCount != 0) {
            RtlCopyMemory(newRuleRefs, node->RuleRefs, sizeof(PREGISTRY_RULE) * (SIZE_T)node->RuleRefCount);
            ExFreePoolWithTag(node->RuleRefs, kExactRuleRefPoolTag);
        }

        newRuleRefs[node->RuleRefCount] = ruleRef;
        node->RuleRefs = newRuleRefs;
        node->RuleRefCount += 1;
        return STATUS_SUCCESS;
    }

    static NTSTATUS BuildExactRuleTable(_Inout_ PRULE_STORE store) {
        if (store == NULL) {
            return STATUS_INVALID_PARAMETER;
        }

        InitializeExactRuleTable(store);
        if (store->ExactRules == NULL || store->ExactRuleCount == 0) {
            return STATUS_SUCCESS;
        }

        for (ULONG index = 0; index < store->ExactRuleCount; ++index) {
            RULE_STORE_EXACT_NODE lookupNode = {};
            BuildExactRuleKeyFromRule(&store->ExactRules[index], &lookupNode.Key);

            BOOLEAN newElement = FALSE;
            PRULE_STORE_EXACT_NODE insertedNode =
                (PRULE_STORE_EXACT_NODE)RtlInsertElementGenericTableAvl(
                    &store->ExactRuleTable,
                    &lookupNode,
                    sizeof(lookupNode),
                    &newElement);
            if (insertedNode == NULL) {
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            if (newElement) {
                store->ExactRuleNodeCount += 1;
            }

            NTSTATUS status = AppendExactRuleReference(insertedNode, &store->ExactRules[index]);
            if (!NT_SUCCESS(status)) {
                return status;
            }
        }

        return STATUS_SUCCESS;
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

        DestroyExactRuleTable(store);
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

        NTSTATUS status = BuildExactRuleTable(store);
        if (!NT_SUCCESS(status)) {
            FreeRuleStore(store);
            return status;
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

    static ULONG GetAvailableExactLookupFlags(
        _In_opt_z_ PCWSTR processName,
        _In_opt_z_ PCWSTR keyPath,
        _In_opt_z_ PCWSTR infoClass,
        _In_opt_z_ PCWSTR valueName,
        _In_opt_z_ PCWSTR valueData) {
        ULONG flags = 0;

        if (!IsNullOrEmptyWide(processName)) {
            flags |= REGISTRY_MATCH_FLAG_PROCESS_NAME;
        }

        if (!IsNullOrEmptyWide(keyPath)) {
            flags |= REGISTRY_MATCH_FLAG_KEY_PATH;
        }

        if (!IsNullOrEmptyWide(infoClass)) {
            flags |= REGISTRY_MATCH_FLAG_INFO_CLASS;
        }

        if (!IsNullOrEmptyWide(valueName)) {
            flags |= REGISTRY_MATCH_FLAG_VALUE_NAME;
        }

        if (!IsNullOrEmptyWide(valueData)) {
            flags |= REGISTRY_MATCH_FLAG_VALUE_DATA;
        }

        return flags;
    }

    static ULONG GetExactRuleOrdinal(
        _In_ const RULE_STORE* store,
        _In_ const REGISTRY_RULE* rule) {
        if (store == NULL || store->ExactRules == NULL || rule == NULL) {
            return MAXULONG;
        }

        if (rule < store->ExactRules || rule >= (store->ExactRules + store->ExactRuleCount)) {
            return MAXULONG;
        }

        return (ULONG)(rule - store->ExactRules);
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

const REGISTRY_RULE* FindExactRegistryRuleMatch(
    _In_opt_ const RULE_STORE* store,
    _In_ ULONG operation,
    _In_opt_z_ PCWSTR processName,
    _In_opt_z_ PCWSTR keyPath,
    _In_opt_z_ PCWSTR infoClass,
    _In_opt_z_ PCWSTR valueName,
    _In_opt_z_ PCWSTR valueData) {
    if (store == NULL ||
        !store->ExactRuleTableInitialized ||
        store->ExactRuleCount == 0) {
        return NULL;
    }

    ULONG availableFlags = GetAvailableExactLookupFlags(
        processName,
        keyPath,
        infoClass,
        valueName,
        valueData);

    const REGISTRY_RULE* bestRule = NULL;
    ULONG bestOrdinal = MAXULONG;

    for (ULONG matchFlags = availableFlags;; matchFlags = (matchFlags - 1) & availableFlags) {
        RULE_STORE_EXACT_NODE lookupNode = {};
        BuildExactLookupKey(
            operation,
            matchFlags,
            processName,
            keyPath,
            infoClass,
            valueName,
            valueData,
            &lookupNode.Key);

        const RULE_STORE_EXACT_NODE* matchedNode =
            (const RULE_STORE_EXACT_NODE*)RtlLookupElementGenericTableAvl(
                (PRTL_AVL_TABLE)&store->ExactRuleTable,
                &lookupNode);
        if (matchedNode != NULL &&
            matchedNode->RuleRefCount != 0 &&
            matchedNode->RuleRefs != NULL &&
            matchedNode->RuleRefs[0] != NULL) {
            const REGISTRY_RULE* candidateRule = matchedNode->RuleRefs[0];
            ULONG candidateOrdinal = GetExactRuleOrdinal(store, candidateRule);
            if (candidateOrdinal < bestOrdinal) {
                bestRule = candidateRule;
                bestOrdinal = candidateOrdinal;
                if (bestOrdinal == 0) {
                    break;
                }
            }
        }

        if (matchFlags == 0) {
            break;
        }
    }

    return bestRule;
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
    BOOLEAN storeUpdated = FALSE;

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
    storeUpdated = TRUE;

    if (newRuleCount != NULL) {
        *newRuleCount = combinedRuleCount;
    }

Cleanup:
    ReleaseExclusiveResourceLock(&g_RuleStoreStateLock);

    FreeRuleArray(flatRules);
    FreeRuleStore(newStore);

    if (NT_SUCCESS(status) && storeUpdated) {
        FlushDecisionCache();
    }

    if (NT_SUCCESS(status) && oldStore != NULL) {
        WaitForRuleStoreReferencesToDrain(oldStore);
        FreeRuleStore(oldStore);
    }

    return status;
}
