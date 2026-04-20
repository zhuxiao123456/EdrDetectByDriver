#include "PebMonitor.h"

ERESOURCE g_DecisionCacheLock = {};
DECISION_CACHE_ENTRY g_DecisionCacheEntries[DECISION_CACHE_MAX_ENTRIES] = {};
volatile LONG64 g_DecisionCacheHitCount = 0;
volatile LONG64 g_DecisionCacheMissCount = 0;
volatile LONG64 g_DecisionCacheFlushCount = 0;
volatile LONG64 g_SlowPathCount = 0;

namespace {
    static ULONGLONG QueryCurrentSystemTimeValue() {
        LARGE_INTEGER now = {};
        KeQuerySystemTime(&now);
        return (ULONGLONG)now.QuadPart;
    }

    static ULONG ReadCurrentPolicyEpoch() {
        return (ULONG)InterlockedCompareExchange((volatile LONG*)&g_PolicyEpoch, 0, 0);
    }

    static WCHAR NormalizeHashCharacter(_In_ WCHAR character) {
        if (character >= L'A' && character <= L'Z') {
            return (WCHAR)(character - L'A' + L'a');
        }

        if (character == L'/') {
            return L'\\';
        }

        return character;
    }

    static ULONG HashPathInsensitive(_In_z_ PCWSTR path) {
        ULONG hash = 2166136261UL;

        for (SIZE_T index = 0; path[index] != L'\0'; ++index) {
            hash ^= (ULONG)NormalizeHashCharacter(path[index]);
            hash *= 16777619UL;
        }

        return hash;
    }

    static BOOLEAN IsDecisionCacheKeyValid(_In_ const DECISION_CACHE_KEY* key) {
        return
            key != NULL &&
            key->ProcessId != 0 &&
            key->CreateTime != 0 &&
            key->OperationType != 0 &&
            key->TargetHash != 0 &&
            key->PolicyEpoch != 0;
    }

    static BOOLEAN DecisionCacheKeysEqual(
        _In_ const DECISION_CACHE_KEY* left,
        _In_ const DECISION_CACHE_KEY* right) {
        return
            left->ProcessId == right->ProcessId &&
            left->CreateTime == right->CreateTime &&
            left->OperationType == right->OperationType &&
            left->TargetHash == right->TargetHash &&
            left->PolicyEpoch == right->PolicyEpoch;
    }

    static BOOLEAN IsCacheEntryExpired(
        _In_ const DECISION_CACHE_ENTRY* entry,
        _In_ ULONGLONG now) {
        ULONGLONG ttlTicks = (ULONGLONG)DECISION_CACHE_TTL_MS * 10ULL * 1000ULL;
        return
            entry == NULL ||
            !entry->InUse ||
            entry->InsertTime == 0 ||
            now < entry->InsertTime ||
            (now - entry->InsertTime) > ttlTicks;
    }

    static VOID ResetDecisionCacheEntry(_Out_ PDECISION_CACHE_ENTRY entry) {
        if (entry != NULL) {
            RtlZeroMemory(entry, sizeof(*entry));
        }
    }

    static BOOLEAN PurgeDecisionCacheProcessEntries(
        _In_ ULONG processId,
        _In_ ULONGLONG createTime,
        _In_ ULONG policyEpoch,
        _In_ ULONGLONG now) {
        BOOLEAN removed = FALSE;

        if (processId == 0 || createTime == 0 || policyEpoch == 0) {
            return FALSE;
        }

        AcquireExclusiveResourceLock(&g_DecisionCacheLock);
        for (ULONG index = 0; index < RTL_NUMBER_OF(g_DecisionCacheEntries); ++index) {
            PDECISION_CACHE_ENTRY currentEntry = &g_DecisionCacheEntries[index];
            if (!currentEntry->InUse || currentEntry->Key.ProcessId != processId) {
                continue;
            }

            if (currentEntry->Key.PolicyEpoch == policyEpoch &&
                currentEntry->Key.CreateTime == createTime &&
                !IsCacheEntryExpired(currentEntry, now)) {
                continue;
            }

            ResetDecisionCacheEntry(currentEntry);
            removed = TRUE;
        }
        ReleaseExclusiveResourceLock(&g_DecisionCacheLock);

        if (removed) {
            InterlockedIncrement64(&g_DecisionCacheFlushCount);
        }

        return removed;
    }

    static BOOLEAN RefreshDecisionCacheHit(
        _In_ const DECISION_CACHE_KEY* key,
        _In_ ULONGLONG now) {
        BOOLEAN refreshed = FALSE;

        if (!IsDecisionCacheKeyValid(key)) {
            return FALSE;
        }

        AcquireExclusiveResourceLock(&g_DecisionCacheLock);
        for (ULONG index = 0; index < RTL_NUMBER_OF(g_DecisionCacheEntries); ++index) {
            PDECISION_CACHE_ENTRY currentEntry = &g_DecisionCacheEntries[index];
            if (!currentEntry->InUse) {
                continue;
            }

            if (IsCacheEntryExpired(currentEntry, now)) {
                continue;
            }

            if (!DecisionCacheKeysEqual(&currentEntry->Key, key)) {
                continue;
            }

            currentEntry->LastHitTime = now;
            currentEntry->HitCount++;
            refreshed = TRUE;
            break;
        }
        ReleaseExclusiveResourceLock(&g_DecisionCacheLock);

        return refreshed;
    }
}

NTSTATUS InitializeDecisionCacheState() {
    NTSTATUS status = ExInitializeResourceLite(&g_DecisionCacheLock);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    RtlZeroMemory(g_DecisionCacheEntries, sizeof(g_DecisionCacheEntries));
    InterlockedExchange64(&g_DecisionCacheHitCount, 0);
    InterlockedExchange64(&g_DecisionCacheMissCount, 0);
    InterlockedExchange64(&g_DecisionCacheFlushCount, 0);
    InterlockedExchange64(&g_SlowPathCount, 0);
    return STATUS_SUCCESS;
}

VOID CleanupDecisionCacheState() {
    FlushDecisionCache();
    ExDeleteResourceLite(&g_DecisionCacheLock);
}

BOOLEAN BuildProcessCreateDecisionCacheKey(
    _In_opt_ const PROCESS_IDENTITY* subjectIdentity,
    _In_opt_z_ PCWSTR targetImagePath,
    _Out_ PDECISION_CACHE_KEY key) {
    if (key == NULL) {
        return FALSE;
    }

    RtlZeroMemory(key, sizeof(*key));
    if (subjectIdentity == NULL ||
        subjectIdentity->ProcessId == 0 ||
        subjectIdentity->CreateTime == 0 ||
        targetImagePath == NULL ||
        targetImagePath[0] == L'\0') {
        return FALSE;
    }

    key->ProcessId = subjectIdentity->ProcessId;
    key->CreateTime = subjectIdentity->CreateTime;
    key->OperationType = DECISION_CACHE_OPERATION_PROCESS_CREATE;
    key->TargetHash = HashPathInsensitive(targetImagePath);
    key->PolicyEpoch = ReadCurrentPolicyEpoch();
    return IsDecisionCacheKeyValid(key);
}

BOOLEAN TryGetDecisionCacheAllow(_In_ const DECISION_CACHE_KEY* key) {
    BOOLEAN allow = FALSE;
    BOOLEAN removeStaleEntries = FALSE;
    ULONGLONG now = 0;
    ULONG currentPolicyEpoch = 0;

    if (!IsDecisionCacheKeyValid(key)) {
        return FALSE;
    }

    now = QueryCurrentSystemTimeValue();
    currentPolicyEpoch = ReadCurrentPolicyEpoch();

    AcquireSharedResourceLock(&g_DecisionCacheLock);
    for (ULONG index = 0; index < RTL_NUMBER_OF(g_DecisionCacheEntries); ++index) {
        PDECISION_CACHE_ENTRY currentEntry = &g_DecisionCacheEntries[index];
        if (!currentEntry->InUse) {
            continue;
        }

        if (currentEntry->Key.ProcessId == key->ProcessId &&
            (currentEntry->Key.PolicyEpoch != currentPolicyEpoch ||
                currentEntry->Key.CreateTime != key->CreateTime ||
                IsCacheEntryExpired(currentEntry, now))) {
            removeStaleEntries = TRUE;
            continue;
        }

        if (!DecisionCacheKeysEqual(&currentEntry->Key, key)) {
            continue;
        }

        allow = TRUE;
        break;
    }
    ReleaseSharedResourceLock(&g_DecisionCacheLock);

    if (removeStaleEntries) {
        PurgeDecisionCacheProcessEntries(key->ProcessId, key->CreateTime, currentPolicyEpoch, now);
    }

    if (allow && !RefreshDecisionCacheHit(key, now)) {
        allow = FALSE;
    }

    if (allow) {
        InterlockedIncrement64(&g_DecisionCacheHitCount);
    }
    else {
        InterlockedIncrement64(&g_DecisionCacheMissCount);
    }

    return allow;
}

VOID RememberAllowedProcessCreateDecision(_In_ const DECISION_CACHE_KEY* key) {
    PDECISION_CACHE_ENTRY selectedEntry = NULL;
    ULONGLONG now = 0;

    if (!IsDecisionCacheKeyValid(key)) {
        return;
    }

    now = QueryCurrentSystemTimeValue();

    AcquireExclusiveResourceLock(&g_DecisionCacheLock);
    for (ULONG index = 0; index < RTL_NUMBER_OF(g_DecisionCacheEntries); ++index) {
        PDECISION_CACHE_ENTRY currentEntry = &g_DecisionCacheEntries[index];
        if (currentEntry->InUse && DecisionCacheKeysEqual(&currentEntry->Key, key)) {
            selectedEntry = currentEntry;
            break;
        }
    }

    if (selectedEntry == NULL) {
        for (ULONG index = 0; index < RTL_NUMBER_OF(g_DecisionCacheEntries); ++index) {
            PDECISION_CACHE_ENTRY currentEntry = &g_DecisionCacheEntries[index];
            if (!currentEntry->InUse) {
                selectedEntry = currentEntry;
                break;
            }

            if (IsCacheEntryExpired(currentEntry, now)) {
                selectedEntry = currentEntry;
                break;
            }

            if (selectedEntry == NULL || currentEntry->LastHitTime < selectedEntry->LastHitTime) {
                selectedEntry = currentEntry;
            }
        }
    }

    if (selectedEntry != NULL) {
        ResetDecisionCacheEntry(selectedEntry);
        selectedEntry->InUse = TRUE;
        selectedEntry->Key = *key;
        selectedEntry->InsertTime = now;
        selectedEntry->LastHitTime = now;
        selectedEntry->HitCount = 0;
    }
    ReleaseExclusiveResourceLock(&g_DecisionCacheLock);
}

VOID FlushDecisionCache() {
    AcquireExclusiveResourceLock(&g_DecisionCacheLock);
    RtlZeroMemory(g_DecisionCacheEntries, sizeof(g_DecisionCacheEntries));
    ReleaseExclusiveResourceLock(&g_DecisionCacheLock);
    InterlockedIncrement64(&g_DecisionCacheFlushCount);
}

VOID FlushDecisionCacheForProcess(_In_ ULONG processId) {
    BOOLEAN removed = FALSE;

    if (processId == 0) {
        return;
    }

    AcquireExclusiveResourceLock(&g_DecisionCacheLock);
    for (ULONG index = 0; index < RTL_NUMBER_OF(g_DecisionCacheEntries); ++index) {
        PDECISION_CACHE_ENTRY currentEntry = &g_DecisionCacheEntries[index];
        if (currentEntry->InUse && currentEntry->Key.ProcessId == processId) {
            ResetDecisionCacheEntry(currentEntry);
            removed = TRUE;
        }
    }
    ReleaseExclusiveResourceLock(&g_DecisionCacheLock);

    if (removed) {
        InterlockedIncrement64(&g_DecisionCacheFlushCount);
    }
}

VOID RecordSlowPathProcessVerdict() {
    InterlockedIncrement64(&g_SlowPathCount);
}
