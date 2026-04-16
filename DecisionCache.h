#pragma once

#include <fltKernel.h>

#include "FastPath.h"

#define DECISION_CACHE_MAX_ENTRIES 256UL
#define DECISION_CACHE_TTL_MS 10000UL
#define DECISION_CACHE_OPERATION_PROCESS_CREATE 1UL

typedef struct _DECISION_CACHE_KEY {
    ULONG ProcessId;
    ULONGLONG CreateTime;
    ULONG OperationType;
    ULONG TargetHash;
    ULONG PolicyEpoch;
} DECISION_CACHE_KEY, *PDECISION_CACHE_KEY;

typedef struct _DECISION_CACHE_ENTRY {
    BOOLEAN InUse;
    DECISION_CACHE_KEY Key;
    ULONGLONG InsertTime;
    ULONGLONG LastHitTime;
    ULONG HitCount;
} DECISION_CACHE_ENTRY, *PDECISION_CACHE_ENTRY;

extern ERESOURCE g_DecisionCacheLock;
extern DECISION_CACHE_ENTRY g_DecisionCacheEntries[DECISION_CACHE_MAX_ENTRIES];
extern volatile LONG64 g_DecisionCacheHitCount;
extern volatile LONG64 g_DecisionCacheMissCount;
extern volatile LONG64 g_DecisionCacheFlushCount;
extern volatile LONG64 g_SlowPathCount;

NTSTATUS InitializeDecisionCacheState();
VOID CleanupDecisionCacheState();
BOOLEAN BuildProcessCreateDecisionCacheKey(
    _In_opt_ const PROCESS_IDENTITY* subjectIdentity,
    _In_opt_z_ PCWSTR targetImagePath,
    _Out_ PDECISION_CACHE_KEY key);
BOOLEAN TryGetDecisionCacheAllow(_In_ const DECISION_CACHE_KEY* key);
VOID RememberAllowedProcessCreateDecision(_In_ const DECISION_CACHE_KEY* key);
VOID FlushDecisionCache();
VOID FlushDecisionCacheForProcess(_In_ ULONG processId);
VOID RecordSlowPathProcessVerdict();
