#pragma once

#include <fltKernel.h>

#include "Shared.h"

#define FASTPATH_TRUST_FLAG_PROCESS_PORT_CLIENT 0x0001UL
#define MAX_FASTPATH_TRUSTED_ENTRIES 8UL

typedef struct _PROCESS_IDENTITY {
    ULONG ProcessId;
    ULONGLONG CreateTime;
    WCHAR FullPath[MAX_REG_PATH_LENGTH];
} PROCESS_IDENTITY, *PPROCESS_IDENTITY;

typedef struct _FASTPATH_TRUSTED_ENTRY {
    BOOLEAN Active;
    ULONG ProcessId;
    ULONGLONG CreateTime;
    WCHAR FullPath[MAX_REG_PATH_LENGTH];
    ULONG TrustFlags;
    ULONGLONG LastVerifiedTime;
} FASTPATH_TRUSTED_ENTRY, *PFASTPATH_TRUSTED_ENTRY;

extern ERESOURCE g_FastPathStateLock;
extern FASTPATH_TRUSTED_ENTRY g_FastPathTrustedEntries[MAX_FASTPATH_TRUSTED_ENTRIES];
extern volatile LONG64 g_FastPathHitCount;

NTSTATUS InitializeFastPathState();
VOID CleanupFastPathState();
BOOLEAN CaptureProcessIdentity(
    _In_ ULONG processId,
    _In_ PEPROCESS process,
    _Out_ PPROCESS_IDENTITY identity);
BOOLEAN CaptureProcessIdentityByProcessId(
    _In_ HANDLE processId,
    _Out_ PPROCESS_IDENTITY identity);
BOOLEAN RegisterFastPathTrustedProcess(
    _In_ ULONG processId,
    _In_ PEPROCESS process,
    _In_ ULONG trustFlags);
VOID RemoveFastPathTrustedProcess(_In_ ULONG processId);
BOOLEAN EvaluateFastPathProcessCreateAllow(_In_opt_ const PROCESS_IDENTITY* subjectIdentity);
