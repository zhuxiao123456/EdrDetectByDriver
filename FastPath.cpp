#include "PebMonitor.h"

ERESOURCE g_FastPathStateLock = {};
FASTPATH_TRUSTED_ENTRY g_FastPathTrustedEntries[MAX_FASTPATH_TRUSTED_ENTRIES] = {};
volatile LONG64 g_FastPathHitCount = 0;

namespace {
    static ULONGLONG QueryCurrentSystemTimeValue() {
        LARGE_INTEGER now = {};
        KeQuerySystemTime(&now);
        return (ULONGLONG)now.QuadPart;
    }

    static VOID ResetTrustedEntry(_Out_ PFASTPATH_TRUSTED_ENTRY entry) {
        if (entry != NULL) {
            RtlZeroMemory(entry, sizeof(*entry));
        }
    }

    static VOID CopyUnicodeStringToFixedBuffer(
        _Out_writes_(bufferLength) WCHAR* buffer,
        _In_ SIZE_T bufferLength,
        _In_opt_ PCUNICODE_STRING source) {
        if (buffer == NULL || bufferLength == 0) {
            return;
        }

        buffer[0] = L'\0';
        if (source == NULL || source->Buffer == NULL || source->Length == 0) {
            return;
        }

        ULONG copyBytes = source->Length;
        ULONG maxBytes = (ULONG)((bufferLength - 1) * sizeof(WCHAR));
        if (copyBytes > maxBytes) {
            copyBytes = maxBytes;
        }

        copyBytes -= (copyBytes % sizeof(WCHAR));
        if (copyBytes == 0) {
            return;
        }

        RtlCopyMemory(buffer, source->Buffer, copyBytes);
        buffer[copyBytes / sizeof(WCHAR)] = L'\0';
    }

    static BOOLEAN IsProcessIdentityValid(_In_ const PROCESS_IDENTITY* identity) {
        return
            identity != NULL &&
            identity->ProcessId != 0 &&
            identity->CreateTime != 0 &&
            identity->FullPath[0] != L'\0';
    }

    static BOOLEAN PathsEqualInsensitive(
        _In_z_ PCWSTR left,
        _In_z_ PCWSTR right) {
        UNICODE_STRING leftString = {};
        UNICODE_STRING rightString = {};

        if (left == NULL || right == NULL || left[0] == L'\0' || right[0] == L'\0') {
            return FALSE;
        }

        RtlInitUnicodeString(&leftString, left);
        RtlInitUnicodeString(&rightString, right);
        return RtlEqualUnicodeString(&leftString, &rightString, TRUE);
    }

    static BOOLEAN CaptureProcessIdentityInternal(
        _In_ ULONG processId,
        _In_ PEPROCESS process,
        _Out_ PPROCESS_IDENTITY identity) {
        PUNICODE_STRING imagePath = NULL;
        BOOLEAN captured = FALSE;

        if (identity == NULL) {
            return FALSE;
        }

        RtlZeroMemory(identity, sizeof(*identity));
        if (process == NULL || processId == 0) {
            return FALSE;
        }

        identity->ProcessId = processId;
        if (!QueryProcessCreateTimeCompat(process, &identity->CreateTime)) {
            return FALSE;
        }

        if (!NT_SUCCESS(QueryProcessImageNameCompat(process, &imagePath)) ||
            imagePath == NULL ||
            imagePath->Buffer == NULL ||
            imagePath->Length == 0) {
            return FALSE;
        }

        CopyUnicodeStringToFixedBuffer(identity->FullPath, RTL_NUMBER_OF(identity->FullPath), imagePath);
        captured = IsProcessIdentityValid(identity);
        ExFreePool(imagePath);
        return captured;
    }

    static PFASTPATH_TRUSTED_ENTRY SelectTrustedEntrySlot() {
        PFASTPATH_TRUSTED_ENTRY selectedEntry = NULL;

        for (ULONG index = 0; index < RTL_NUMBER_OF(g_FastPathTrustedEntries); ++index) {
            PFASTPATH_TRUSTED_ENTRY currentEntry = &g_FastPathTrustedEntries[index];
            if (!currentEntry->Active) {
                return currentEntry;
            }

            if (selectedEntry == NULL || currentEntry->LastVerifiedTime < selectedEntry->LastVerifiedTime) {
                selectedEntry = currentEntry;
            }
        }

        return selectedEntry;
    }
}

NTSTATUS InitializeFastPathState() {
    NTSTATUS status = ExInitializeResourceLite(&g_FastPathStateLock);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    RtlZeroMemory(g_FastPathTrustedEntries, sizeof(g_FastPathTrustedEntries));
    InterlockedExchange64(&g_FastPathHitCount, 0);
    return STATUS_SUCCESS;
}

VOID CleanupFastPathState() {
    AcquireExclusiveResourceLock(&g_FastPathStateLock);
    RtlZeroMemory(g_FastPathTrustedEntries, sizeof(g_FastPathTrustedEntries));
    ReleaseExclusiveResourceLock(&g_FastPathStateLock);
    ExDeleteResourceLite(&g_FastPathStateLock);
}

BOOLEAN CaptureProcessIdentity(
    _In_ ULONG processId,
    _In_ PEPROCESS process,
    _Out_ PPROCESS_IDENTITY identity) {
    return CaptureProcessIdentityInternal(processId, process, identity);
}

BOOLEAN CaptureProcessIdentityByProcessId(
    _In_ HANDLE processId,
    _Out_ PPROCESS_IDENTITY identity) {
    PEPROCESS process = NULL;
    BOOLEAN captured = FALSE;

    if (!NT_SUCCESS(PsLookupProcessByProcessId(processId, &process))) {
        return FALSE;
    }

    captured = CaptureProcessIdentityInternal(HandleToULong(processId), process, identity);
    ObDereferenceObject(process);
    return captured;
}

BOOLEAN RegisterFastPathTrustedProcess(
    _In_ ULONG processId,
    _In_ PEPROCESS process,
    _In_ ULONG trustFlags) {
    PROCESS_IDENTITY identity = {};
    PFASTPATH_TRUSTED_ENTRY targetEntry = NULL;
    ULONGLONG now = 0;

    if (!CaptureProcessIdentity(processId, process, &identity)) {
        return FALSE;
    }

    now = QueryCurrentSystemTimeValue();

    AcquireExclusiveResourceLock(&g_FastPathStateLock);
    for (ULONG index = 0; index < RTL_NUMBER_OF(g_FastPathTrustedEntries); ++index) {
        PFASTPATH_TRUSTED_ENTRY currentEntry = &g_FastPathTrustedEntries[index];
        if (currentEntry->Active && currentEntry->ProcessId == processId) {
            targetEntry = currentEntry;
            break;
        }
    }

    if (targetEntry == NULL) {
        targetEntry = SelectTrustedEntrySlot();
    }

    if (targetEntry != NULL) {
        ResetTrustedEntry(targetEntry);
        targetEntry->Active = TRUE;
        targetEntry->ProcessId = identity.ProcessId;
        targetEntry->CreateTime = identity.CreateTime;
        targetEntry->TrustFlags = trustFlags;
        targetEntry->LastVerifiedTime = now;
        RtlStringCchCopyW(
            targetEntry->FullPath,
            RTL_NUMBER_OF(targetEntry->FullPath),
            identity.FullPath);
    }

    ReleaseExclusiveResourceLock(&g_FastPathStateLock);
    return (targetEntry != NULL);
}

VOID RemoveFastPathTrustedProcess(_In_ ULONG processId) {
    if (processId == 0) {
        return;
    }

    AcquireExclusiveResourceLock(&g_FastPathStateLock);
    for (ULONG index = 0; index < RTL_NUMBER_OF(g_FastPathTrustedEntries); ++index) {
        PFASTPATH_TRUSTED_ENTRY currentEntry = &g_FastPathTrustedEntries[index];
        if (currentEntry->Active && currentEntry->ProcessId == processId) {
            ResetTrustedEntry(currentEntry);
        }
    }
    ReleaseExclusiveResourceLock(&g_FastPathStateLock);
}

BOOLEAN EvaluateFastPathProcessCreateAllow(_In_opt_ const PROCESS_IDENTITY* subjectIdentity) {
    BOOLEAN allow = FALSE;
    ULONGLONG now = 0;

    if (!IsProcessIdentityValid(subjectIdentity)) {
        return FALSE;
    }

    now = QueryCurrentSystemTimeValue();

    AcquireExclusiveResourceLock(&g_FastPathStateLock);
    for (ULONG index = 0; index < RTL_NUMBER_OF(g_FastPathTrustedEntries); ++index) {
        PFASTPATH_TRUSTED_ENTRY currentEntry = &g_FastPathTrustedEntries[index];
        if (!currentEntry->Active) {
            continue;
        }

        if (currentEntry->ProcessId != subjectIdentity->ProcessId ||
            currentEntry->CreateTime != subjectIdentity->CreateTime) {
            continue;
        }

        if (!PathsEqualInsensitive(currentEntry->FullPath, subjectIdentity->FullPath)) {
            continue;
        }

        currentEntry->LastVerifiedTime = now;
        allow = TRUE;
        break;
    }
    ReleaseExclusiveResourceLock(&g_FastPathStateLock);

    if (allow) {
        InterlockedIncrement64(&g_FastPathHitCount);
    }

    return allow;
}
