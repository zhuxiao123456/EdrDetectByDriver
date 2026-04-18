#pragma once

#include <fltKernel.h>

typedef struct _FILE_PROTECTION_STATE {
    BOOLEAN Initialized;
    UNICODE_STRING ProtectedDriverPathSuffix;
} FILE_PROTECTION_STATE, *PFILE_PROTECTION_STATE;

NTSTATUS InitializeFileProtectionState();
VOID CleanupFileProtectionState();

FLT_PREOP_CALLBACK_STATUS FileProtectionPreCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext);
