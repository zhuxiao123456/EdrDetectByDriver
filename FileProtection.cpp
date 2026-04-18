#include "PebMonitor.h"

static FILE_PROTECTION_STATE g_FileProtectionState = {};
static const WCHAR g_ProtectedDriverPathSuffixBuffer[] = L"\\Windows\\System32\\drivers\\DriverModule.sys";

static BOOLEAN IsDangerousCreateRequest(_In_ PFLT_CALLBACK_DATA Data) {
    if (Data == NULL || Data->Iopb == NULL) {
        return FALSE;
    }

    ACCESS_MASK desiredAccess = 0;
    PIO_SECURITY_CONTEXT securityContext = Data->Iopb->Parameters.Create.SecurityContext;
    if (securityContext != NULL) {
        desiredAccess = securityContext->DesiredAccess;
    }

    ULONG createOptions = Data->Iopb->Parameters.Create.Options & 0x00FFFFFF;
    ULONG createDisposition = (Data->Iopb->Parameters.Create.Options >> 24) & 0x000000FF;

    if ((desiredAccess & (DELETE | FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_ATTRIBUTES | FILE_WRITE_EA | WRITE_DAC | WRITE_OWNER)) != 0) {
        return TRUE;
    }

    if ((createOptions & FILE_DELETE_ON_CLOSE) != 0) {
        return TRUE;
    }

    return (createDisposition == FILE_SUPERSEDE ||
        createDisposition == FILE_OVERWRITE ||
        createDisposition == FILE_OVERWRITE_IF);
}

static BOOLEAN EndsWithUnicodeStringInsensitive(
    _In_ PCUNICODE_STRING value,
    _In_ PCUNICODE_STRING suffix) {
    if (value == NULL || suffix == NULL || value->Buffer == NULL || suffix->Buffer == NULL) {
        return FALSE;
    }

    if (value->Length < suffix->Length) {
        return FALSE;
    }

    UNICODE_STRING tail = {};
    tail.Length = suffix->Length;
    tail.MaximumLength = suffix->Length;
    tail.Buffer = value->Buffer + ((value->Length - suffix->Length) / sizeof(WCHAR));
    return RtlEqualUnicodeString(&tail, suffix, TRUE);
}

static BOOLEAN IsProtectedDriverPath(_In_ PCUNICODE_STRING normalizedName) {
    if (!g_FileProtectionState.Initialized) {
        return FALSE;
    }

    return EndsWithUnicodeStringInsensitive(
        normalizedName,
        &g_FileProtectionState.ProtectedDriverPathSuffix);
}

NTSTATUS InitializeFileProtectionState() {
    RtlZeroMemory(&g_FileProtectionState, sizeof(g_FileProtectionState));
    RtlInitUnicodeString(
        &g_FileProtectionState.ProtectedDriverPathSuffix,
        g_ProtectedDriverPathSuffixBuffer);
    g_FileProtectionState.Initialized = TRUE;
    return STATUS_SUCCESS;
}

VOID CleanupFileProtectionState() {
    RtlZeroMemory(&g_FileProtectionState, sizeof(g_FileProtectionState));
}

FLT_PREOP_CALLBACK_STATUS FileProtectionPreCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext) {
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    if (!g_FileProtectionState.Initialized || Data == NULL || Data->Iopb == NULL) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (Data->RequestorMode == KernelMode || !IsDangerousCreateRequest(Data)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    NTSTATUS status = FltGetFileNameInformation(
        Data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
        &nameInfo);
    if (!NT_SUCCESS(status) || nameInfo == NULL) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    BOOLEAN blockRequest = FALSE;
    status = FltParseFileNameInformation(nameInfo);
    if (NT_SUCCESS(status) && IsProtectedDriverPath(&nameInfo->Name)) {
        blockRequest = TRUE;
    }

    if (blockRequest) {
        KdPrint(("[PebMonitor] WARN: Blocking write/delete access to protected driver file.\n"));
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        FltReleaseFileNameInformation(nameInfo);
        return FLT_PREOP_COMPLETE;
    }

    FltReleaseFileNameInformation(nameInfo);
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}
