#include "PebMonitor.h"

static FILE_PROTECTION_STATE g_FileProtectionState = {};
static const WCHAR g_ProtectedDriverPathSuffixBuffer[] = L"\\Windows\\System32\\drivers\\DriverModule.sys";
static const WCHAR g_FileProtectionRuleId[] = L"driver_self_protection";

EXTERN_C PCHAR PsGetProcessImageFileName(_In_ PEPROCESS Process);

static VOID CopyAnsiProcessNameToWideBuffer(
    _Out_writes_(bufferLength) WCHAR* buffer,
    _In_ SIZE_T bufferLength,
    _In_opt_z_ PCSTR source) {
    if (buffer == NULL || bufferLength == 0) {
        return;
    }

    buffer[0] = L'\0';
    if (source == NULL || source[0] == '\0') {
        return;
    }

    SIZE_T writeIndex = 0;
    while (writeIndex + 1 < bufferLength && source[writeIndex] != '\0') {
        CHAR character = source[writeIndex];
        if (character >= 'A' && character <= 'Z') {
            character = (CHAR)(character - 'A' + 'a');
        }

        buffer[writeIndex] = (WCHAR)(UCHAR)character;
        writeIndex++;
    }

    buffer[writeIndex] = L'\0';
}

static VOID CopyWideStringToFixedBuffer(
    _Out_writes_(bufferLength) WCHAR* buffer,
    _In_ SIZE_T bufferLength,
    _In_opt_z_ PCWSTR source) {
    if (buffer == NULL || bufferLength == 0) {
        return;
    }

    buffer[0] = L'\0';
    if (source == NULL || source[0] == L'\0') {
        return;
    }

    NTSTATUS status = RtlStringCchCopyW(buffer, bufferLength, source);
    if (!NT_SUCCESS(status)) {
        buffer[bufferLength - 1] = L'\0';
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

static BOOLEAN IsDangerousSetInformationClass(_In_ FILE_INFORMATION_CLASS fileInformationClass) {
    return (fileInformationClass == FileDispositionInformation ||
        fileInformationClass == FileDispositionInformationEx ||
        fileInformationClass == FileRenameInformation ||
        fileInformationClass == FileRenameInformationEx);
}

static PCWSTR GetSetInformationClassName(_In_ FILE_INFORMATION_CLASS fileInformationClass) {
    switch (fileInformationClass) {
    case FileDispositionInformation:
        return L"FileDispositionInformation";
    case FileDispositionInformationEx:
        return L"FileDispositionInformationEx";
    case FileRenameInformation:
        return L"FileRenameInformation";
    case FileRenameInformationEx:
        return L"FileRenameInformationEx";
    default:
        return L"UnknownFileSetInformationClass";
    }
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

static VOID QueueBlockedFileProtectionEvent(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCUNICODE_STRING normalizedName,
    _In_opt_z_ PCWSTR infoClassName) {
    PDRIVER_EVENT_NODE node = AllocateDriverEventNode();
    if (node == NULL) {
        InterlockedIncrement64(&g_DriverEventAllocFailCount);
        return;
    }

    node->EventData.EventType = DRIVER_EVENT_TYPE_BLOCKED_FILE_OPERATION;
    node->EventData.Severity = 100;
    CopyWideStringToFixedBuffer(
        node->EventData.RuleId,
        RTL_NUMBER_OF(node->EventData.RuleId),
        g_FileProtectionRuleId);
    CopyUnicodeStringToFixedBuffer(
        node->EventData.TargetPath,
        RTL_NUMBER_OF(node->EventData.TargetPath),
        normalizedName);
    CopyWideStringToFixedBuffer(
        node->EventData.InfoClass,
        RTL_NUMBER_OF(node->EventData.InfoClass),
        infoClassName);

    PEPROCESS requestorProcess = FltGetRequestorProcess(Data);
    if (requestorProcess != NULL) {
        node->EventData.ProcessId = HandleToULong(PsGetProcessId(requestorProcess));
        CopyAnsiProcessNameToWideBuffer(
            node->EventData.ProcessName,
            RTL_NUMBER_OF(node->EventData.ProcessName),
            PsGetProcessImageFileName(requestorProcess));
    }

    QueueDriverEventNode(node);
}

static FLT_PREOP_CALLBACK_STATUS CompleteBlockedProtectedFileRequest(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCUNICODE_STRING normalizedName,
    _In_opt_z_ PCWSTR infoClassName) {
    QueueBlockedFileProtectionEvent(Data, normalizedName, infoClassName);
    Data->IoStatus.Status = STATUS_ACCESS_DENIED;
    Data->IoStatus.Information = 0;
    return FLT_PREOP_COMPLETE;
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
        FLT_PREOP_CALLBACK_STATUS result = CompleteBlockedProtectedFileRequest(
            Data,
            &nameInfo->Name,
            NULL);
        FltReleaseFileNameInformation(nameInfo);
        return result;
    }

    FltReleaseFileNameInformation(nameInfo);
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

FLT_PREOP_CALLBACK_STATUS FileProtectionPreSetInformation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext) {
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    if (!g_FileProtectionState.Initialized || Data == NULL || Data->Iopb == NULL) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    FILE_INFORMATION_CLASS fileInformationClass =
        Data->Iopb->Parameters.SetFileInformation.FileInformationClass;
    if (Data->RequestorMode == KernelMode || !IsDangerousSetInformationClass(fileInformationClass)) {
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
        KdPrint(("[PebMonitor] WARN: Blocking delete/rename set-information access to protected driver file.\n"));
        FLT_PREOP_CALLBACK_STATUS result = CompleteBlockedProtectedFileRequest(
            Data,
            &nameInfo->Name,
            GetSetInformationClassName(fileInformationClass));
        FltReleaseFileNameInformation(nameInfo);
        return result;
    }

    FltReleaseFileNameInformation(nameInfo);
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}
