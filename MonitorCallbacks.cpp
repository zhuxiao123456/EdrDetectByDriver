#define POOL_ZERO_DOWN_LEVEL_SUPPORT
#include "PebMonitor.h"

typedef struct _RTL_USER_PROCESS_PARAMETERS_LITE {
    UCHAR Reserved1[16];
    PVOID Reserved2[10];
    UNICODE_STRING ImagePathName;
    UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS_LITE, *PRTL_USER_PROCESS_PARAMETERS_LITE;

typedef struct _PEB_LITE {
    UCHAR Reserved1[2];
    UCHAR BeingDebugged;
    UCHAR Reserved2[1];
    PVOID Reserved3[2];
    PRTL_USER_PROCESS_PARAMETERS_LITE ProcessParameters;
} PEB_LITE, *PPEB_LITE;

EXTERN_C PCHAR PsGetProcessImageFileName(_In_ PEPROCESS Process);

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

static BOOLEAN CaptureUnicodeStringToLocalBuffer(
    _In_opt_ PCUNICODE_STRING source,
    _Out_writes_(bufferLength) WCHAR* buffer,
    _In_ SIZE_T bufferLength,
    _Out_ PUNICODE_STRING capturedValue) {
    if (buffer == NULL || bufferLength == 0 || capturedValue == NULL) {
        return FALSE;
    }

    buffer[0] = L'\0';
    RtlZeroMemory(capturedValue, sizeof(*capturedValue));

    if (source == NULL) {
        return FALSE;
    }

    ULONG copyBytes = 0;
    ULONG maxBytes = (ULONG)((bufferLength - 1) * sizeof(WCHAR));

    __try {
        if (source->Buffer == NULL || source->Length == 0) {
            return FALSE;
        }

        copyBytes = source->Length;
        if (copyBytes > maxBytes) {
            copyBytes = maxBytes;
        }

        copyBytes -= (copyBytes % sizeof(WCHAR));
        if (copyBytes == 0) {
            return FALSE;
        }

        RtlCopyMemory(buffer, source->Buffer, copyBytes);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        buffer[0] = L'\0';
        return FALSE;
    }

    buffer[copyBytes / sizeof(WCHAR)] = L'\0';
    capturedValue->Buffer = buffer;
    capturedValue->Length = (USHORT)copyBytes;
    capturedValue->MaximumLength = (USHORT)(bufferLength * sizeof(WCHAR));

    while (capturedValue->Length > 0 &&
        capturedValue->Buffer[(capturedValue->Length / sizeof(WCHAR)) - 1] == L'\0') {
        capturedValue->Length -= sizeof(WCHAR);
    }

    return capturedValue->Length > 0;
}

static BOOLEAN CaptureUnicodeStringToLocalBufferWithEllipsis(
    _In_opt_ PCUNICODE_STRING source,
    _Out_writes_(bufferLength) WCHAR* buffer,
    _In_ SIZE_T bufferLength,
    _Out_ PUNICODE_STRING capturedValue) {
    ULONG sourceLength = 0;

    __try {
        if (source != NULL) {
            sourceLength = source->Length;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        sourceLength = 0;
    }

    BOOLEAN captured = CaptureUnicodeStringToLocalBuffer(source, buffer, bufferLength, capturedValue);
    ULONG maxBytes = (ULONG)((bufferLength - 1) * sizeof(WCHAR));
    if (captured && sourceLength > maxBytes && bufferLength > 4) {
        buffer[bufferLength - 4] = L'.';
        buffer[bufferLength - 3] = L'.';
        buffer[bufferLength - 2] = L'.';
        buffer[bufferLength - 1] = L'\0';
    }

    return captured;
}

_IRQL_requires_max_(APC_LEVEL)
static BOOLEAN CaptureUnicodeStringToLocalText(
    _In_opt_ PCUNICODE_STRING source,
    _Out_writes_(bufferLength) WCHAR* buffer,
    _In_ SIZE_T bufferLength) {
    UNICODE_STRING capturedValue = {};
    return CaptureUnicodeStringToLocalBuffer(source, buffer, bufferLength, &capturedValue);
}

static VOID CaptureProcessShortName(
    _In_opt_ PEPROCESS process,
    _Out_writes_(bufferLength) WCHAR* buffer,
    _In_ SIZE_T bufferLength) {
    if (buffer == NULL || bufferLength == 0) {
        return;
    }

    buffer[0] = L'\0';
    if (process == NULL) {
        return;
    }

    PCHAR imageName = PsGetProcessImageFileName(process);
    if (imageName == NULL || imageName[0] == '\0') {
        return;
    }

    SIZE_T index = 0;
    while (index + 1 < bufferLength && imageName[index] != '\0') {
        CHAR character = imageName[index];
        if (character >= 'A' && character <= 'Z') {
            character = (CHAR)(character - 'A' + 'a');
        }
        buffer[index] = (WCHAR)(UCHAR)character;
        index++;
    }

    buffer[index] = L'\0';
}

static VOID ExtractProcessNameFromPathBuffer(
    _In_opt_z_ PCWSTR path,
    _Out_writes_(bufferLength) WCHAR* buffer,
    _In_ SIZE_T bufferLength) {
    if (buffer == NULL || bufferLength == 0) {
        return;
    }

    buffer[0] = L'\0';
    if (path == NULL || path[0] == L'\0') {
        return;
    }

    SIZE_T startIndex = 0;
    for (SIZE_T index = 0; path[index] != L'\0'; ++index) {
        if (path[index] == L'\\' || path[index] == L'/') {
            startIndex = index + 1;
        }
    }

    SIZE_T writeIndex = 0;
    while (writeIndex + 1 < bufferLength && path[startIndex + writeIndex] != L'\0') {
        WCHAR character = path[startIndex + writeIndex];
        if (character >= L'A' && character <= L'Z') {
            character = (WCHAR)(character - L'A' + L'a');
        }
        buffer[writeIndex] = character;
        writeIndex++;
    }

    buffer[writeIndex] = L'\0';
}

VOID QueueDriverEventNode(_Inout_opt_ PDRIVER_EVENT_NODE node) {
    if (node == NULL) {
        return;
    }

    KIRQL oldIrql;
    PIRP irpToComplete = NULL;

    KeAcquireSpinLock(&g_DriverQueueLock, &oldIrql);
    if (g_DriverEventCount < MAX_EVENT_COUNT) {
        InsertTailList(&g_DriverEventQueue, &node->ListEntry);
        g_DriverEventCount++;

        if (g_PendingDriverIrp != NULL) {
            if (IoSetCancelRoutine(g_PendingDriverIrp, NULL)) {
                irpToComplete = g_PendingDriverIrp;
                g_PendingDriverIrp = NULL;
                RemoveEntryList(&node->ListEntry);
                g_DriverEventCount--;
            }
            else {
                g_PendingDriverIrp = NULL;
            }
        }
    }
    else {
        InterlockedIncrement64(&g_DriverEventDropCount);
        FreeDriverEventNode(node);
        node = NULL;
    }
    KeReleaseSpinLock(&g_DriverQueueLock, oldIrql);

    if (irpToComplete != NULL && node != NULL) {
        RtlCopyMemory(irpToComplete->AssociatedIrp.SystemBuffer, &node->EventData, sizeof(DRIVER_EVENT));
        irpToComplete->IoStatus.Information = sizeof(DRIVER_EVENT);
        irpToComplete->IoStatus.Status = STATUS_SUCCESS;
        IoCompleteRequest(irpToComplete, IO_NO_INCREMENT);
        FreeDriverEventNode(node);
    }
}

static VOID QueueKernelEvent(
    _In_ ULONG eventType,
    _In_ ULONG registryOperation,
    _In_ ULONG fileOperation,
    _In_ ULONG processId,
    _In_opt_z_ PCWSTR processName,
    _In_opt_z_ PCWSTR ruleId,
    _In_ ULONG severity,
    _In_opt_ PCUNICODE_STRING targetPath,
    _In_opt_z_ PCWSTR infoClass,
    _In_opt_ PCUNICODE_STRING valueName,
    _In_opt_z_ PCWSTR valueData) {
    UNREFERENCED_PARAMETER(fileOperation);

    PDRIVER_EVENT_NODE node = AllocateDriverEventNode();
    if (!node) {
        InterlockedIncrement64(&g_DriverEventAllocFailCount);
        return;
    }
    node->EventData.EventType = eventType;
    node->EventData.RegistryOperation = registryOperation;
    node->EventData.ProcessId = processId;
    node->EventData.Severity = severity;
    CopyWideStringToFixedBuffer(node->EventData.ProcessName, RTL_NUMBER_OF(node->EventData.ProcessName), processName);
    CopyWideStringToFixedBuffer(node->EventData.RuleId, RTL_NUMBER_OF(node->EventData.RuleId), ruleId);
    CopyUnicodeStringToFixedBuffer(node->EventData.TargetPath, RTL_NUMBER_OF(node->EventData.TargetPath), targetPath);
    CopyWideStringToFixedBuffer(node->EventData.InfoClass, RTL_NUMBER_OF(node->EventData.InfoClass), infoClass);
    CopyUnicodeStringToFixedBuffer(node->EventData.ValueName, RTL_NUMBER_OF(node->EventData.ValueName), valueName);
    CopyWideStringToFixedBuffer(node->EventData.ValueData, RTL_NUMBER_OF(node->EventData.ValueData), valueData);
    QueueDriverEventNode(node);
}

static VOID QueueProcessObservedEvent(
    _In_ HANDLE processId,
    _In_opt_ HANDLE parentProcessId,
    _In_opt_z_ PCWSTR imagePath,
    _In_opt_z_ PCWSTR processName,
    _In_opt_z_ PCWSTR commandLine) {
    PDRIVER_EVENT_NODE node = AllocateDriverEventNode();
    if (!node) {
        InterlockedIncrement64(&g_DriverEventAllocFailCount);
        return;
    }

    node->EventData.EventType = DRIVER_EVENT_TYPE_OBSERVED_PROCESS_CREATE;
    node->EventData.ProcessId = HandleToULong(processId);
    node->EventData.ParentProcessId = HandleToULong(parentProcessId);
    CopyWideStringToFixedBuffer(node->EventData.ProcessName, RTL_NUMBER_OF(node->EventData.ProcessName), processName);
    CopyWideStringToFixedBuffer(node->EventData.CommandLine, RTL_NUMBER_OF(node->EventData.CommandLine), commandLine);
    CopyWideStringToFixedBuffer(node->EventData.TargetPath, RTL_NUMBER_OF(node->EventData.TargetPath), imagePath);
    QueueDriverEventNode(node);
}

const FLT_OPERATION_REGISTRATION g_FilterOperationCallbacks[] = {
    { IRP_MJ_CREATE, 0, FileProtectionPreCreate, NULL },
    { IRP_MJ_SET_INFORMATION, 0, FileProtectionPreSetInformation, NULL },
    { IRP_MJ_OPERATION_END }
};

const FLT_REGISTRATION g_FilterRegistration = {
    sizeof(FLT_REGISTRATION),
    FLT_REGISTRATION_VERSION,
    0,
    NULL,
    g_FilterOperationCallbacks,
    FileFilterUnload,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL
};

static SIZE_T SafeStringLength(_In_opt_z_ PCWSTR text) {
    return (text == NULL) ? 0 : wcslen(text);
}

static BOOLEAN StringsEqualInsensitive(_In_opt_z_ PCWSTR left, _In_opt_z_ PCWSTR right) {
    SIZE_T leftLength = SafeStringLength(left);
    SIZE_T rightLength = SafeStringLength(right);
    if (leftLength != rightLength) {
        return FALSE;
    }

    for (SIZE_T i = 0; i < leftLength; ++i) {
        if (RtlDowncaseUnicodeChar(left[i]) != RtlDowncaseUnicodeChar(right[i])) {
            return FALSE;
        }
    }

    return TRUE;
}

static BOOLEAN StartsWithInsensitive(_In_opt_z_ PCWSTR text, _In_opt_z_ PCWSTR prefix) {
    SIZE_T textLength = SafeStringLength(text);
    SIZE_T prefixLength = SafeStringLength(prefix);
    if (prefixLength == 0 || textLength < prefixLength) {
        return FALSE;
    }

    for (SIZE_T i = 0; i < prefixLength; ++i) {
        if (RtlDowncaseUnicodeChar(text[i]) != RtlDowncaseUnicodeChar(prefix[i])) {
            return FALSE;
        }
    }

    return TRUE;
}

static BOOLEAN EndsWithInsensitive(_In_opt_z_ PCWSTR text, _In_opt_z_ PCWSTR suffix) {
    SIZE_T textLength = SafeStringLength(text);
    SIZE_T suffixLength = SafeStringLength(suffix);
    if (suffixLength == 0 || textLength < suffixLength) {
        return FALSE;
    }

    SIZE_T start = textLength - suffixLength;
    for (SIZE_T i = 0; i < suffixLength; ++i) {
        if (RtlDowncaseUnicodeChar(text[start + i]) != RtlDowncaseUnicodeChar(suffix[i])) {
            return FALSE;
        }
    }

    return TRUE;
}

static BOOLEAN ContainsInsensitive(_In_opt_z_ PCWSTR text, _In_opt_z_ PCWSTR needle) {
    SIZE_T textLength = SafeStringLength(text);
    SIZE_T needleLength = SafeStringLength(needle);
    if (needleLength == 0 || textLength < needleLength) {
        return FALSE;
    }

    for (SIZE_T offset = 0; offset <= textLength - needleLength; ++offset) {
        BOOLEAN matched = TRUE;
        for (SIZE_T i = 0; i < needleLength; ++i) {
            if (RtlDowncaseUnicodeChar(text[offset + i]) != RtlDowncaseUnicodeChar(needle[i])) {
                matched = FALSE;
                break;
            }
        }

        if (matched) {
            return TRUE;
        }
    }

    return FALSE;
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

        unsigned int digit = 0xFFFFFFFF;
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

static BOOLEAN MatchRegistryField(
    _In_ ULONG matchType,
    _In_opt_z_ PCWSTR pattern,
    _In_opt_z_ PCWSTR candidate) {
    if (pattern == NULL || pattern[0] == L'\0') {
        return TRUE;
    }

    if (candidate == NULL || candidate[0] == L'\0') {
        return FALSE;
    }

    if (matchType == REGISTRY_MATCH_TYPE_EXACT) {
        ULONGLONG patternValue = 0;
        ULONGLONG candidateValue = 0;
        if (TryParseUnsignedInteger(pattern, &patternValue) &&
            TryParseUnsignedInteger(candidate, &candidateValue)) {
            return patternValue == candidateValue;
        }

        return StringsEqualInsensitive(pattern, candidate);
    }

    if (matchType == REGISTRY_MATCH_TYPE_PREFIX) {
        return StartsWithInsensitive(candidate, pattern);
    }

    if (matchType == REGISTRY_MATCH_TYPE_SUFFIX) {
        return EndsWithInsensitive(candidate, pattern);
    }

    if (matchType == REGISTRY_MATCH_TYPE_CONTAINS) {
        return ContainsInsensitive(candidate, pattern);
    }

    return FALSE;
}

static VOID GetCurrentProcessName(
    _Out_writes_(bufferLength) WCHAR* buffer,
    _In_ SIZE_T bufferLength) {
    if (buffer == NULL || bufferLength == 0) {
        return;
    }

    buffer[0] = L'\0';

    PUNICODE_STRING imagePath = NULL;
    if (!NT_SUCCESS(QueryProcessImageNameCompat(PsGetCurrentProcess(), &imagePath)) ||
        imagePath == NULL ||
        imagePath->Buffer == NULL ||
        imagePath->Length == 0) {
        return;
    }

    USHORT startIndex = 0;
    for (USHORT i = 0; i < imagePath->Length / sizeof(WCHAR); ++i) {
        if (imagePath->Buffer[i] == L'\\' || imagePath->Buffer[i] == L'/') {
            startIndex = (USHORT)(i + 1);
        }
    }

    SIZE_T i = 0;
    while (i + 1 < bufferLength &&
        (startIndex + i) < (imagePath->Length / sizeof(WCHAR))) {
        WCHAR ch = imagePath->Buffer[startIndex + i];
        if (ch >= L'A' && ch <= L'Z') {
            ch = (WCHAR)(ch - L'A' + L'a');
        }
        buffer[i] = ch;
        ++i;
    }

    buffer[i] = L'\0';
    ExFreePool(imagePath);
}

_IRQL_requires_(PASSIVE_LEVEL)
static VOID CaptureProcessImagePath(
    _In_opt_ PEPROCESS process,
    _Out_writes_(bufferLength) WCHAR* buffer,
    _In_ SIZE_T bufferLength) {
    if (buffer == NULL || bufferLength == 0) {
        return;
    }

    buffer[0] = L'\0';
    if (process == NULL || KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return;
    }

    PUNICODE_STRING imagePath = NULL;
    if (NT_SUCCESS(QueryProcessImageNameCompat(process, &imagePath)) &&
        imagePath != NULL &&
        imagePath->Buffer != NULL &&
        imagePath->Length > 0) {
        CopyUnicodeStringToFixedBuffer(buffer, bufferLength, imagePath);
    }

    if (imagePath != NULL) {
        ExFreePool(imagePath);
    }
}

_IRQL_requires_(PASSIVE_LEVEL)
static VOID CaptureProcessImagePathByProcessId(
    _In_opt_ HANDLE processId,
    _Out_writes_(bufferLength) WCHAR* buffer,
    _In_ SIZE_T bufferLength) {
    if (buffer == NULL || bufferLength == 0) {
        return;
    }

    buffer[0] = L'\0';
    if (processId == NULL) {
        return;
    }

    PEPROCESS process = NULL;
    if (!NT_SUCCESS(PsLookupProcessByProcessId(processId, &process))) {
        return;
    }

    CaptureProcessImagePath(process, buffer, bufferLength);
    ObDereferenceObject(process);
}

_IRQL_requires_(PASSIVE_LEVEL)
static VOID CaptureProcessCommandLine(
    _In_opt_ PEPROCESS process,
    _Out_writes_(bufferLength) WCHAR* buffer,
    _In_ SIZE_T bufferLength) {
    if (buffer == NULL || bufferLength == 0) {
        return;
    }

    buffer[0] = L'\0';
    if (process == NULL || KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return;
    }

    KAPC_STATE apcState;
    KeStackAttachProcess(process, &apcState);

    __try {
        PPEB_LITE peb = (PPEB_LITE)QueryProcessPebCompat(process);
        if (peb != NULL && peb->ProcessParameters != NULL) {
            CopyUnicodeStringToFixedBuffer(
                buffer,
                bufferLength,
                &peb->ProcessParameters->CommandLine);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        buffer[0] = L'\0';
    }

    KeUnstackDetachProcess(&apcState);
}

_IRQL_requires_(PASSIVE_LEVEL)
static VOID CaptureProcessCommandLineByProcessId(
    _In_opt_ HANDLE processId,
    _Out_writes_(bufferLength) WCHAR* buffer,
    _In_ SIZE_T bufferLength) {
    if (buffer == NULL || bufferLength == 0) {
        return;
    }

    buffer[0] = L'\0';
    if (processId == NULL) {
        return;
    }

    PEPROCESS process = NULL;
    if (!NT_SUCCESS(PsLookupProcessByProcessId(processId, &process))) {
        return;
    }

    CaptureProcessCommandLine(process, buffer, bufferLength);
    ObDereferenceObject(process);
}

static VOID FormatBinaryRegistryData(
    _In_reads_bytes_opt_(dataSize) const UCHAR* data,
    _In_ ULONG dataSize,
    _Out_writes_(bufferLength) WCHAR* buffer,
    _In_ SIZE_T bufferLength) {
    static const WCHAR kHexChars[] = L"0123456789abcdef";

    if (buffer == NULL || bufferLength == 0) {
        return;
    }

    buffer[0] = L'\0';
    if (data == NULL || dataSize == 0) {
        return;
    }

    SIZE_T cursor = 0;
    for (ULONG i = 0; i < dataSize && cursor + 2 < bufferLength; ++i) {
        buffer[cursor++] = kHexChars[(data[i] >> 4) & 0x0F];
        buffer[cursor++] = kHexChars[data[i] & 0x0F];
    }
    buffer[cursor] = L'\0';
}

_IRQL_requires_max_(APC_LEVEL)
static BOOLEAN CaptureRegistryDataBytes(
    _In_reads_bytes_opt_(dataSize) const VOID* data,
    _In_ ULONG dataSize,
    _Out_writes_bytes_(captureBufferSize) UCHAR* captureBuffer,
    _In_ ULONG captureBufferSize,
    _Out_ ULONG* capturedSize) {
    if (captureBuffer == NULL || captureBufferSize == 0 || capturedSize == NULL) {
        return FALSE;
    }

    *capturedSize = 0;
    if (data == NULL || dataSize == 0) {
        return FALSE;
    }

    ULONG bytesToCopy = dataSize;
    if (bytesToCopy > captureBufferSize) {
        bytesToCopy = captureBufferSize;
    }

    KPROCESSOR_MODE previousMode = ExGetPreviousMode();
    if (previousMode != KernelMode && KeGetCurrentIrql() > APC_LEVEL) {
        return FALSE;
    }

    __try {
        if (previousMode != KernelMode) {
            ProbeForRead((PVOID)data, bytesToCopy, sizeof(UCHAR));
        }
        RtlCopyMemory(captureBuffer, data, bytesToCopy);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }

    *capturedSize = bytesToCopy;
    return TRUE;
}

_IRQL_requires_max_(APC_LEVEL)
static BOOLEAN CaptureRegistryUnicodeString(
    _In_reads_bytes_opt_(dataSize) const VOID* data,
    _In_ ULONG dataSize,
    _Out_writes_(bufferLength) WCHAR* captureBuffer,
    _In_ SIZE_T bufferLength,
    _Out_ PUNICODE_STRING capturedValue) {
    if (captureBuffer == NULL || bufferLength == 0 || capturedValue == NULL) {
        return FALSE;
    }

    captureBuffer[0] = L'\0';
    RtlZeroMemory(capturedValue, sizeof(*capturedValue));

    if (data == NULL || dataSize == 0 || (dataSize % sizeof(WCHAR)) != 0) {
        return FALSE;
    }

    ULONG maxBytes = (ULONG)((bufferLength - 1) * sizeof(WCHAR));
    ULONG capturedBytes = 0;
    if (!CaptureRegistryDataBytes(data, dataSize, (UCHAR*)captureBuffer, maxBytes, &capturedBytes)) {
        return FALSE;
    }

    capturedBytes -= (capturedBytes % sizeof(WCHAR));
    captureBuffer[capturedBytes / sizeof(WCHAR)] = L'\0';

    capturedValue->Buffer = captureBuffer;
    capturedValue->Length = (USHORT)capturedBytes;
    capturedValue->MaximumLength = (USHORT)(bufferLength * sizeof(WCHAR));

    while (capturedValue->Length > 0 &&
        capturedValue->Buffer[(capturedValue->Length / sizeof(WCHAR)) - 1] == L'\0') {
        capturedValue->Length -= sizeof(WCHAR);
    }

    return TRUE;
}

static VOID ExtractRegistryValueDataString(
    _In_ ULONG type,
    _In_reads_bytes_opt_(dataSize) const VOID* data,
    _In_ ULONG dataSize,
    _Out_writes_(bufferLength) WCHAR* buffer,
    _In_ SIZE_T bufferLength) {
    if (buffer == NULL || bufferLength == 0) {
        return;
    }

    buffer[0] = L'\0';
    if (data == NULL || dataSize == 0) {
        return;
    }

    if (type == REG_SZ || type == REG_EXPAND_SZ || type == REG_LINK) {
        WCHAR capturedString[MAX_RULE_LENGTH];
        UNICODE_STRING valueData;

        RtlZeroMemory(capturedString, sizeof(capturedString));
        if (!CaptureRegistryUnicodeString(data, dataSize, capturedString, RTL_NUMBER_OF(capturedString), &valueData)) {
            return;
        }

        CopyUnicodeStringToFixedBuffer(buffer, bufferLength, &valueData);
        return;
    }

    if (type == REG_MULTI_SZ) {
        WCHAR capturedMulti[MAX_RULE_LENGTH];
        UNICODE_STRING multiData;
        SIZE_T cursor = 0;

        RtlZeroMemory(capturedMulti, sizeof(capturedMulti));
        if (!CaptureRegistryUnicodeString(data, dataSize, capturedMulti, RTL_NUMBER_OF(capturedMulti), &multiData)) {
            return;
        }

        SIZE_T chars = multiData.Length / sizeof(WCHAR);
        for (SIZE_T i = 0; i < chars && cursor + 1 < bufferLength; ++i) {
            WCHAR ch = capturedMulti[i];
            if (ch == L'\0') {
                if (i + 1 >= chars || capturedMulti[i + 1] == L'\0') {
                    break;
                }

                if (cursor > 0 && buffer[cursor - 1] != L';') {
                    buffer[cursor++] = L';';
                }
            }
            else {
                buffer[cursor++] = ch;
            }
        }

        buffer[cursor] = L'\0';
        return;
    }

    if (type == REG_DWORD) {
        ULONG number = 0;
        ULONG capturedBytes = 0;
        if (CaptureRegistryDataBytes(data, dataSize, (UCHAR*)&number, sizeof(number), &capturedBytes) &&
            capturedBytes >= sizeof(number)) {
            RtlStringCchPrintfW(buffer, bufferLength, L"%lu", number);
        }
        return;
    }

    if (type == REG_QWORD) {
        ULONGLONG number = 0;
        ULONG capturedBytes = 0;
        if (CaptureRegistryDataBytes(data, dataSize, (UCHAR*)&number, sizeof(number), &capturedBytes) &&
            capturedBytes >= sizeof(number)) {
            RtlStringCchPrintfW(buffer, bufferLength, L"%llu", number);
        }
        return;
    }

    UCHAR capturedBinary[MAX_RULE_LENGTH];
    ULONG capturedBytes = 0;
    if (CaptureRegistryDataBytes(data, dataSize, capturedBinary, sizeof(capturedBinary), &capturedBytes)) {
        FormatBinaryRegistryData(capturedBinary, capturedBytes, buffer, bufferLength);
    }
}

static NTSTATUS QueryRegistryObjectPath(
    _In_opt_ PVOID object,
    _Outptr_result_maybenull_ PCUNICODE_STRING* objectName,
    _Out_opt_ PBOOLEAN releaseRequired) {
    if (objectName == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *objectName = NULL;
    if (releaseRequired != NULL) {
        *releaseRequired = FALSE;
    }

    if (object == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    return QueryRegistryObjectNameCompat(&g_RegCookie, object, objectName, releaseRequired);
}

static VOID BuildRegistryCreatePath(
    _In_ PREG_CREATE_KEY_INFORMATION_V1 info,
    _Out_writes_(bufferLength) WCHAR* buffer,
    _In_ SIZE_T bufferLength,
    _Out_ NTSTATUS* rootStatus,
    _Outptr_result_maybenull_ PCUNICODE_STRING* rootKeyPath,
    _Out_opt_ PBOOLEAN rootKeyReleaseRequired) {
    if (buffer == NULL || bufferLength == 0 || rootStatus == NULL || rootKeyPath == NULL) {
        return;
    }

    buffer[0] = L'\0';
    *rootStatus = STATUS_UNSUCCESSFUL;
    *rootKeyPath = NULL;
    if (rootKeyReleaseRequired != NULL) {
        *rootKeyReleaseRequired = FALSE;
    }

    if (info == NULL) {
        return;
    }

    WCHAR completeNameBuffer[MAX_REG_PATH_LENGTH] = {};
    if (!CaptureUnicodeStringToLocalText(info->CompleteName, completeNameBuffer, RTL_NUMBER_OF(completeNameBuffer))) {
        return;
    }

    if (completeNameBuffer[0] == L'\\') {
        CopyWideStringToFixedBuffer(buffer, bufferLength, completeNameBuffer);
        return;
    }

    if (info->RootObject != NULL) {
        *rootStatus = QueryRegistryObjectPath(info->RootObject, rootKeyPath, rootKeyReleaseRequired);
        if (NT_SUCCESS(*rootStatus) && *rootKeyPath != NULL) {
            WCHAR rootBuffer[MAX_REG_PATH_LENGTH] = {};

            if (CaptureUnicodeStringToLocalText(*rootKeyPath, rootBuffer, RTL_NUMBER_OF(rootBuffer)) &&
                NT_SUCCESS(RtlStringCchCopyW(buffer, bufferLength, rootBuffer))) {
                SIZE_T currentLength = wcslen(buffer);
                if (currentLength > 0 && buffer[currentLength - 1] != L'\\' && completeNameBuffer[0] != L'\\') {
                    RtlStringCchCatW(buffer, bufferLength, L"\\");
                }
                RtlStringCchCatW(buffer, bufferLength, completeNameBuffer);
                return;
            }
        }
    }

    CopyWideStringToFixedBuffer(buffer, bufferLength, completeNameBuffer);
}

static VOID FormatBinaryRegistryData(
    _In_reads_bytes_opt_(dataSize) const UCHAR* data,
    _In_ ULONG dataSize,
    _Out_writes_(bufferLength) WCHAR* buffer,
    _In_ SIZE_T bufferLength);

static PCWSTR GetKeySetInformationClassName(_In_ KEY_SET_INFORMATION_CLASS infoClass) {
    switch (infoClass) {
    case KeyWriteTimeInformation:
        return L"KeyWriteTimeInformation";
    case KeyWow64FlagsInformation:
        return L"KeyWow64FlagsInformation";
    case KeyControlFlagsInformation:
        return L"KeyControlFlagsInformation";
    case KeySetVirtualizationInformation:
        return L"KeySetVirtualizationInformation";
    case KeySetDebugInformation:
        return L"KeySetDebugInformation";
    case KeySetHandleTagsInformation:
        return L"KeySetHandleTagsInformation";
    case KeySetLayerInformation:
        return L"KeySetLayerInformation";
    default:
        return L"UnknownKeySetInformationClass";
    }
}

static VOID ExtractSetInformationKeyDataString(
    _In_ KEY_SET_INFORMATION_CLASS infoClass,
    _In_reads_bytes_opt_(dataLength) const VOID* data,
    _In_ ULONG dataLength,
    _Out_writes_(bufferLength) WCHAR* buffer,
    _In_ SIZE_T bufferLength) {
    if (buffer == NULL || bufferLength == 0) {
        return;
    }

    buffer[0] = L'\0';
    if (data == NULL || dataLength == 0) {
        return;
    }

    if (infoClass == KeyWriteTimeInformation) {
        LARGE_INTEGER timestamp = {};
        ULONG capturedBytes = 0;
        if (CaptureRegistryDataBytes(data, dataLength, (UCHAR*)&timestamp, sizeof(timestamp), &capturedBytes) &&
            capturedBytes >= sizeof(timestamp)) {
            RtlStringCchPrintfW(buffer, bufferLength, L"%lld", timestamp.QuadPart);
        }
        return;
    }

    if (infoClass == KeyWow64FlagsInformation ||
        infoClass == KeySetVirtualizationInformation ||
        infoClass == KeyControlFlagsInformation ||
        infoClass == KeySetDebugInformation ||
        infoClass == KeySetHandleTagsInformation ||
        infoClass == KeySetLayerInformation) {
        ULONG number = 0;
        ULONG capturedBytes = 0;
        if (CaptureRegistryDataBytes(data, dataLength, (UCHAR*)&number, sizeof(number), &capturedBytes) &&
            capturedBytes >= sizeof(number)) {
            RtlStringCchPrintfW(buffer, bufferLength, L"0x%08lx", number);
        }
        return;
    }

    UCHAR capturedBinary[MAX_RULE_LENGTH];
    ULONG capturedBytes = 0;
    if (CaptureRegistryDataBytes(data, dataLength, capturedBinary, sizeof(capturedBinary), &capturedBytes)) {
        FormatBinaryRegistryData(capturedBinary, capturedBytes, buffer, bufferLength);
    }
}

static BOOLEAN MatchRegistryRule(
    _In_ const REGISTRY_RULE* rule,
    _In_ ULONG actualOperation,
    _In_opt_z_ PCWSTR processName,
    _In_opt_z_ PCWSTR keyPath,
    _In_opt_z_ PCWSTR infoClass,
    _In_opt_z_ PCWSTR valueName,
    _In_opt_z_ PCWSTR valueData) {
    if (rule == NULL || rule->Operation != actualOperation) {
        return FALSE;
    }

    if ((rule->MatchFlags & REGISTRY_MATCH_FLAG_PROCESS_NAME) &&
        !MatchRegistryField(rule->ProcessNameMatchType, rule->ProcessName, processName)) {
        return FALSE;
    }

    if ((rule->MatchFlags & REGISTRY_MATCH_FLAG_KEY_PATH) &&
        !MatchRegistryField(rule->KeyPathMatchType, rule->KeyPath, keyPath)) {
        return FALSE;
    }

    if ((rule->MatchFlags & REGISTRY_MATCH_FLAG_INFO_CLASS) &&
        !MatchRegistryField(rule->InfoClassMatchType, rule->InfoClass, infoClass)) {
        return FALSE;
    }

    if ((rule->MatchFlags & REGISTRY_MATCH_FLAG_VALUE_NAME) &&
        !MatchRegistryField(rule->ValueNameMatchType, rule->ValueName, valueName)) {
        return FALSE;
    }

    if ((rule->MatchFlags & REGISTRY_MATCH_FLAG_VALUE_DATA) &&
        !MatchRegistryField(rule->ValueDataMatchType, rule->ValueData, valueData)) {
        return FALSE;
    }

    return TRUE;
}

static _Must_inspect_result_ const REGISTRY_RULE* MatchRegistryRuleArray(
    _In_reads_opt_(ruleCount) const REGISTRY_RULE* rules,
    _In_ ULONG ruleCount,
    _In_ ULONG actualOperation,
    _In_opt_z_ PCWSTR processName,
    _In_opt_z_ PCWSTR keyPath,
    _In_opt_z_ PCWSTR infoClass,
    _In_opt_z_ PCWSTR valueName,
    _In_opt_z_ PCWSTR valueData) {
    if (rules == NULL || ruleCount == 0) {
        return NULL;
    }

    for (ULONG index = 0; index < ruleCount; ++index) {
        const REGISTRY_RULE* currentRule = &rules[index];
        if (MatchRegistryRule(
                currentRule,
                actualOperation,
                processName,
                keyPath,
                infoClass,
                valueName,
                valueData)) {
            return currentRule;
        }
    }

    return NULL;
}

static _Must_inspect_result_ const REGISTRY_RULE* MatchRegistryRuleArrayWithOrdinal(
    _In_reads_opt_(ruleCount) const REGISTRY_RULE* rules,
    _In_reads_opt_(ruleCount) const ULONG* ruleOrdinals,
    _In_ ULONG ruleCount,
    _In_ ULONG actualOperation,
    _In_opt_z_ PCWSTR processName,
    _In_opt_z_ PCWSTR keyPath,
    _In_opt_z_ PCWSTR infoClass,
    _In_opt_z_ PCWSTR valueName,
    _In_opt_z_ PCWSTR valueData,
    _Out_opt_ PULONG matchedOrdinal) {
    if (matchedOrdinal != NULL) {
        *matchedOrdinal = MAXULONG;
    }

    const REGISTRY_RULE* matchedRule = MatchRegistryRuleArray(
        rules,
        ruleCount,
        actualOperation,
        processName,
        keyPath,
        infoClass,
        valueName,
        valueData);
    if (matchedRule == NULL) {
        return NULL;
    }

    ULONG matchIndex = (ULONG)(matchedRule - rules);
    if (matchedOrdinal != NULL) {
        if (ruleOrdinals != NULL && matchIndex < ruleCount) {
            *matchedOrdinal = ruleOrdinals[matchIndex];
        }
        else {
            *matchedOrdinal = matchIndex;
        }
    }

    return matchedRule;
}

static VOID ConsiderRegistryRuleCandidate(
    _Inout_ const REGISTRY_RULE** bestRule,
    _Inout_ PULONG bestOrdinal,
    _In_opt_ const REGISTRY_RULE* candidateRule,
    _In_ ULONG candidateOrdinal) {
    if (bestRule == NULL || bestOrdinal == NULL) {
        return;
    }

    if (candidateRule != NULL && candidateOrdinal < *bestOrdinal) {
        *bestRule = candidateRule;
        *bestOrdinal = candidateOrdinal;
    }
}

static _Must_inspect_result_ const REGISTRY_RULE* MatchRegistryRuleStore(
    _In_opt_ const RULE_STORE* store,
    _In_ ULONG actualOperation,
    _In_opt_z_ PCWSTR processName,
    _In_opt_z_ PCWSTR keyPath,
    _In_opt_z_ PCWSTR infoClass,
    _In_opt_z_ PCWSTR valueName,
    _In_opt_z_ PCWSTR valueData) {
    const REGISTRY_RULE* matchedRule = NULL;
    ULONG bestOrdinal = MAXULONG;
    ULONG candidateOrdinal = MAXULONG;

    if (store == NULL) {
        return NULL;
    }

    const REGISTRY_RULE* candidateRule = FindExactRegistryRuleMatch(
        store,
        actualOperation,
        processName,
        keyPath,
        infoClass,
        valueName,
        valueData,
        &candidateOrdinal);
    ConsiderRegistryRuleCandidate(&matchedRule, &bestOrdinal, candidateRule, candidateOrdinal);
    if (bestOrdinal == 0) {
        return matchedRule;
    }

    candidateRule = MatchRegistryRuleArrayWithOrdinal(
        store->PrefixRules,
        store->PrefixRuleOrdinals,
        store->PrefixRuleCount,
        actualOperation,
        processName,
        keyPath,
        infoClass,
        valueName,
        valueData,
        &candidateOrdinal);
    ConsiderRegistryRuleCandidate(&matchedRule, &bestOrdinal, candidateRule, candidateOrdinal);
    if (bestOrdinal == 0) {
        return matchedRule;
    }

    candidateRule = MatchRegistryRuleArrayWithOrdinal(
        store->SuffixRules,
        store->SuffixRuleOrdinals,
        store->SuffixRuleCount,
        actualOperation,
        processName,
        keyPath,
        infoClass,
        valueName,
        valueData,
        &candidateOrdinal);
    ConsiderRegistryRuleCandidate(&matchedRule, &bestOrdinal, candidateRule, candidateOrdinal);
    if (bestOrdinal == 0) {
        return matchedRule;
    }

    candidateRule = MatchRegistryRuleArrayWithOrdinal(
        store->ContainsRules,
        store->ContainsRuleOrdinals,
        store->ContainsRuleCount,
        actualOperation,
        processName,
        keyPath,
        infoClass,
        valueName,
        valueData,
        &candidateOrdinal);
    ConsiderRegistryRuleCandidate(&matchedRule, &bestOrdinal, candidateRule, candidateOrdinal);

    return matchedRule;
}

NTSTATUS FileFilterUnload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags) {
    UNREFERENCED_PARAMETER(Flags);
    return STATUS_SUCCESS;
}

NTSTATUS RegistryCallback(_In_ PVOID CallbackContext, _In_ PVOID Argument1, _In_ PVOID Argument2) {
    UNREFERENCED_PARAMETER(CallbackContext);

    if (!ExAcquireRundownProtection(&g_RundownRef)) {
        return STATUS_SUCCESS;
    }

    REG_NOTIFY_CLASS notifyClass = (REG_NOTIFY_CLASS)(ULONG_PTR)Argument1;
    NTSTATUS status = STATUS_SUCCESS;
    ULONG registryOperation = 0;

    WCHAR processName[MAX_RULE_LENGTH];
    WCHAR keyPathBuffer[MAX_REG_PATH_LENGTH];
    WCHAR infoClassBuffer[MAX_RULE_LENGTH];
    WCHAR valueNameBuffer[MAX_RULE_LENGTH];
    WCHAR valueDataBuffer[MAX_RULE_LENGTH];
    WCHAR matchedRuleId[MAX_RULE_ID_LENGTH];
    WCHAR matchedAllowRuleId[MAX_RULE_ID_LENGTH];
    ULONG matchedRuleSeverity = 0;
    BOOLEAN registryAllowMatched = FALSE;
    BOOLEAN registryRuleMatched = FALSE;

    PCUNICODE_STRING keyPath = NULL;
    NTSTATUS keyStatus = STATUS_UNSUCCESSFUL;
    BOOLEAN keyReleaseRequired = FALSE;
    PCUNICODE_STRING rootKeyPath = NULL;
    NTSTATUS rootKeyStatus = STATUS_UNSUCCESSFUL;
    BOOLEAN rootKeyReleaseRequired = FALSE;

    GetCurrentProcessName(processName, RTL_NUMBER_OF(processName));
    keyPathBuffer[0] = L'\0';
    infoClassBuffer[0] = L'\0';
    valueNameBuffer[0] = L'\0';
    valueDataBuffer[0] = L'\0';
    matchedRuleId[0] = L'\0';
    matchedAllowRuleId[0] = L'\0';

    switch (notifyClass) {
    case RegNtPreSetValueKey: {
        PREG_SET_VALUE_KEY_INFORMATION info = (PREG_SET_VALUE_KEY_INFORMATION)Argument2;
        if (info == NULL) {
            goto Cleanup;
        }

        registryOperation = REGISTRY_OPERATION_SET_VALUE;
        keyStatus = QueryRegistryObjectPath(info->Object, &keyPath, &keyReleaseRequired);
        if (NT_SUCCESS(keyStatus) && keyPath != NULL) {
            CaptureUnicodeStringToLocalText(keyPath, keyPathBuffer, RTL_NUMBER_OF(keyPathBuffer));
        }

        if (info->ValueName != NULL) {
            CaptureUnicodeStringToLocalText(info->ValueName, valueNameBuffer, RTL_NUMBER_OF(valueNameBuffer));
        }

        ExtractRegistryValueDataString(info->Type, info->Data, info->DataSize, valueDataBuffer, RTL_NUMBER_OF(valueDataBuffer));

        break;
    }

    case RegNtPreCreateKey:
    case RegNtPreCreateKeyEx: {
        PREG_CREATE_KEY_INFORMATION_V1 info = (PREG_CREATE_KEY_INFORMATION_V1)Argument2;
        if (info == NULL) {
            goto Cleanup;
        }

        registryOperation = REGISTRY_OPERATION_CREATE_KEY;
        BuildRegistryCreatePath(
            info,
            keyPathBuffer,
            RTL_NUMBER_OF(keyPathBuffer),
            &rootKeyStatus,
            &rootKeyPath,
            &rootKeyReleaseRequired);
        break;
    }

    case RegNtPreDeleteValueKey: {
        PREG_DELETE_VALUE_KEY_INFORMATION info = (PREG_DELETE_VALUE_KEY_INFORMATION)Argument2;
        if (info == NULL) {
            goto Cleanup;
        }

        registryOperation = REGISTRY_OPERATION_DELETE_VALUE;
        keyStatus = QueryRegistryObjectPath(info->Object, &keyPath, &keyReleaseRequired);
        if (NT_SUCCESS(keyStatus) && keyPath != NULL) {
            CaptureUnicodeStringToLocalText(keyPath, keyPathBuffer, RTL_NUMBER_OF(keyPathBuffer));
        }

        if (info->ValueName != NULL) {
            CaptureUnicodeStringToLocalText(info->ValueName, valueNameBuffer, RTL_NUMBER_OF(valueNameBuffer));
        }
        break;
    }

    case RegNtPreDeleteKey: {
        PREG_DELETE_KEY_INFORMATION info = (PREG_DELETE_KEY_INFORMATION)Argument2;
        if (info == NULL) {
            goto Cleanup;
        }

        registryOperation = REGISTRY_OPERATION_DELETE_KEY;
        keyStatus = QueryRegistryObjectPath(info->Object, &keyPath, &keyReleaseRequired);
        if (NT_SUCCESS(keyStatus) && keyPath != NULL) {
            CaptureUnicodeStringToLocalText(keyPath, keyPathBuffer, RTL_NUMBER_OF(keyPathBuffer));
        }
        break;
    }

    case RegNtPreRenameKey: {
        PREG_RENAME_KEY_INFORMATION info = (PREG_RENAME_KEY_INFORMATION)Argument2;
        if (info == NULL) {
            goto Cleanup;
        }

        registryOperation = REGISTRY_OPERATION_RENAME_KEY;
        keyStatus = QueryRegistryObjectPath(info->Object, &keyPath, &keyReleaseRequired);
        if (NT_SUCCESS(keyStatus) && keyPath != NULL) {
            CaptureUnicodeStringToLocalText(keyPath, keyPathBuffer, RTL_NUMBER_OF(keyPathBuffer));
        }

        if (info->NewName != NULL) {
            CaptureUnicodeStringToLocalText(info->NewName, valueDataBuffer, RTL_NUMBER_OF(valueDataBuffer));
        }
        break;
    }

    case RegNtPreSetInformationKey: {
        PREG_SET_INFORMATION_KEY_INFORMATION info = (PREG_SET_INFORMATION_KEY_INFORMATION)Argument2;
        if (info == NULL) {
            goto Cleanup;
        }

        registryOperation = REGISTRY_OPERATION_SET_INFORMATION_KEY;
        keyStatus = QueryRegistryObjectPath(info->Object, &keyPath, &keyReleaseRequired);
        if (NT_SUCCESS(keyStatus) && keyPath != NULL) {
            CaptureUnicodeStringToLocalText(keyPath, keyPathBuffer, RTL_NUMBER_OF(keyPathBuffer));
        }

        CopyWideStringToFixedBuffer(
            infoClassBuffer,
            RTL_NUMBER_OF(infoClassBuffer),
            GetKeySetInformationClassName(info->KeySetInformationClass));
        ExtractSetInformationKeyDataString(
            info->KeySetInformationClass,
            info->KeySetInformation,
            info->KeySetInformationLength,
            valueDataBuffer,
            RTL_NUMBER_OF(valueDataBuffer));
        break;
    }

    default:
        goto Cleanup;
    }

    {
        PRULE_STORE allowStore = NULL;
        AcquireRuleStoreSnapshot(&g_RegistryAllowRuleStore, &allowStore);

        const REGISTRY_RULE* matchedAllowRule = MatchRegistryRuleStore(
            allowStore,
            registryOperation,
            processName,
            keyPathBuffer,
            infoClassBuffer,
            valueNameBuffer,
            valueDataBuffer);
        if (matchedAllowRule != NULL) {
            CopyWideStringToFixedBuffer(
                matchedAllowRuleId,
                RTL_NUMBER_OF(matchedAllowRuleId),
                matchedAllowRule->RuleId);
            registryAllowMatched = TRUE;
        }

        ReleaseRuleStoreSnapshot(allowStore);
    }

    if (!registryAllowMatched) {
        PRULE_STORE blockStore = NULL;
        AcquireRuleStoreSnapshot(&g_RegistryBlockRuleStore, &blockStore);

        const REGISTRY_RULE* matchedBlockRule = MatchRegistryRuleStore(
            blockStore,
            registryOperation,
            processName,
            keyPathBuffer,
            infoClassBuffer,
            valueNameBuffer,
            valueDataBuffer);
        if (matchedBlockRule != NULL) {
            CopyWideStringToFixedBuffer(
                matchedRuleId,
                RTL_NUMBER_OF(matchedRuleId),
                matchedBlockRule->RuleId);
            matchedRuleSeverity = matchedBlockRule->Severity;
            registryRuleMatched = TRUE;
        }

        ReleaseRuleStoreSnapshot(blockStore);
    }
    else {
        KdPrint(("[EDR] Allowed registry operation by allow rule. Operation=%lu RuleId=%ws Key=%ws Value=%ws Data=%ws\n",
            registryOperation,
            matchedAllowRuleId,
            keyPathBuffer,
            valueNameBuffer,
            valueDataBuffer));
    }

    if (registryRuleMatched) {
        UNICODE_STRING keyPathString;
        UNICODE_STRING valueNameString;
        BOOLEAN shouldBlock = (g_ProtectionMode == HIPS_MODE_BLOCKING);
        ULONG driverEventType = shouldBlock
            ? DRIVER_EVENT_TYPE_BLOCKED_REGISTRY_OPERATION
            : DRIVER_EVENT_TYPE_OBSERVED_REGISTRY_OPERATION;

        RtlInitUnicodeString(&keyPathString, keyPathBuffer);
        RtlInitUnicodeString(&valueNameString, valueNameBuffer);

        if (shouldBlock) {
            KdPrint(("[EDR] Blocked registry operation. Operation=%lu RuleId=%ws Key=%ws InfoClass=%ws Value=%ws Data=%ws\n",
                registryOperation,
                matchedRuleId,
                keyPathBuffer,
                infoClassBuffer,
                valueNameBuffer,
                valueDataBuffer));
        }
        else {
            KdPrint(("[EDR] Observed registry operation in monitor-only mode. Operation=%lu RuleId=%ws Key=%ws InfoClass=%ws Value=%ws Data=%ws\n",
                registryOperation,
                matchedRuleId,
                keyPathBuffer,
                infoClassBuffer,
                valueNameBuffer,
                valueDataBuffer));
        }

        QueueKernelEvent(
            driverEventType,
            registryOperation,
            0,
            HandleToULong(PsGetCurrentProcessId()),
            processName,
            matchedRuleId,
            matchedRuleSeverity,
            &keyPathString,
            infoClassBuffer,
            &valueNameString,
            valueDataBuffer);
        status = shouldBlock ? STATUS_ACCESS_DENIED : STATUS_SUCCESS;
    }

Cleanup:
    ReleaseRegistryObjectNameCompat(keyPath, keyReleaseRequired);
    ReleaseRegistryObjectNameCompat(rootKeyPath, rootKeyReleaseRequired);

    ExReleaseRundownProtection(&g_RundownRef);
    return status;
}

_IRQL_requires_max_(APC_LEVEL)
static LARGE_INTEGER ProcessVerdictWaitTimeout(_Out_opt_ PULONG timeoutMs) {
    ULONG configuredTimeoutMs = PROCESS_VERDICT_TIMEOUT_MS_DEFAULT;

    AcquireSharedResourceLock(&g_RuntimeStatusLock);
    if (g_ProcessVerdictTimeoutMs >= PROCESS_VERDICT_TIMEOUT_MS_MIN &&
        g_ProcessVerdictTimeoutMs <= PROCESS_VERDICT_TIMEOUT_MS_MAX) {
        configuredTimeoutMs = g_ProcessVerdictTimeoutMs;
    }
    ReleaseSharedResourceLock(&g_RuntimeStatusLock);

    if (timeoutMs != NULL) {
        *timeoutMs = configuredTimeoutMs;
    }

    LARGE_INTEGER timeout;
    timeout.QuadPart = -((LONGLONG)configuredTimeoutMs * 10 * 1000);
    return timeout;
}

void ProcessNotifyCallbackEx(_Inout_ PEPROCESS Process, _In_ HANDLE ProcessId, _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo) {
    if (!ExAcquireRundownProtection(&g_RundownRef)) {
        return;
    }

    const ULONG currentProcessId = HandleToULong(ProcessId);

    if (CreateInfo == NULL) {
        RemoveFastPathTrustedProcess(currentProcessId);
        FlushDecisionCacheForProcess(currentProcessId);
        ExReleaseRundownProtection(&g_RundownRef);
        return;
    }

    const HANDLE parentProcessId = CreateInfo->ParentProcessId;
    PROCESS_IDENTITY subjectIdentity = {};
    BOOLEAN subjectIdentityCaptured = FALSE;
    DECISION_CACHE_KEY cacheKey = {};
    BOOLEAN cacheKeyBuilt = FALSE;

    if (g_ProtectionMode == HIPS_MODE_MONITOR_ONLY) {
        WCHAR observedImagePath[MAX_REG_PATH_LENGTH] = {};
        WCHAR observedProcessName[MAX_RULE_LENGTH] = {};
        WCHAR observedCommandLine[MAX_EVENT_COMMAND_LINE_LENGTH] = {};
        UNICODE_STRING capturedObservedImagePath = {};
        UNICODE_STRING capturedObservedCommandLine = {};

        if (!CaptureUnicodeStringToLocalBuffer(
            CreateInfo->ImageFileName,
            observedImagePath,
            RTL_NUMBER_OF(observedImagePath),
            &capturedObservedImagePath)) {
            CaptureProcessImagePath(Process, observedImagePath, RTL_NUMBER_OF(observedImagePath));
        }

        if (observedImagePath[0] != L'\0') {
            ExtractProcessNameFromPathBuffer(
                observedImagePath,
                observedProcessName,
                RTL_NUMBER_OF(observedProcessName));
        }
        else {
            CaptureProcessShortName(Process, observedProcessName, RTL_NUMBER_OF(observedProcessName));
        }

        CaptureUnicodeStringToLocalBufferWithEllipsis(
            CreateInfo->CommandLine,
            observedCommandLine,
            RTL_NUMBER_OF(observedCommandLine),
            &capturedObservedCommandLine);

        QueueProcessObservedEvent(
            ProcessId,
            parentProcessId,
            observedImagePath,
            observedProcessName,
            observedCommandLine);
        ExReleaseRundownProtection(&g_RundownRef);
        return;
    }

    if (InterlockedCompareExchange(&g_ProcessVerdictBreakerOpen, 0, 0) != 0) {
        ExReleaseRundownProtection(&g_RundownRef);
        return;
    }

    ULONG failMode = PROCESS_VERDICT_FAIL_OPEN;
    AcquireSharedResourceLock(&g_RuntimeStatusLock);
    if (g_ProcessVerdictFailMode == PROCESS_VERDICT_FAIL_CLOSE) {
        failMode = PROCESS_VERDICT_FAIL_CLOSE;
    }
    ReleaseSharedResourceLock(&g_RuntimeStatusLock);

    PROCESS_PORT_REQUEST request = {};
    request.Version = PROCESS_PORT_PROTOCOL_VERSION;
    request.ProcessId = currentProcessId;
    request.ParentProcessId = HandleToULong(parentProcessId);
    if (CreateInfo->FileOpenNameAvailable) {
        request.Flags |= PROCESS_PORT_REQUEST_FLAG_FILE_OPEN_NAME_AVAILABLE;
    }

    subjectIdentityCaptured = CaptureProcessIdentityByProcessId(parentProcessId, &subjectIdentity);

    UNICODE_STRING capturedImagePath = {};
    if (!CaptureUnicodeStringToLocalBuffer(
        CreateInfo->ImageFileName,
        request.ImagePath,
        RTL_NUMBER_OF(request.ImagePath),
        &capturedImagePath)) {
        CaptureProcessImagePath(Process, request.ImagePath, RTL_NUMBER_OF(request.ImagePath));
    }

    if (subjectIdentityCaptured &&
        EvaluateFastPathProcessCreateAllow(&subjectIdentity)) {
        ExReleaseRundownProtection(&g_RundownRef);
        return;
    }

    cacheKeyBuilt = BuildProcessCreateDecisionCacheKey(
        subjectIdentityCaptured ? &subjectIdentity : NULL,
        request.ImagePath,
        &cacheKey);
    if (cacheKeyBuilt &&
        TryGetDecisionCacheAllow(&cacheKey)) {
        ExReleaseRundownProtection(&g_RundownRef);
        return;
    }

    RecordSlowPathProcessVerdict();

    PFLT_FILTER filterHandle = NULL;
    PFLT_PORT clientPort = NULL;

    AcquireSharedResourceLock(&g_ProcessPortLock);
    filterHandle = g_FilterHandle;
    clientPort = g_ProcessClientPort;
    ReleaseSharedResourceLock(&g_ProcessPortLock);

    if (filterHandle == NULL || clientPort == NULL) {
        if (failMode == PROCESS_VERDICT_FAIL_CLOSE) {
            CreateInfo->CreationStatus = STATUS_ACCESS_DENIED;
            KdPrint(("[EDR] Process verdict channel offline and fail-close is enabled. PID=%lu\n",
                currentProcessId));
        }

        ExReleaseRundownProtection(&g_RundownRef);
        return;
    }

    BOOLEAN blockProcess = FALSE;
    request.EventId = (ULONGLONG)InterlockedIncrement64(&g_NextProcessEventId);
    if (request.EventId == 0) {
        request.EventId = (ULONGLONG)InterlockedIncrement64(&g_NextProcessEventId);
    }

    LARGE_INTEGER createTime;
    KeQuerySystemTime(&createTime);
    request.CreateTime = (ULONGLONG)createTime.QuadPart;

    CaptureProcessImagePathByProcessId(
        parentProcessId,
        request.ParentImagePath,
        RTL_NUMBER_OF(request.ParentImagePath));

    UNICODE_STRING capturedCommandLine = {};
    if (!CaptureUnicodeStringToLocalBuffer(
        CreateInfo->CommandLine,
        request.CommandLine,
        RTL_NUMBER_OF(request.CommandLine),
        &capturedCommandLine)) {
        request.CommandLine[0] = L'\0';
    }

    BOOLEAN captureParentCmdline = FALSE;
    AcquireSharedResourceLock(&g_RuntimeStatusLock);
    if (g_CaptureParentCommandLine == PROCESS_PARENT_CMDLINE_CAPTURE_ENABLED) {
        captureParentCmdline = TRUE;
    }
    ReleaseSharedResourceLock(&g_RuntimeStatusLock);

    if (captureParentCmdline) {
        CaptureProcessCommandLineByProcessId(
            parentProcessId,
            request.ParentCommandLine,
            RTL_NUMBER_OF(request.ParentCommandLine));
    }
    else {
        request.ParentCommandLine[0] = L'\0';
    }

    RecordProcessVerdictRequestEvent();

    PROCESS_PORT_REPLY reply = {};
    ULONG replyLength = sizeof(reply);
    ULONG timeoutMs = 0;
    LARGE_INTEGER timeout = ProcessVerdictWaitTimeout(&timeoutMs);
    NTSTATUS sendStatus = STATUS_PORT_DISCONNECTED;
    sendStatus = FltSendMessage(
        filterHandle,
        &clientPort,
        &request,
        sizeof(request),
        &reply,
        &replyLength,
        &timeout);

    if (NT_SUCCESS(sendStatus) &&
        replyLength >= sizeof(PROCESS_PORT_REPLY) &&
        reply.Version == PROCESS_PORT_PROTOCOL_VERSION) {
        if (reply.BlockProcess != 0) {
            blockProcess = TRUE;
        }
        else if (cacheKeyBuilt) {
            RememberAllowedProcessCreateDecision(&cacheKey);
        }
    }
    else {
        if (sendStatus == STATUS_TIMEOUT) {
            RecordProcessVerdictTimeoutEvent();
            KdPrint(("[EDR] Process verdict wait timed out. PID=%lu EventId=%llu TimeoutMs=%lu FailMode=%lu\n",
                request.ProcessId,
                request.EventId,
                timeoutMs,
                failMode));
        }
        else {
            KdPrint(("[EDR] Process verdict unavailable. PID=%lu EventId=%llu Status=0x%08X FailMode=%lu\n",
                request.ProcessId,
                request.EventId,
                sendStatus,
                failMode));
        }

        if (failMode == PROCESS_VERDICT_FAIL_CLOSE) {
            blockProcess = TRUE;
        }
    }

    if (blockProcess) {
        CreateInfo->CreationStatus = STATUS_ACCESS_DENIED;
        KdPrint(("[EDR] Synchronously blocked process create. PID=%lu EventId=%llu\n",
            request.ProcessId,
            request.EventId));
    }

    ExReleaseRundownProtection(&g_RundownRef);
}
