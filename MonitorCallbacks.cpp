#define POOL_ZERO_DOWN_LEVEL_SUPPORT
#include "PebMonitor.h"

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
    PDRIVER_EVENT_NODE node = (PDRIVER_EVENT_NODE)ExAllocatePoolZero(NonPagedPoolNx, sizeof(DRIVER_EVENT_NODE), 'drPM');
    if (!node) {
        return;
    }

    RtlZeroMemory(node, sizeof(DRIVER_EVENT_NODE));
    node->EventData.EventType = eventType;
    node->EventData.RegistryOperation = registryOperation;
    node->EventData.FileOperation = fileOperation;
    node->EventData.ProcessId = processId;
    node->EventData.Severity = severity;
    CopyWideStringToFixedBuffer(node->EventData.ProcessName, RTL_NUMBER_OF(node->EventData.ProcessName), processName);
    CopyWideStringToFixedBuffer(node->EventData.RuleId, RTL_NUMBER_OF(node->EventData.RuleId), ruleId);
    CopyUnicodeStringToFixedBuffer(node->EventData.TargetPath, RTL_NUMBER_OF(node->EventData.TargetPath), targetPath);
    CopyWideStringToFixedBuffer(node->EventData.InfoClass, RTL_NUMBER_OF(node->EventData.InfoClass), infoClass);
    CopyUnicodeStringToFixedBuffer(node->EventData.ValueName, RTL_NUMBER_OF(node->EventData.ValueName), valueName);
    CopyWideStringToFixedBuffer(node->EventData.ValueData, RTL_NUMBER_OF(node->EventData.ValueData), valueData);

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
        ExFreePoolWithTag(node, 'drPM');
        node = NULL;
    }
    KeReleaseSpinLock(&g_DriverQueueLock, oldIrql);

    if (irpToComplete != NULL && node != NULL) {
        RtlCopyMemory(irpToComplete->AssociatedIrp.SystemBuffer, &node->EventData, sizeof(DRIVER_EVENT));
        irpToComplete->IoStatus.Information = sizeof(DRIVER_EVENT);
        irpToComplete->IoStatus.Status = STATUS_SUCCESS;
        IoCompleteRequest(irpToComplete, IO_NO_INCREMENT);
        ExFreePoolWithTag(node, 'drPM');
    }
}

const FLT_OPERATION_REGISTRATION g_FilterOperationCallbacks[] = {
    { IRP_MJ_CREATE, 0, FilePreCreateOperation, NULL },
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

static BOOLEAN MatchDriverName(_In_ PCUNICODE_STRING fullImageName, _In_z_ PCWSTR targetSuffix) {
    UNICODE_STRING usTarget;
    RtlInitUnicodeString(&usTarget, targetSuffix);
    if (fullImageName->Length < usTarget.Length) {
        return FALSE;
    }

    PWCH pStart = (PWCH)((PUCHAR)fullImageName->Buffer + fullImageName->Length - usTarget.Length);
    UNICODE_STRING usSuffix;
    usSuffix.Length = usTarget.Length;
    usSuffix.MaximumLength = usTarget.Length;
    usSuffix.Buffer = pStart;

    return RtlEqualUnicodeString(&usSuffix, &usTarget, TRUE);
}

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
    if (!NT_SUCCESS(SeLocateProcessImageName(PsGetCurrentProcess(), &imagePath)) ||
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
        UNICODE_STRING valueData;
        valueData.Buffer = (PWCHAR)data;
        valueData.Length = (USHORT)dataSize;
        valueData.MaximumLength = (USHORT)dataSize;

        while (valueData.Length > 0 &&
            valueData.Buffer[(valueData.Length / sizeof(WCHAR)) - 1] == L'\0') {
            valueData.Length -= sizeof(WCHAR);
        }

        CopyUnicodeStringToFixedBuffer(buffer, bufferLength, &valueData);
        return;
    }

    if (type == REG_MULTI_SZ) {
        const WCHAR* multi = (const WCHAR*)data;
        SIZE_T chars = dataSize / sizeof(WCHAR);
        SIZE_T cursor = 0;

        for (SIZE_T i = 0; i < chars && cursor + 1 < bufferLength; ++i) {
            WCHAR ch = multi[i];
            if (ch == L'\0') {
                if (i + 1 >= chars || multi[i + 1] == L'\0') {
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

    if (type == REG_DWORD && dataSize >= sizeof(ULONG)) {
        const ULONG* number = (const ULONG*)data;
        RtlStringCchPrintfW(buffer, bufferLength, L"%lu", *number);
        return;
    }

    if (type == REG_QWORD && dataSize >= sizeof(ULONGLONG)) {
        const ULONGLONG* number = (const ULONGLONG*)data;
        RtlStringCchPrintfW(buffer, bufferLength, L"%llu", *number);
        return;
    }

    FormatBinaryRegistryData((const UCHAR*)data, dataSize, buffer, bufferLength);
}

static NTSTATUS QueryRegistryObjectPath(
    _In_opt_ PVOID object,
    _Outptr_result_maybenull_ PCUNICODE_STRING* objectName) {
    if (objectName == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *objectName = NULL;
    if (object == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    return CmCallbackGetKeyObjectIDEx(&g_RegCookie, object, NULL, objectName, 0);
}

static VOID BuildRegistryCreatePath(
    _In_ PREG_CREATE_KEY_INFORMATION_V1 info,
    _Out_writes_(bufferLength) WCHAR* buffer,
    _In_ SIZE_T bufferLength,
    _Out_ NTSTATUS* rootStatus,
    _Outptr_result_maybenull_ PCUNICODE_STRING* rootKeyPath) {
    if (buffer == NULL || bufferLength == 0 || rootStatus == NULL || rootKeyPath == NULL) {
        return;
    }

    buffer[0] = L'\0';
    *rootStatus = STATUS_UNSUCCESSFUL;
    *rootKeyPath = NULL;

    if (info == NULL || info->CompleteName == NULL || info->CompleteName->Buffer == NULL) {
        return;
    }

    if (info->CompleteName->Length > 0 && info->CompleteName->Buffer[0] == L'\\') {
        CopyUnicodeStringToFixedBuffer(buffer, bufferLength, info->CompleteName);
        return;
    }

    if (info->RootObject != NULL) {
        *rootStatus = QueryRegistryObjectPath(info->RootObject, rootKeyPath);
        if (NT_SUCCESS(*rootStatus) && *rootKeyPath != NULL) {
            WCHAR rootBuffer[MAX_REG_PATH_LENGTH];
            WCHAR relativeBuffer[MAX_REG_PATH_LENGTH];

            CopyUnicodeStringToFixedBuffer(rootBuffer, RTL_NUMBER_OF(rootBuffer), *rootKeyPath);
            CopyUnicodeStringToFixedBuffer(relativeBuffer, RTL_NUMBER_OF(relativeBuffer), info->CompleteName);

            if (NT_SUCCESS(RtlStringCchCopyW(buffer, bufferLength, rootBuffer))) {
                SIZE_T currentLength = wcslen(buffer);
                if (currentLength > 0 && buffer[currentLength - 1] != L'\\' && relativeBuffer[0] != L'\\') {
                    RtlStringCchCatW(buffer, bufferLength, L"\\");
                }
                RtlStringCchCatW(buffer, bufferLength, relativeBuffer);
                return;
            }
        }
    }

    CopyUnicodeStringToFixedBuffer(buffer, bufferLength, info->CompleteName);
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

    if (infoClass == KeyWriteTimeInformation && dataLength >= sizeof(LARGE_INTEGER)) {
        const LARGE_INTEGER* timestamp = (const LARGE_INTEGER*)data;
        RtlStringCchPrintfW(buffer, bufferLength, L"%lld", timestamp->QuadPart);
        return;
    }

    if ((infoClass == KeyWow64FlagsInformation ||
        infoClass == KeySetVirtualizationInformation ||
        infoClass == KeyControlFlagsInformation ||
        infoClass == KeySetDebugInformation ||
        infoClass == KeySetHandleTagsInformation ||
        infoClass == KeySetLayerInformation) &&
        dataLength >= sizeof(ULONG)) {
        const ULONG* number = (const ULONG*)data;
        RtlStringCchPrintfW(buffer, bufferLength, L"0x%08lx", *number);
        return;
    }

    FormatBinaryRegistryData((const UCHAR*)data, dataLength, buffer, bufferLength);
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

static BOOLEAN MatchFileRule(
    _In_ const FILE_RULE* rule,
    _In_ ULONG actualOperation,
    _In_opt_z_ PCWSTR processName,
    _In_opt_z_ PCWSTR targetPath,
    _In_opt_z_ PCWSTR extension) {
    if (rule == NULL) {
        return FALSE;
    }

    if (rule->Operation == FILE_OPERATION_CREATE && actualOperation != FILE_OPERATION_CREATE) {
        return FALSE;
    }

    if (rule->Operation == FILE_OPERATION_WRITE && actualOperation != FILE_OPERATION_WRITE) {
        return FALSE;
    }

    if ((rule->MatchFlags & FILE_MATCH_FLAG_PROCESS_NAME) &&
        !MatchRegistryField(rule->ProcessNameMatchType, rule->ProcessName, processName)) {
        return FALSE;
    }

    if ((rule->MatchFlags & FILE_MATCH_FLAG_TARGET_PATH) &&
        !MatchRegistryField(rule->TargetPathMatchType, rule->TargetPath, targetPath)) {
        return FALSE;
    }

    if ((rule->MatchFlags & FILE_MATCH_FLAG_EXTENSION) &&
        !MatchRegistryField(rule->ExtensionMatchType, rule->Extension, extension)) {
        return FALSE;
    }

    return TRUE;
}

static ULONG DetermineFileOperationFromCreate(_In_ PFLT_CALLBACK_DATA Data) {
    if (Data == NULL || Data->Iopb == NULL) {
        return 0;
    }

    ACCESS_MASK desiredAccess = Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess;
    ULONG disposition = (Data->Iopb->Parameters.Create.Options >> 24) & 0xFF;
    BOOLEAN hasWriteAccess =
        (desiredAccess & (FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_ATTRIBUTES | FILE_WRITE_EA | DELETE)) != 0 ||
        (desiredAccess & (GENERIC_WRITE | GENERIC_ALL)) != 0;
    BOOLEAN isCreateStyle =
        disposition == FILE_SUPERSEDE ||
        disposition == FILE_CREATE ||
        disposition == FILE_OPEN_IF ||
        disposition == FILE_OVERWRITE ||
        disposition == FILE_OVERWRITE_IF;

    if (isCreateStyle) {
        return FILE_OPERATION_CREATE;
    }

    if (hasWriteAccess) {
        return FILE_OPERATION_WRITE;
    }

    return 0;
}

static VOID ExtractFileExtensionFromPath(
    _In_opt_z_ PCWSTR targetPath,
    _Out_writes_(bufferLength) WCHAR* buffer,
    _In_ SIZE_T bufferLength) {
    if (buffer == NULL || bufferLength == 0) {
        return;
    }

    buffer[0] = L'\0';
    if (targetPath == NULL || targetPath[0] == L'\0') {
        return;
    }

    const WCHAR* lastSlash = wcsrchr(targetPath, L'\\');
    const WCHAR* lastForwardSlash = wcsrchr(targetPath, L'/');
    const WCHAR* start = targetPath;
    if (lastSlash != NULL && lastSlash + 1 > start) {
        start = lastSlash + 1;
    }
    if (lastForwardSlash != NULL && lastForwardSlash + 1 > start) {
        start = lastForwardSlash + 1;
    }

    const WCHAR* lastDot = wcsrchr(start, L'.');
    if (lastDot == NULL || lastDot[0] == L'\0') {
        return;
    }

    RtlStringCchCopyW(buffer, bufferLength, lastDot);
}

NTSTATUS FileFilterUnload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags) {
    UNREFERENCED_PARAMETER(Flags);
    return STATUS_SUCCESS;
}

FLT_PREOP_CALLBACK_STATUS FilePreCreateOperation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext) {
    UNREFERENCED_PARAMETER(CompletionContext);

    if (!ExAcquireRundownProtection(&g_RundownRef)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (Data == NULL || Data->Iopb == NULL || FltObjects == NULL || Data->RequestorMode == KernelMode) {
        ExReleaseRundownProtection(&g_RundownRef);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    const ULONG fileOperation = DetermineFileOperationFromCreate(Data);
    if (fileOperation == 0) {
        ExReleaseRundownProtection(&g_RundownRef);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    WCHAR processName[MAX_RULE_LENGTH];
    WCHAR targetPathBuffer[MAX_REG_PATH_LENGTH];
    WCHAR extensionBuffer[MAX_RULE_LENGTH];
    FILE_RULE matchedRule = {};
    BOOLEAN ruleMatched = FALSE;

    processName[0] = L'\0';
    targetPathBuffer[0] = L'\0';
    extensionBuffer[0] = L'\0';

    GetCurrentProcessName(processName, RTL_NUMBER_OF(processName));

    PFLT_FILE_NAME_INFORMATION fileNameInfo = NULL;
    if (NT_SUCCESS(FltGetFileNameInformation(
        Data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
        &fileNameInfo)) && fileNameInfo != NULL) {
        FltParseFileNameInformation(fileNameInfo);
        CopyUnicodeStringToFixedBuffer(targetPathBuffer, RTL_NUMBER_OF(targetPathBuffer), &fileNameInfo->Name);
        if (fileNameInfo->Extension.Length > 0) {
            CopyUnicodeStringToFixedBuffer(extensionBuffer, RTL_NUMBER_OF(extensionBuffer), &fileNameInfo->Extension);
            if (extensionBuffer[0] != L'\0' && extensionBuffer[0] != L'.') {
                WCHAR extensionWithDot[MAX_RULE_LENGTH];
                RtlStringCchPrintfW(extensionWithDot, RTL_NUMBER_OF(extensionWithDot), L".%ws", extensionBuffer);
                RtlStringCchCopyW(extensionBuffer, RTL_NUMBER_OF(extensionBuffer), extensionWithDot);
            }
        }
        FltReleaseFileNameInformation(fileNameInfo);
    }
    else if (FltObjects->FileObject != NULL && FltObjects->FileObject->FileName.Buffer != NULL) {
        CopyUnicodeStringToFixedBuffer(targetPathBuffer, RTL_NUMBER_OF(targetPathBuffer), &FltObjects->FileObject->FileName);
    }

    if (extensionBuffer[0] == L'\0') {
        ExtractFileExtensionFromPath(targetPathBuffer, extensionBuffer, RTL_NUMBER_OF(extensionBuffer));
    }

    KIRQL oldIrql;
    KeAcquireSpinLock(&g_FileRuleLock, &oldIrql);
    for (ULONG i = 0; i < g_FileRuleCount; ++i) {
        if (MatchFileRule(&g_FileRules[i], fileOperation, processName, targetPathBuffer, extensionBuffer)) {
            matchedRule = g_FileRules[i];
            ruleMatched = TRUE;
            break;
        }
    }
    KeReleaseSpinLock(&g_FileRuleLock, oldIrql);

    if (!ruleMatched) {
        ExReleaseRundownProtection(&g_RundownRef);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    UNICODE_STRING targetPath;
    RtlInitUnicodeString(&targetPath, targetPathBuffer);

    KdPrint(("[EDR] Blocked file operation. Operation=%lu RuleId=%ws Process=%ws Path=%ws\n",
        fileOperation,
        matchedRule.RuleId,
        processName,
        targetPathBuffer));

    QueueKernelEvent(
        DRIVER_EVENT_TYPE_BLOCKED_FILE_OPERATION,
        0,
        fileOperation,
        HandleToULong(PsGetCurrentProcessId()),
        processName,
        matchedRule.RuleId,
        matchedRule.Severity,
        &targetPath,
        NULL,
        NULL,
        extensionBuffer);

    Data->IoStatus.Status = STATUS_ACCESS_DENIED;
    Data->IoStatus.Information = 0;
    ExReleaseRundownProtection(&g_RundownRef);
    return FLT_PREOP_COMPLETE;
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
    REGISTRY_RULE matchedRule = {};
    REGISTRY_RULE matchedAllowRule = {};
    BOOLEAN registryAllowMatched = FALSE;
    BOOLEAN registryRuleMatched = FALSE;

    PCUNICODE_STRING keyPath = NULL;
    NTSTATUS keyStatus = STATUS_UNSUCCESSFUL;
    PCUNICODE_STRING rootKeyPath = NULL;
    NTSTATUS rootKeyStatus = STATUS_UNSUCCESSFUL;

    GetCurrentProcessName(processName, RTL_NUMBER_OF(processName));
    keyPathBuffer[0] = L'\0';
    infoClassBuffer[0] = L'\0';
    valueNameBuffer[0] = L'\0';
    valueDataBuffer[0] = L'\0';

    switch (notifyClass) {
    case RegNtPreSetValueKey: {
        PREG_SET_VALUE_KEY_INFORMATION info = (PREG_SET_VALUE_KEY_INFORMATION)Argument2;
        if (info == NULL) {
            goto Cleanup;
        }

        registryOperation = REGISTRY_OPERATION_SET_VALUE;
        keyStatus = QueryRegistryObjectPath(info->Object, &keyPath);
        if (NT_SUCCESS(keyStatus) && keyPath != NULL) {
            CopyUnicodeStringToFixedBuffer(keyPathBuffer, RTL_NUMBER_OF(keyPathBuffer), keyPath);
        }

        if (info->ValueName != NULL) {
            CopyUnicodeStringToFixedBuffer(valueNameBuffer, RTL_NUMBER_OF(valueNameBuffer), info->ValueName);
        }

        ExtractRegistryValueDataString(info->Type, info->Data, info->DataSize, valueDataBuffer, RTL_NUMBER_OF(valueDataBuffer));

        if (info->ValueName != NULL && info->Data != NULL && info->DataSize > 0) {
            UNICODE_STRING targetValueName;
            RtlInitUnicodeString(&targetValueName, L"ImagePath");

            if (RtlCompareUnicodeString(info->ValueName, &targetValueName, TRUE) == 0 &&
                (info->Type == REG_SZ || info->Type == REG_EXPAND_SZ)) {
                UNICODE_STRING imagePath;
                imagePath.Buffer = (PWCH)info->Data;
                imagePath.Length = (USHORT)info->DataSize;
                imagePath.MaximumLength = (USHORT)info->DataSize;

                while (imagePath.Length > 0 &&
                    imagePath.Buffer[(imagePath.Length / sizeof(WCHAR)) - 1] == L'\0') {
                    imagePath.Length -= sizeof(WCHAR);
                }

                KIRQL oldIrql;
                BOOLEAN isMalicious = FALSE;
                KeAcquireSpinLock(&g_BlacklistLock, &oldIrql);
                for (ULONG i = 0; i < g_BlacklistCount; ++i) {
                    if (MatchDriverName(&imagePath, g_DriverBlacklist[i])) {
                        isMalicious = TRUE;
                        break;
                    }
                }
                KeReleaseSpinLock(&g_BlacklistLock, oldIrql);

                if (isMalicious) {
                    KdPrint(("[EDR] Blocked malicious driver service registration: %wZ\n", &imagePath));
                        QueueKernelEvent(
                            DRIVER_EVENT_TYPE_BLOCKED_SERVICE,
                            0,
                            0,
                            HandleToULong(PsGetCurrentProcessId()),
                            processName,
                            NULL,
                            0,
                            &imagePath,
                            NULL,
                            info->ValueName,
                            valueDataBuffer);
                    status = STATUS_ACCESS_DENIED;
                    goto Cleanup;
                }
            }
        }
        break;
    }

    case RegNtPreCreateKey:
    case RegNtPreCreateKeyEx: {
        PREG_CREATE_KEY_INFORMATION_V1 info = (PREG_CREATE_KEY_INFORMATION_V1)Argument2;
        if (info == NULL) {
            goto Cleanup;
        }

        registryOperation = REGISTRY_OPERATION_CREATE_KEY;
        BuildRegistryCreatePath(info, keyPathBuffer, RTL_NUMBER_OF(keyPathBuffer), &rootKeyStatus, &rootKeyPath);
        break;
    }

    case RegNtPreDeleteValueKey: {
        PREG_DELETE_VALUE_KEY_INFORMATION info = (PREG_DELETE_VALUE_KEY_INFORMATION)Argument2;
        if (info == NULL) {
            goto Cleanup;
        }

        registryOperation = REGISTRY_OPERATION_DELETE_VALUE;
        keyStatus = QueryRegistryObjectPath(info->Object, &keyPath);
        if (NT_SUCCESS(keyStatus) && keyPath != NULL) {
            CopyUnicodeStringToFixedBuffer(keyPathBuffer, RTL_NUMBER_OF(keyPathBuffer), keyPath);
        }

        if (info->ValueName != NULL) {
            CopyUnicodeStringToFixedBuffer(valueNameBuffer, RTL_NUMBER_OF(valueNameBuffer), info->ValueName);
        }
        break;
    }

    case RegNtPreDeleteKey: {
        PREG_DELETE_KEY_INFORMATION info = (PREG_DELETE_KEY_INFORMATION)Argument2;
        if (info == NULL) {
            goto Cleanup;
        }

        registryOperation = REGISTRY_OPERATION_DELETE_KEY;
        keyStatus = QueryRegistryObjectPath(info->Object, &keyPath);
        if (NT_SUCCESS(keyStatus) && keyPath != NULL) {
            CopyUnicodeStringToFixedBuffer(keyPathBuffer, RTL_NUMBER_OF(keyPathBuffer), keyPath);
        }
        break;
    }

    case RegNtPreRenameKey: {
        PREG_RENAME_KEY_INFORMATION info = (PREG_RENAME_KEY_INFORMATION)Argument2;
        if (info == NULL) {
            goto Cleanup;
        }

        registryOperation = REGISTRY_OPERATION_RENAME_KEY;
        keyStatus = QueryRegistryObjectPath(info->Object, &keyPath);
        if (NT_SUCCESS(keyStatus) && keyPath != NULL) {
            CopyUnicodeStringToFixedBuffer(keyPathBuffer, RTL_NUMBER_OF(keyPathBuffer), keyPath);
        }

        if (info->NewName != NULL) {
            CopyUnicodeStringToFixedBuffer(valueDataBuffer, RTL_NUMBER_OF(valueDataBuffer), info->NewName);
        }
        break;
    }

    case RegNtPreSetInformationKey: {
        PREG_SET_INFORMATION_KEY_INFORMATION info = (PREG_SET_INFORMATION_KEY_INFORMATION)Argument2;
        if (info == NULL) {
            goto Cleanup;
        }

        registryOperation = REGISTRY_OPERATION_SET_INFORMATION_KEY;
        keyStatus = QueryRegistryObjectPath(info->Object, &keyPath);
        if (NT_SUCCESS(keyStatus) && keyPath != NULL) {
            CopyUnicodeStringToFixedBuffer(keyPathBuffer, RTL_NUMBER_OF(keyPathBuffer), keyPath);
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
        KIRQL oldIrql;
        KeAcquireSpinLock(&g_RegistryAllowRuleLock, &oldIrql);

        for (ULONG i = 0; i < g_RegistryAllowRuleCount; ++i) {
            if (MatchRegistryRule(
                &g_RegistryAllowRules[i],
                registryOperation,
                processName,
                keyPathBuffer,
                infoClassBuffer,
                valueNameBuffer,
                valueDataBuffer)) {
                matchedAllowRule = g_RegistryAllowRules[i];
                registryAllowMatched = TRUE;
                break;
            }
        }

        KeReleaseSpinLock(&g_RegistryAllowRuleLock, oldIrql);
    }

    if (!registryAllowMatched) {
        KIRQL oldIrql;
        KeAcquireSpinLock(&g_RegistryRuleLock, &oldIrql);

        for (ULONG i = 0; i < g_RegistryRuleCount; ++i) {
            if (MatchRegistryRule(
                &g_RegistryRules[i],
                registryOperation,
                processName,
                keyPathBuffer,
                infoClassBuffer,
                valueNameBuffer,
                valueDataBuffer)) {
                matchedRule = g_RegistryRules[i];
                registryRuleMatched = TRUE;
                break;
            }
        }

        KeReleaseSpinLock(&g_RegistryRuleLock, oldIrql);
    }
    else {
        KdPrint(("[EDR] Allowed registry operation by allow rule. Operation=%lu RuleId=%ws Key=%ws Value=%ws Data=%ws\n",
            registryOperation,
            matchedAllowRule.RuleId,
            keyPathBuffer,
            valueNameBuffer,
            valueDataBuffer));
    }

    if (registryRuleMatched) {
        UNICODE_STRING keyPathString;
        UNICODE_STRING valueNameString;

        RtlInitUnicodeString(&keyPathString, keyPathBuffer);
        RtlInitUnicodeString(&valueNameString, valueNameBuffer);

        KdPrint(("[EDR] Blocked registry operation. Operation=%lu RuleId=%ws Key=%ws InfoClass=%ws Value=%ws Data=%ws\n",
            registryOperation,
            matchedRule.RuleId,
            keyPathBuffer,
            infoClassBuffer,
            valueNameBuffer,
            valueDataBuffer));

        QueueKernelEvent(
            DRIVER_EVENT_TYPE_BLOCKED_REGISTRY_OPERATION,
            registryOperation,
            0,
            HandleToULong(PsGetCurrentProcessId()),
            processName,
            matchedRule.RuleId,
            matchedRule.Severity,
            &keyPathString,
            infoClassBuffer,
            &valueNameString,
            valueDataBuffer);
        status = STATUS_ACCESS_DENIED;
    }

Cleanup:
    if (NT_SUCCESS(keyStatus) && keyPath != NULL) {
        CmCallbackReleaseKeyObjectIDEx(keyPath);
    }
    if (NT_SUCCESS(rootKeyStatus) && rootKeyPath != NULL) {
        CmCallbackReleaseKeyObjectIDEx(rootKeyPath);
    }

    ExReleaseRundownProtection(&g_RundownRef);
    return status;
}

void ProcessNotifyCallbackEx(_Inout_ PEPROCESS Process, _In_ HANDLE ProcessId, _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo) {
    UNREFERENCED_PARAMETER(Process);

    if (!ExAcquireRundownProtection(&g_RundownRef)) return;

    PPROCESS_EVENT_NODE node = NULL;
    if (CreateInfo == NULL) goto Cleanup;

    WCHAR extractedCmdLine[1024];
    RtlZeroMemory(extractedCmdLine, sizeof(extractedCmdLine));
    USHORT extractedLen = 0;
    BOOLEAN gotCmdLine = FALSE;

    if (CreateInfo->CommandLine != NULL && CreateInfo->CommandLine->Buffer != NULL) {
        USHORT cmdLen = CreateInfo->CommandLine->Length;
        if (cmdLen > 0 && cmdLen < sizeof(extractedCmdLine) - sizeof(WCHAR)) {
            RtlCopyMemory(extractedCmdLine, CreateInfo->CommandLine->Buffer, cmdLen);
            extractedLen = cmdLen;
            gotCmdLine = TRUE;
        }
    }

    node = (PPROCESS_EVENT_NODE)ExAllocatePoolZero(NonPagedPoolNx, sizeof(PROCESS_EVENT_NODE), 'ndPM');
    if (!node) goto Cleanup;

    RtlZeroMemory(node, sizeof(PROCESS_EVENT_NODE));
    node->EventData.ProcessId = HandleToULong(ProcessId);
    node->EventData.ParentProcessId = HandleToULong(CreateInfo->ParentProcessId);

    if (gotCmdLine) {
        ULONG maxDestBytes = sizeof(node->EventData.CommandLine) - sizeof(WCHAR);
        ULONG copyBytes = (extractedLen < maxDestBytes) ? extractedLen : maxDestBytes;
        RtlCopyMemory(node->EventData.CommandLine, extractedCmdLine, copyBytes);
        node->EventData.CommandLine[copyBytes / sizeof(WCHAR)] = L'\0';
    }
    else {
        node->EventData.CommandLine[0] = L'\0';
    }

    PurgeExpiredProcessEvents();

    KIRQL oldIrql;
    PIRP irpToComplete = NULL;
    KeAcquireSpinLock(&g_QueueLock, &oldIrql);

    if (g_EventCount >= MAX_EVENT_COUNT) {
        KeReleaseSpinLock(&g_QueueLock, oldIrql);
        goto Cleanup;
    }

    InsertTailList(&g_EventQueue, &node->ListEntry);
    g_EventCount++;

    if (g_PendingEventIrp != NULL) {
        if (IoSetCancelRoutine(g_PendingEventIrp, NULL)) {
            PIRP pendingIrp = g_PendingEventIrp;
            MarkProcessEventDelivered(node, IoGetCurrentIrpStackLocation(pendingIrp)->FileObject);
            irpToComplete = pendingIrp;
            g_PendingEventIrp = NULL;
        }
    }
    KeReleaseSpinLock(&g_QueueLock, oldIrql);

    if (irpToComplete != NULL) {
        RtlCopyMemory(irpToComplete->AssociatedIrp.SystemBuffer, &node->EventData, sizeof(PROCESS_EVENT));
        irpToComplete->IoStatus.Information = sizeof(PROCESS_EVENT);
        irpToComplete->IoStatus.Status = STATUS_SUCCESS;
        IoCompleteRequest(irpToComplete, IO_NO_INCREMENT);
    }

    node = NULL;

Cleanup:
    if (node != NULL) {
        ExFreePoolWithTag(node, 'ndPM');
    }
    ExReleaseRundownProtection(&g_RundownRef);
}

VOID ImageNotifyCallback(_In_opt_ PUNICODE_STRING FullImageName, _In_ HANDLE ProcessId, _In_ PIMAGE_INFO ImageInfo) {
    UNREFERENCED_PARAMETER(ProcessId);
    if (FullImageName == NULL || FullImageName->Buffer == NULL || ImageInfo->SystemModeImage == 0) return;

    KIRQL oldIrql;
    BOOLEAN isMalicious = FALSE;

    KeAcquireSpinLock(&g_BlacklistLock, &oldIrql);
    for (ULONG i = 0; i < g_BlacklistCount; ++i) {
        if (MatchDriverName(FullImageName, g_DriverBlacklist[i])) {
            isMalicious = TRUE;
            break;
        }
    }
    KeReleaseSpinLock(&g_BlacklistLock, oldIrql);

    if (isMalicious) {
        KdPrint(("[EDR] Observed suspicious driver load: %wZ\n", FullImageName));
        QueueKernelEvent(
            DRIVER_EVENT_TYPE_OBSERVED_LOAD,
            0,
            0,
            0,
            NULL,
            NULL,
            0,
            FullImageName,
            NULL,
            NULL,
            NULL);
    }
}
