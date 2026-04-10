/* Core entry: global state definitions and driver load/unload. */
#include "PebMonitor.h"

#include <initguid.h>
#include <wdmsec.h>

DEFINE_GUID(GUID_SD_PEBMONITOR, 0x8a923a1c, 0xc1d5, 0x4f2b, 0x9b, 0x11, 0x72, 0xa1, 0xd8, 0x3e, 0x5a, 0x9f);

PDEVICE_OBJECT g_DeviceObject = NULL;
EX_RUNDOWN_REF g_RundownRef;
volatile LONG64 g_NextProcessEventId = 0;
EX_PUSH_LOCK g_ProcessPortLock = 0;
PFLT_PORT g_ProcessServerPort = NULL;
PFLT_PORT g_ProcessClientPort = NULL;

LIST_ENTRY g_DriverEventQueue;
KSPIN_LOCK g_DriverQueueLock;
PIRP g_PendingDriverIrp = NULL;
ULONG g_DriverEventCount = 0;
NPAGED_LOOKASIDE_LIST g_DriverEventLookaside;

ULONG g_BlacklistCount = 0;
EX_PUSH_LOCK g_BlacklistLock = 0;

REGISTRY_RULE g_RegistryRules[MAX_REGISTRY_RULE_COUNT];
ULONG g_RegistryRuleCount = 0;
EX_PUSH_LOCK g_RegistryRuleLock = 0;

REGISTRY_RULE g_RegistryAllowRules[MAX_REGISTRY_RULE_COUNT];
ULONG g_RegistryAllowRuleCount = 0;
EX_PUSH_LOCK g_RegistryAllowRuleLock = 0;

FILE_RULE g_FileRules[MAX_FILE_RULE_COUNT];
ULONG g_FileRuleCount = 0;
EX_PUSH_LOCK g_FileRuleLock = 0;

LARGE_INTEGER g_RegCookie = { 0 };
ULONG g_RuntimeStatusFlags = 0;
EX_PUSH_LOCK g_RuntimeStatusLock = 0;
ULONGLONG g_ProcessVerdictRequestCount = 0;
ULONGLONG g_ProcessVerdictTimeoutCount = 0;
ULONGLONG g_ProcessPortConnectCount = 0;
ULONGLONG g_ProcessPortDisconnectCount = 0;
ULONGLONG g_LastProcessPortConnectTime = 0;
ULONGLONG g_LastProcessPortDisconnectTime = 0;
ULONGLONG g_LastProcessVerdictTimeoutTime = 0;
ULONG g_ProcessVerdictTimeoutMs = PROCESS_VERDICT_TIMEOUT_MS_DEFAULT;
ULONG g_ProcessVerdictFailMode = PROCESS_VERDICT_FAIL_OPEN;
ULONG g_CaptureParentCommandLine = PROCESS_PARENT_CMDLINE_CAPTURE_DISABLED;
WCHAR g_ActiveConfigVersion[MAX_RULE_LENGTH];
WCHAR g_ActiveProfileName[MAX_RULE_LENGTH];
WCHAR g_ActiveGeneratedAt[MAX_RULE_LENGTH];
PFLT_FILTER g_FilterHandle = NULL;

typedef struct _DRIVER_BLACKLIST_TRIE_NODE {
    struct _DRIVER_BLACKLIST_TRIE_NODE* FirstChild;
    struct _DRIVER_BLACKLIST_TRIE_NODE* NextSibling;
    WCHAR Character;
    BOOLEAN IsTerminal;
} DRIVER_BLACKLIST_TRIE_NODE, *PDRIVER_BLACKLIST_TRIE_NODE;

static DRIVER_BLACKLIST_TRIE_NODE g_DriverBlacklistTrieRoot = {};

static PDRIVER_BLACKLIST_TRIE_NODE AllocateDriverBlacklistTrieNode(_In_ WCHAR character) {
    PDRIVER_BLACKLIST_TRIE_NODE node =
        (PDRIVER_BLACKLIST_TRIE_NODE)ExAllocatePoolZero(
            NonPagedPoolNx,
            sizeof(DRIVER_BLACKLIST_TRIE_NODE),
            'trPM');
    if (node != NULL) {
        node->Character = character;
    }
    return node;
}

static VOID FreeDriverBlacklistTrieNode(_In_opt_ PDRIVER_BLACKLIST_TRIE_NODE node) {
    if (node != NULL) {
        ExFreePoolWithTag(node, 'trPM');
    }
}

static PDRIVER_BLACKLIST_TRIE_NODE FindDriverBlacklistChild(
    _In_ PDRIVER_BLACKLIST_TRIE_NODE parent,
    _In_ WCHAR character) {
    PDRIVER_BLACKLIST_TRIE_NODE child = parent->FirstChild;
    while (child != NULL) {
        if (child->Character == character) {
            return child;
        }
        child = child->NextSibling;
    }
    return NULL;
}

static BOOLEAN IsPathSeparatorCharacter(_In_ WCHAR character) {
    return character == L'\\' || character == L'/';
}

static VOID DetachDriverBlacklistChild(
    _Inout_ PDRIVER_BLACKLIST_TRIE_NODE parent,
    _In_ PDRIVER_BLACKLIST_TRIE_NODE target) {
    PDRIVER_BLACKLIST_TRIE_NODE previous = NULL;
    PDRIVER_BLACKLIST_TRIE_NODE child = parent->FirstChild;

    while (child != NULL) {
        if (child == target) {
            if (previous == NULL) {
                parent->FirstChild = child->NextSibling;
            }
            else {
                previous->NextSibling = child->NextSibling;
            }
            child->NextSibling = NULL;
            return;
        }

        previous = child;
        child = child->NextSibling;
    }
}

BOOLEAN MatchDriverBlacklistRuleLocked(_In_ PCUNICODE_STRING FullImageName) {
    if (FullImageName == NULL || FullImageName->Buffer == NULL || FullImageName->Length == 0) {
        return FALSE;
    }

    USHORT characterCount = FullImageName->Length / sizeof(WCHAR);
    if (characterCount == 0) {
        return FALSE;
    }

    PDRIVER_BLACKLIST_TRIE_NODE current = &g_DriverBlacklistTrieRoot;
    for (USHORT index = characterCount; index > 0; --index) {
        WCHAR character = RtlDowncaseUnicodeChar(FullImageName->Buffer[index - 1]);
        current = FindDriverBlacklistChild(current, character);
        if (current == NULL) {
            return FALSE;
        }

        if (current->IsTerminal) {
            USHORT matchedStartIndex = (USHORT)(index - 1);
            if (matchedStartIndex == 0) {
                return TRUE;
            }

            if (IsPathSeparatorCharacter(FullImageName->Buffer[matchedStartIndex]) ||
                IsPathSeparatorCharacter(FullImageName->Buffer[matchedStartIndex - 1])) {
                return TRUE;
            }
        }
    }

    return FALSE;
}

NTSTATUS InsertDriverBlacklistRuleLocked(_In_z_ PCWSTR RuleText) {
    if (RuleText == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    SIZE_T characterCount = wcsnlen(RuleText, MAX_RULE_LENGTH - 1);
    if (characterCount == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    PDRIVER_BLACKLIST_TRIE_NODE current = &g_DriverBlacklistTrieRoot;
    PDRIVER_BLACKLIST_TRIE_NODE insertedParents[MAX_RULE_LENGTH];
    PDRIVER_BLACKLIST_TRIE_NODE insertedNodes[MAX_RULE_LENGTH];
    ULONG insertedCount = 0;

    for (SIZE_T index = characterCount; index > 0; --index) {
        WCHAR character = RtlDowncaseUnicodeChar(RuleText[index - 1]);
        PDRIVER_BLACKLIST_TRIE_NODE child = FindDriverBlacklistChild(current, character);
        if (child == NULL) {
            child = AllocateDriverBlacklistTrieNode(character);
            if (child == NULL) {
                while (insertedCount > 0) {
                    insertedCount--;
                    DetachDriverBlacklistChild(insertedParents[insertedCount], insertedNodes[insertedCount]);
                    FreeDriverBlacklistTrieNode(insertedNodes[insertedCount]);
                }
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            child->NextSibling = current->FirstChild;
            current->FirstChild = child;
            insertedParents[insertedCount] = current;
            insertedNodes[insertedCount] = child;
            insertedCount++;
        }

        current = child;
    }

    current->IsTerminal = TRUE;
    return STATUS_SUCCESS;
}

VOID ClearDriverBlacklistRulesLocked() {
    PDRIVER_BLACKLIST_TRIE_NODE stack = g_DriverBlacklistTrieRoot.FirstChild;
    g_DriverBlacklistTrieRoot.FirstChild = NULL;
    g_DriverBlacklistTrieRoot.IsTerminal = FALSE;

    while (stack != NULL) {
        PDRIVER_BLACKLIST_TRIE_NODE node = stack;
        stack = stack->NextSibling;

        PDRIVER_BLACKLIST_TRIE_NODE child = node->FirstChild;
        while (child != NULL) {
            PDRIVER_BLACKLIST_TRIE_NODE nextChild = child->NextSibling;
            child->NextSibling = stack;
            stack = child;
            child = nextChild;
        }

        FreeDriverBlacklistTrieNode(node);
    }
}

static VOID SetRuntimeStatusFlag(_In_ ULONG flag, _In_ BOOLEAN enabled) {
    AcquireExclusivePushLock(&g_RuntimeStatusLock);
    if (enabled) {
        g_RuntimeStatusFlags |= flag;
    }
    else {
        g_RuntimeStatusFlags &= ~flag;
    }
    ReleaseExclusivePushLock(&g_RuntimeStatusLock);
}

static VOID ResetRuntimeConfigInfo() {
    AcquireExclusivePushLock(&g_RuntimeStatusLock);
    RtlZeroMemory(g_ActiveConfigVersion, sizeof(g_ActiveConfigVersion));
    RtlZeroMemory(g_ActiveProfileName, sizeof(g_ActiveProfileName));
    RtlZeroMemory(g_ActiveGeneratedAt, sizeof(g_ActiveGeneratedAt));
    ReleaseExclusivePushLock(&g_RuntimeStatusLock);
}

static ULONGLONG QueryCurrentSystemTimeValue() {
    LARGE_INTEGER now;
    KeQuerySystemTime(&now);
    return (ULONGLONG)now.QuadPart;
}

static VOID RecordProcessPortConnectEvent() {
    AcquireExclusivePushLock(&g_RuntimeStatusLock);
    g_RuntimeStatusFlags |= DRIVER_STATUS_FLAG_PROCESS_PORT_CONNECTED;
    g_ProcessPortConnectCount++;
    g_LastProcessPortConnectTime = QueryCurrentSystemTimeValue();
    ReleaseExclusivePushLock(&g_RuntimeStatusLock);
}

static VOID RecordProcessPortDisconnectEvent() {
    AcquireExclusivePushLock(&g_RuntimeStatusLock);
    if ((g_RuntimeStatusFlags & DRIVER_STATUS_FLAG_PROCESS_PORT_CONNECTED) != 0) {
        g_RuntimeStatusFlags &= ~DRIVER_STATUS_FLAG_PROCESS_PORT_CONNECTED;
        g_ProcessPortDisconnectCount++;
        g_LastProcessPortDisconnectTime = QueryCurrentSystemTimeValue();
    }
    ReleaseExclusivePushLock(&g_RuntimeStatusLock);
}

VOID RecordProcessVerdictRequestEvent() {
    AcquireExclusivePushLock(&g_RuntimeStatusLock);
    g_ProcessVerdictRequestCount++;
    ReleaseExclusivePushLock(&g_RuntimeStatusLock);
}

VOID RecordProcessVerdictTimeoutEvent() {
    AcquireExclusivePushLock(&g_RuntimeStatusLock);
    g_ProcessVerdictTimeoutCount++;
    g_LastProcessVerdictTimeoutTime = QueryCurrentSystemTimeValue();
    ReleaseExclusivePushLock(&g_RuntimeStatusLock);
}

NTSTATUS ProcessPortConnectNotify(
    _In_ PFLT_PORT ClientPort,
    _In_opt_ PVOID ServerPortCookie,
    _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
    _In_ ULONG SizeOfContext,
    _Outptr_result_maybenull_ PVOID* ConnectionCookie) {
    UNREFERENCED_PARAMETER(ServerPortCookie);
    UNREFERENCED_PARAMETER(ConnectionContext);
    UNREFERENCED_PARAMETER(SizeOfContext);

    if (ConnectionCookie != NULL) {
        *ConnectionCookie = NULL;
    }

    AcquireExclusivePushLock(&g_ProcessPortLock);
    if (g_ProcessClientPort != NULL) {
        ReleaseExclusivePushLock(&g_ProcessPortLock);
        return STATUS_DEVICE_BUSY;
    }

    g_ProcessClientPort = ClientPort;
    ReleaseExclusivePushLock(&g_ProcessPortLock);
    RecordProcessPortConnectEvent();
    return STATUS_SUCCESS;
}

VOID ProcessPortDisconnectNotify(_In_opt_ PVOID ConnectionCookie) {
    UNREFERENCED_PARAMETER(ConnectionCookie);

    AcquireExclusivePushLock(&g_ProcessPortLock);
    if (g_FilterHandle != NULL && g_ProcessClientPort != NULL) {
        FltCloseClientPort(g_FilterHandle, &g_ProcessClientPort);
    }
    ReleaseExclusivePushLock(&g_ProcessPortLock);
    RecordProcessPortDisconnectEvent();
}

NTSTATUS ProcessPortMessageNotify(
    _In_opt_ PVOID PortCookie,
    _In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _Out_writes_bytes_to_opt_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG ReturnOutputBufferLength) {
    UNREFERENCED_PARAMETER(PortCookie);
    UNREFERENCED_PARAMETER(InputBuffer);
    UNREFERENCED_PARAMETER(InputBufferLength);
    UNREFERENCED_PARAMETER(OutputBuffer);
    UNREFERENCED_PARAMETER(OutputBufferLength);

    if (ReturnOutputBufferLength != NULL) {
        *ReturnOutputBufferLength = 0;
    }

    return STATUS_INVALID_DEVICE_REQUEST;
}

static VOID CloseProcessCommunicationPorts() {
    AcquireExclusivePushLock(&g_ProcessPortLock);
    if (g_FilterHandle != NULL && g_ProcessClientPort != NULL) {
        FltCloseClientPort(g_FilterHandle, &g_ProcessClientPort);
    }
    ReleaseExclusivePushLock(&g_ProcessPortLock);

    if (g_ProcessServerPort != NULL) {
        FltCloseCommunicationPort(g_ProcessServerPort);
        g_ProcessServerPort = NULL;
    }
}

void UnloadDriver(PDRIVER_OBJECT DriverObject) {
    UNREFERENCED_PARAMETER(DriverObject);

    if (g_FilterHandle != NULL) {
        CloseProcessCommunicationPorts();
        FltUnregisterFilter(g_FilterHandle);
        g_FilterHandle = NULL;
        SetRuntimeStatusFlag(DRIVER_STATUS_FLAG_FILE_FILTER_READY, FALSE);
    }

    if (g_RegCookie.QuadPart != 0) {
        CmUnRegisterCallback(g_RegCookie);
        g_RegCookie.QuadPart = 0;
        SetRuntimeStatusFlag(DRIVER_STATUS_FLAG_REGISTRY_CALLBACK_REGISTERED, FALSE);
    }

    PsRemoveLoadImageNotifyRoutine(ImageNotifyCallback);
    SetRuntimeStatusFlag(DRIVER_STATUS_FLAG_IMAGE_CALLBACK_REGISTERED, FALSE);
    PsSetCreateProcessNotifyRoutineEx(ProcessNotifyCallbackEx, TRUE);
    SetRuntimeStatusFlag(DRIVER_STATUS_FLAG_PROCESS_CALLBACK_REGISTERED, FALSE);

    ExWaitForRundownProtectionRelease(&g_RundownRef);

    PIRP irpToCancel = (PIRP)InterlockedExchangePointer((PVOID*)&g_PendingDriverIrp, NULL);
    if (irpToCancel) {
        if (IoSetCancelRoutine(irpToCancel, NULL)) {
            irpToCancel->IoStatus.Status = STATUS_CANCELLED;
            irpToCancel->IoStatus.Information = 0;
            IoCompleteRequest(irpToCancel, IO_NO_INCREMENT);
        }
    }

    KIRQL oldIrql;
    KeAcquireSpinLock(&g_DriverQueueLock, &oldIrql);
    while (!IsListEmpty(&g_DriverEventQueue)) {
        PLIST_ENTRY drvEntry = RemoveHeadList(&g_DriverEventQueue);
        PDRIVER_EVENT_NODE drvNode = CONTAINING_RECORD(drvEntry, DRIVER_EVENT_NODE, ListEntry);
        FreeDriverEventNode(drvNode);
    }
    g_DriverEventCount = 0;
    KeReleaseSpinLock(&g_DriverQueueLock, oldIrql);

    AcquireExclusivePushLock(&g_BlacklistLock);
    ClearDriverBlacklistRulesLocked();
    g_BlacklistCount = 0;
    ReleaseExclusivePushLock(&g_BlacklistLock);

    ExDeleteNPagedLookasideList(&g_DriverEventLookaside);

    UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\DosDevices\\PebMonitor");
    IoDeleteSymbolicLink(&symLink);
    if (g_DeviceObject) {
        IoDeleteDevice(g_DeviceObject);
    }
    ResetRuntimeConfigInfo();
    SetRuntimeStatusFlag(DRIVER_STATUS_FLAG_DEVICE_READY, FALSE);

    KdPrint(("[PebMonitor] INFO: Driver Unloaded Safely.\n"));
}

extern "C" NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);
    DriverObject->DriverUnload = UnloadDriver;
    NTSTATUS status = STATUS_SUCCESS;
    BOOLEAN lookasideInitialized = FALSE;
    BOOLEAN deviceCreated = FALSE;
    BOOLEAN symbolicLinkCreated = FALSE;
    BOOLEAN filterRegistered = FALSE;
    BOOLEAN processPortCreated = FALSE;
    BOOLEAN registryCallbackRegistered = FALSE;
    BOOLEAN processCallbackRegistered = FALSE;
    BOOLEAN imageCallbackRegistered = FALSE;
    PSECURITY_DESCRIPTOR securityDescriptor = NULL;
    UNICODE_STRING processPortName = { 0 };
    OBJECT_ATTRIBUTES processPortAttributes = { 0 };
    UNICODE_STRING altitude = { 0 };

    ExInitializeDriverRuntime(DrvRtPoolNxOptIn);

    InitializeListHead(&g_DriverEventQueue);
    KeInitializeSpinLock(&g_DriverQueueLock);
    g_DriverEventCount = 0;
    ExInitializeNPagedLookasideList(
        &g_DriverEventLookaside,
        NULL,
        NULL,
        0,
        sizeof(DRIVER_EVENT_NODE),
        'drPM',
        0);
    lookasideInitialized = TRUE;

    ExInitializePushLock(&g_BlacklistLock);
    g_BlacklistCount = 0;
    ClearDriverBlacklistRulesLocked();

    ExInitializePushLock(&g_ProcessPortLock);
    g_ProcessServerPort = NULL;
    g_ProcessClientPort = NULL;

    ExInitializePushLock(&g_RegistryRuleLock);
    g_RegistryRuleCount = 0;
    RtlZeroMemory(g_RegistryRules, sizeof(g_RegistryRules));

    ExInitializePushLock(&g_RegistryAllowRuleLock);
    g_RegistryAllowRuleCount = 0;
    RtlZeroMemory(g_RegistryAllowRules, sizeof(g_RegistryAllowRules));

    ExInitializePushLock(&g_FileRuleLock);
    g_FileRuleCount = 0;
    RtlZeroMemory(g_FileRules, sizeof(g_FileRules));

    ExInitializePushLock(&g_RuntimeStatusLock);
    g_RuntimeStatusFlags = 0;
    g_ProcessVerdictRequestCount = 0;
    g_ProcessVerdictTimeoutCount = 0;
    g_ProcessPortConnectCount = 0;
    g_ProcessPortDisconnectCount = 0;
    g_LastProcessPortConnectTime = 0;
    g_LastProcessPortDisconnectTime = 0;
    g_LastProcessVerdictTimeoutTime = 0;
    g_ProcessVerdictTimeoutMs = PROCESS_VERDICT_TIMEOUT_MS_DEFAULT;
    g_ProcessVerdictFailMode = PROCESS_VERDICT_FAIL_OPEN;
    g_CaptureParentCommandLine = PROCESS_PARENT_CMDLINE_CAPTURE_DISABLED;
    g_NextProcessEventId = 0;
    RtlZeroMemory(g_ActiveConfigVersion, sizeof(g_ActiveConfigVersion));
    RtlZeroMemory(g_ActiveProfileName, sizeof(g_ActiveProfileName));
    RtlZeroMemory(g_ActiveGeneratedAt, sizeof(g_ActiveGeneratedAt));

    ExInitializeRundownProtection(&g_RundownRef);

    UNICODE_STRING devName = RTL_CONSTANT_STRING(L"\\Device\\PebMonitor");
    UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\DosDevices\\PebMonitor");
    UNICODE_STRING sddl = RTL_CONSTANT_STRING(L"D:P(A;;GA;;;SY)(A;;GA;;;BA)");

    status = IoCreateDeviceSecure(
        DriverObject,
        0,
        &devName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &sddl,
        (LPCGUID)&GUID_SD_PEBMONITOR,
        &g_DeviceObject
    );
    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }
    deviceCreated = TRUE;

    status = IoCreateSymbolicLink(&symLink, &devName);
    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }
    symbolicLinkCreated = TRUE;

    DriverObject->MajorFunction[IRP_MJ_CREATE] = DispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = DispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchDeviceControl;

    status = FltRegisterFilter(DriverObject, &g_FilterRegistration, &g_FilterHandle);
    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }
    filterRegistered = TRUE;

    status = FltBuildDefaultSecurityDescriptor(&securityDescriptor, FLT_PORT_ALL_ACCESS);
    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }

    RtlInitUnicodeString(&processPortName, PEBMONITOR_PROCESS_PORT_NAME);
    InitializeObjectAttributes(
        &processPortAttributes,
        &processPortName,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        NULL,
        securityDescriptor);

    status = FltCreateCommunicationPort(
        g_FilterHandle,
        &g_ProcessServerPort,
        &processPortAttributes,
        NULL,
        ProcessPortConnectNotify,
        ProcessPortDisconnectNotify,
        ProcessPortMessageNotify,
        1);
    FltFreeSecurityDescriptor(securityDescriptor);
    securityDescriptor = NULL;

    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }
    processPortCreated = TRUE;

    RtlInitUnicodeString(&altitude, L"320000");
    status = CmRegisterCallbackEx(RegistryCallback, &altitude, DriverObject, NULL, &g_RegCookie, NULL);
    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }
    registryCallbackRegistered = TRUE;
    SetRuntimeStatusFlag(DRIVER_STATUS_FLAG_REGISTRY_CALLBACK_REGISTERED, TRUE);

    status = PsSetCreateProcessNotifyRoutineEx(ProcessNotifyCallbackEx, FALSE);
    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }
    processCallbackRegistered = TRUE;
    SetRuntimeStatusFlag(DRIVER_STATUS_FLAG_PROCESS_CALLBACK_REGISTERED, TRUE);

    status = PsSetLoadImageNotifyRoutine(ImageNotifyCallback);
    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }
    imageCallbackRegistered = TRUE;
    SetRuntimeStatusFlag(DRIVER_STATUS_FLAG_IMAGE_CALLBACK_REGISTERED, TRUE);

    status = FltStartFiltering(g_FilterHandle);
    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }

    SetRuntimeStatusFlag(DRIVER_STATUS_FLAG_FILE_FILTER_READY, TRUE);
    SetRuntimeStatusFlag(DRIVER_STATUS_FLAG_DEVICE_READY, TRUE);

    KdPrint(("[PebMonitor] INFO: Driver Loaded Successfully with Registry + File Protection.\n"));
    return STATUS_SUCCESS;

Cleanup:
    if (securityDescriptor != NULL) {
        FltFreeSecurityDescriptor(securityDescriptor);
        securityDescriptor = NULL;
    }

    if (imageCallbackRegistered) {
        PsRemoveLoadImageNotifyRoutine(ImageNotifyCallback);
        SetRuntimeStatusFlag(DRIVER_STATUS_FLAG_IMAGE_CALLBACK_REGISTERED, FALSE);
    }

    if (processCallbackRegistered) {
        PsSetCreateProcessNotifyRoutineEx(ProcessNotifyCallbackEx, TRUE);
        SetRuntimeStatusFlag(DRIVER_STATUS_FLAG_PROCESS_CALLBACK_REGISTERED, FALSE);
    }

    if (registryCallbackRegistered) {
        CmUnRegisterCallback(g_RegCookie);
        g_RegCookie.QuadPart = 0;
        SetRuntimeStatusFlag(DRIVER_STATUS_FLAG_REGISTRY_CALLBACK_REGISTERED, FALSE);
    }

    if (processPortCreated) {
        CloseProcessCommunicationPorts();
    }

    if (filterRegistered) {
        FltUnregisterFilter(g_FilterHandle);
        g_FilterHandle = NULL;
    }

    if (symbolicLinkCreated) {
        IoDeleteSymbolicLink(&symLink);
    }

    if (deviceCreated) {
        IoDeleteDevice(g_DeviceObject);
        g_DeviceObject = NULL;
    }

    if (lookasideInitialized) {
        ExDeleteNPagedLookasideList(&g_DriverEventLookaside);
    }

    SetRuntimeStatusFlag(DRIVER_STATUS_FLAG_FILE_FILTER_READY, FALSE);
    SetRuntimeStatusFlag(DRIVER_STATUS_FLAG_DEVICE_READY, FALSE);
    return status;
}
