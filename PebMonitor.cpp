/* Core entry: global state definitions and driver load/unload. */
#include "PebMonitor.h"

#include <initguid.h>

PDEVICE_OBJECT g_DeviceObject = NULL;
EX_RUNDOWN_REF g_RundownRef;
volatile LONG64 g_NextProcessEventId = 0;
ERESOURCE g_ProcessPortLock = {};
PFLT_PORT g_ProcessServerPort = NULL;
PFLT_PORT g_ProcessClientPort = NULL;

LIST_ENTRY g_DriverEventQueue;
KSPIN_LOCK g_DriverQueueLock;
PIRP g_PendingDriverIrp = NULL;
ULONG g_DriverEventCount = 0;
volatile LONG64 g_DriverEventDropCount = 0;
volatile LONG64 g_DriverEventAllocFailCount = 0;
NPAGED_LOOKASIDE_LIST g_DriverEventLookaside;

PRULE_STORE g_RegistryBlockRuleStore = NULL;
PRULE_STORE g_RegistryAllowRuleStore = NULL;
ERESOURCE g_RuleStoreStateLock = {};
volatile LONG g_PolicyEpoch = 0;

LARGE_INTEGER g_RegCookie = { 0 };
ULONG g_RuntimeStatusFlags = 0;
HIPS_PROTECTION_MODE g_ProtectionMode = HIPS_MODE_BLOCKING;
ERESOURCE g_RuntimeStatusLock = {};
ULONGLONG g_ProcessVerdictRequestCount = 0;
ULONGLONG g_ProcessVerdictTimeoutCount = 0;
ULONGLONG g_ProcessPortConnectCount = 0;
ULONGLONG g_ProcessPortDisconnectCount = 0;
ULONGLONG g_LastProcessPortConnectTime = 0;
ULONGLONG g_LastProcessPortDisconnectTime = 0;
ULONGLONG g_LastProcessVerdictTimeoutTime = 0;
volatile LONG g_ProcessVerdictBreakerOpen = 0;
volatile LONG g_ProcessPortConnected = 0;
volatile LONG64 g_LastHeartbeatInterruptTime = 0;
volatile LONG64 g_LastHeartbeatTime = 0;
volatile LONG64 g_ProcessBreakerOpenCount = 0;
volatile LONG64 g_LastProcessBreakerOpenTime = 0;
volatile LONG64 g_LastProcessBreakerCloseTime = 0;
ULONG g_ProcessVerdictTimeoutMs = PROCESS_VERDICT_TIMEOUT_MS_DEFAULT;
ULONG g_ProcessVerdictFailMode = PROCESS_VERDICT_FAIL_OPEN;
ULONG g_HeartbeatIntervalMs = PROCESS_HEARTBEAT_INTERVAL_MS_DEFAULT;
ULONG g_HeartbeatTimeoutMs = PROCESS_HEARTBEAT_TIMEOUT_MS_DEFAULT;
ULONG g_CaptureParentCommandLine = PROCESS_PARENT_CMDLINE_CAPTURE_DISABLED;
WCHAR g_ActiveConfigVersion[MAX_RULE_LENGTH];
WCHAR g_ActiveProfileName[MAX_RULE_LENGTH];
WCHAR g_ActiveGeneratedAt[MAX_RULE_LENGTH];
PFLT_FILTER g_FilterHandle = NULL;
KTIMER g_HeartbeatCheckTimer = {};
KDPC g_HeartbeatCheckDpc = {};

static LONG ReadInterlockedLong(_In_ volatile LONG* value) {
    return InterlockedCompareExchange(value, 0, 0);
}

static ULONGLONG ReadInterlockedCounter64(_In_ volatile LONG64* value) {
    return (ULONGLONG)InterlockedCompareExchange64(value, 0, 0);
}

static VOID SetRuntimeStatusFlag(_In_ ULONG flag, _In_ BOOLEAN enabled) {
    if (enabled) {
        InterlockedOr((volatile LONG*)&g_RuntimeStatusFlags, (LONG)flag);
    }
    else {
        InterlockedAnd((volatile LONG*)&g_RuntimeStatusFlags, ~((LONG)flag));
    }
}

static VOID InitializeProtectionMode() {
    HIPS_PROTECTION_MODE protectionMode = HIPS_MODE_BLOCKING;

    if (g_ApiSupport.OsMajorVersion < 6 ||
        (g_ApiSupport.OsMajorVersion == 6 && g_ApiSupport.OsMinorVersion <= 1)) {
        protectionMode = HIPS_MODE_MONITOR_ONLY;
    }

    g_ProtectionMode = protectionMode;
    SetRuntimeStatusFlag(DRIVER_STATUS_FLAG_MONITOR_ONLY, protectionMode == HIPS_MODE_MONITOR_ONLY);

    KdPrint((
        "[PebMonitor] INFO: Protection mode initialized. Mode=%s OS=%lu.%lu build=%lu\n",
        (protectionMode == HIPS_MODE_MONITOR_ONLY) ? "monitor_only" : "blocking",
        g_ApiSupport.OsMajorVersion,
        g_ApiSupport.OsMinorVersion,
        g_ApiSupport.OsBuildNumber));
}

static VOID ResetRuntimeConfigInfo() {
    AcquireExclusiveResourceLock(&g_RuntimeStatusLock);
    RtlZeroMemory(g_ActiveConfigVersion, sizeof(g_ActiveConfigVersion));
    RtlZeroMemory(g_ActiveProfileName, sizeof(g_ActiveProfileName));
    RtlZeroMemory(g_ActiveGeneratedAt, sizeof(g_ActiveGeneratedAt));
    ReleaseExclusiveResourceLock(&g_RuntimeStatusLock);
}

static ULONGLONG QueryCurrentSystemTimeValue() {
    LARGE_INTEGER now = { 0 };
    KeQuerySystemTime(&now);
    return (ULONGLONG)now.QuadPart;
}

static ULONGLONG QueryCurrentInterruptTimeValue() {
    return KeQueryInterruptTime();
}

static VOID OpenProcessVerdictBreaker(_In_ ULONGLONG nowWallTime) {
    if (InterlockedCompareExchange(&g_ProcessVerdictBreakerOpen, 1, 0) != 0) {
        return;
    }

    SetRuntimeStatusFlag(DRIVER_STATUS_FLAG_PROCESS_BREAKER_OPEN, TRUE);
    InterlockedIncrement64(&g_ProcessBreakerOpenCount);
    InterlockedExchange64(&g_LastProcessBreakerOpenTime, (LONG64)nowWallTime);
    KdPrint(("[PebMonitor] WARN: Process verdict breaker opened; process create path is fail-open until heartbeat recovery.\n"));
}

static VOID CloseProcessVerdictBreaker(_In_ ULONGLONG nowWallTime) {
    if (InterlockedCompareExchange(&g_ProcessVerdictBreakerOpen, 0, 1) != 1) {
        return;
    }

    SetRuntimeStatusFlag(DRIVER_STATUS_FLAG_PROCESS_BREAKER_OPEN, FALSE);
    InterlockedExchange64(&g_LastProcessBreakerCloseTime, (LONG64)nowWallTime);
    KdPrint(("[PebMonitor] INFO: Process verdict breaker closed after heartbeat recovery.\n"));
}

VOID RecordProcessHeartbeatEvent() {
    ULONGLONG nowInterruptTime = QueryCurrentInterruptTimeValue();
    ULONGLONG nowWallTime = QueryCurrentSystemTimeValue();
    InterlockedExchange64(&g_LastHeartbeatInterruptTime, (LONG64)nowInterruptTime);
    InterlockedExchange64(&g_LastHeartbeatTime, (LONG64)nowWallTime);
    CloseProcessVerdictBreaker(nowWallTime);
}

static VOID HeartbeatCheckDpcRoutine(
    _In_ struct _KDPC* Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2) {
    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(DeferredContext);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);

    if (ReadInterlockedLong(&g_ProcessPortConnected) == 0) {
        return;
    }

    if (ReadInterlockedLong(&g_ProcessVerdictBreakerOpen) != 0) {
        return;
    }

    ULONGLONG lastHeartbeat = ReadInterlockedCounter64(&g_LastHeartbeatInterruptTime);
    if (lastHeartbeat == 0) {
        return;
    }

    ULONGLONG timeoutTicks = (ULONGLONG)g_HeartbeatTimeoutMs * 10ULL * 1000ULL;
    ULONGLONG nowInterruptTime = QueryCurrentInterruptTimeValue();
    if (nowInterruptTime > lastHeartbeat &&
        (nowInterruptTime - lastHeartbeat) > timeoutTicks) {
        OpenProcessVerdictBreaker(QueryCurrentSystemTimeValue());
    }
}

static VOID RecordProcessPortConnectEvent() {
    ULONGLONG nowWallTime = QueryCurrentSystemTimeValue();
    InterlockedExchange(&g_ProcessPortConnected, 1);
    InterlockedExchange64(&g_LastHeartbeatInterruptTime, (LONG64)QueryCurrentInterruptTimeValue());
    InterlockedExchange64(&g_LastHeartbeatTime, (LONG64)nowWallTime);
    SetRuntimeStatusFlag(DRIVER_STATUS_FLAG_PROCESS_PORT_CONNECTED, TRUE);
    CloseProcessVerdictBreaker(nowWallTime);

    AcquireExclusiveResourceLock(&g_RuntimeStatusLock);
    g_ProcessPortConnectCount++;
    g_LastProcessPortConnectTime = nowWallTime;
    ReleaseExclusiveResourceLock(&g_RuntimeStatusLock);
}

static VOID RecordProcessPortDisconnectEvent() {
    InterlockedExchange(&g_ProcessPortConnected, 0);
    InterlockedExchange64(&g_LastHeartbeatInterruptTime, 0);

    AcquireExclusiveResourceLock(&g_RuntimeStatusLock);
    if ((g_RuntimeStatusFlags & DRIVER_STATUS_FLAG_PROCESS_PORT_CONNECTED) != 0) {
        g_ProcessPortDisconnectCount++;
        g_LastProcessPortDisconnectTime = QueryCurrentSystemTimeValue();
    }
    ReleaseExclusiveResourceLock(&g_RuntimeStatusLock);

    SetRuntimeStatusFlag(DRIVER_STATUS_FLAG_PROCESS_PORT_CONNECTED, FALSE);
}

VOID RecordProcessVerdictRequestEvent() {
    AcquireExclusiveResourceLock(&g_RuntimeStatusLock);
    g_ProcessVerdictRequestCount++;
    ReleaseExclusiveResourceLock(&g_RuntimeStatusLock);
}

VOID RecordProcessVerdictTimeoutEvent() {
    AcquireExclusiveResourceLock(&g_RuntimeStatusLock);
    g_ProcessVerdictTimeoutCount++;
    g_LastProcessVerdictTimeoutTime = QueryCurrentSystemTimeValue();
    ReleaseExclusiveResourceLock(&g_RuntimeStatusLock);
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

    ULONG clientProcessId = HandleToULong(PsGetCurrentProcessId());
    if (ConnectionCookie != NULL) {
        *ConnectionCookie = ULongToPtr(clientProcessId);
    }

    AcquireExclusiveResourceLock(&g_ProcessPortLock);
    if (g_ProcessClientPort != NULL) {
        ReleaseExclusiveResourceLock(&g_ProcessPortLock);
        return STATUS_DEVICE_BUSY;
    }

    g_ProcessClientPort = ClientPort;
    ReleaseExclusiveResourceLock(&g_ProcessPortLock);

    if (!RegisterFastPathTrustedProcess(
        clientProcessId,
        PsGetCurrentProcess(),
        FASTPATH_TRUST_FLAG_PROCESS_PORT_CLIENT)) {
        KdPrint(("[PebMonitor] WARN: Failed to register trusted fast-path client process. PID=%lu\n", clientProcessId));
    }

    RecordProcessPortConnectEvent();
    return STATUS_SUCCESS;
}

VOID ProcessPortDisconnectNotify(_In_opt_ PVOID ConnectionCookie) {
    PFLT_PORT clientPort = NULL;
    PFLT_FILTER filterHandle = NULL;
    ULONG clientProcessId = HandleToULong(ConnectionCookie);

    AcquireExclusiveResourceLock(&g_ProcessPortLock);
    clientPort = g_ProcessClientPort;
    filterHandle = g_FilterHandle;
    g_ProcessClientPort = NULL;
    ReleaseExclusiveResourceLock(&g_ProcessPortLock);

    if (filterHandle != NULL && clientPort != NULL) {
        FltCloseClientPort(filterHandle, &clientPort);
    }

    if (clientProcessId != 0) {
        RemoveFastPathTrustedProcess(clientProcessId);
        FlushDecisionCacheForProcess(clientProcessId);
    }

    RecordProcessPortDisconnectEvent();
    KdPrint(("[PebMonitor] WARN: Process verdict port disconnected; process create path is fail-open until reconnect.\n"));
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
    PFLT_PORT clientPort = NULL;
    PFLT_FILTER filterHandle = NULL;

    AcquireExclusiveResourceLock(&g_ProcessPortLock);
    clientPort = g_ProcessClientPort;
    filterHandle = g_FilterHandle;
    g_ProcessClientPort = NULL;
    ReleaseExclusiveResourceLock(&g_ProcessPortLock);

    if (filterHandle != NULL && clientPort != NULL) {
        FltCloseClientPort(filterHandle, &clientPort);
    }

    if (g_ProcessServerPort != NULL) {
        FltCloseCommunicationPort(g_ProcessServerPort);
        g_ProcessServerPort = NULL;
    }
}

void UnloadDriver(PDRIVER_OBJECT DriverObject) {
    UNREFERENCED_PARAMETER(DriverObject);

    KeCancelTimer(&g_HeartbeatCheckTimer);
    KeFlushQueuedDpcs();

    if (g_FilterHandle != NULL) {
        CloseProcessCommunicationPorts();
        FltUnregisterFilter(g_FilterHandle);
        g_FilterHandle = NULL;
    }

    if (g_RegCookie.QuadPart != 0) {
        CmUnRegisterCallback(g_RegCookie);
        g_RegCookie.QuadPart = 0;
        SetRuntimeStatusFlag(DRIVER_STATUS_FLAG_REGISTRY_CALLBACK_REGISTERED, FALSE);
    }

    PsSetCreateProcessNotifyRoutineEx(ProcessNotifyCallbackEx, TRUE);
    SetRuntimeStatusFlag(DRIVER_STATUS_FLAG_PROCESS_CALLBACK_REGISTERED, FALSE);

    ExWaitForRundownProtectionRelease(&g_RundownRef);
    CleanupRuleStoreState();
    CleanupDecisionCacheState();
    CleanupFastPathState();

    PIRP irpToCancel = (PIRP)InterlockedExchangePointer((PVOID*)&g_PendingDriverIrp, NULL);
    if (irpToCancel != NULL) {
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

    ExDeleteNPagedLookasideList(&g_DriverEventLookaside);

    ResetRuntimeConfigInfo();
    ExDeleteResourceLite(&g_RuntimeStatusLock);
    ExDeleteResourceLite(&g_RuleStoreStateLock);
    ExDeleteResourceLite(&g_ProcessPortLock);

    UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\DosDevices\\PebMonitor");
    IoDeleteSymbolicLink(&symLink);
    if (g_DeviceObject != NULL) {
        IoDeleteDevice(g_DeviceObject);
        g_DeviceObject = NULL;
    }

    SetRuntimeStatusFlag(DRIVER_STATUS_FLAG_DEVICE_READY, FALSE);

    KdPrint(("[PebMonitor] INFO: Driver Unloaded Safely.\n"));
}

extern "C" NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);

    DriverObject->DriverUnload = UnloadDriver;

#if defined(PEBMONITOR_BREAK_ON_ENTRY)
    if (KD_DEBUGGER_ENABLED && !KdRefreshDebuggerNotPresent()) {
        KdPrint(("[PebMonitor] INFO: Breaking in DriverEntry because PEBMONITOR_BREAK_ON_ENTRY is enabled.\n"));
        DbgBreakPoint();
    }
    else {
        KdPrint(("[PebMonitor] INFO: PEBMONITOR_BREAK_ON_ENTRY enabled, but no kernel debugger is attached.\n"));
    }
#endif

    NTSTATUS status = STATUS_SUCCESS;
    BOOLEAN lookasideInitialized = FALSE;
    BOOLEAN deviceCreated = FALSE;
    BOOLEAN symbolicLinkCreated = FALSE;
    BOOLEAN filterRegistered = FALSE;
    BOOLEAN processPortCreated = FALSE;
    BOOLEAN registryCallbackRegistered = FALSE;
    BOOLEAN processCallbackRegistered = FALSE;
    BOOLEAN processPortLockInitialized = FALSE;
    BOOLEAN ruleStoreStateLockInitialized = FALSE;
    BOOLEAN fastPathStateInitialized = FALSE;
    BOOLEAN decisionCacheStateInitialized = FALSE;
    BOOLEAN runtimeStatusLockInitialized = FALSE;
    PSECURITY_DESCRIPTOR securityDescriptor = NULL;
    UNICODE_STRING processPortName = { 0 };
    OBJECT_ATTRIBUTES processPortAttributes = { 0 };
    UNICODE_STRING altitude = { 0 };
    LARGE_INTEGER heartbeatDueTime = {};
    UNICODE_STRING devName = RTL_CONSTANT_STRING(L"\\Device\\PebMonitor");
    UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\DosDevices\\PebMonitor");
    InitializeApiCompatibility();
    TryInitializeDriverRuntimeCompat();

    InitializeListHead(&g_DriverEventQueue);
    KeInitializeSpinLock(&g_DriverQueueLock);
    g_DriverEventCount = 0;
    g_DriverEventDropCount = 0;
    g_DriverEventAllocFailCount = 0;
    ExInitializeNPagedLookasideList(
        &g_DriverEventLookaside,
        NULL,
        NULL,
        0,
        sizeof(DRIVER_EVENT_NODE),
        'drPM',
        0);
    lookasideInitialized = TRUE;

    status = ExInitializeResourceLite(&g_ProcessPortLock);
    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }
    processPortLockInitialized = TRUE;
    g_ProcessServerPort = NULL;
    g_ProcessClientPort = NULL;
    g_ProcessPortConnected = 0;

    status = ExInitializeResourceLite(&g_RuleStoreStateLock);
    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }
    ruleStoreStateLockInitialized = TRUE;

    status = InitializeRuleStoreState();
    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }

    status = InitializeFastPathState();
    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }
    fastPathStateInitialized = TRUE;

    status = InitializeDecisionCacheState();
    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }
    decisionCacheStateInitialized = TRUE;

    status = ExInitializeResourceLite(&g_RuntimeStatusLock);
    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }
    runtimeStatusLockInitialized = TRUE;
    g_RuntimeStatusFlags = 0;
    g_ProtectionMode = HIPS_MODE_BLOCKING;
    g_ProcessVerdictRequestCount = 0;
    g_ProcessVerdictTimeoutCount = 0;
    g_ProcessPortConnectCount = 0;
    g_ProcessPortDisconnectCount = 0;
    g_LastProcessPortConnectTime = 0;
    g_LastProcessPortDisconnectTime = 0;
    g_LastProcessVerdictTimeoutTime = 0;
    g_ProcessVerdictBreakerOpen = 0;
    g_LastHeartbeatInterruptTime = 0;
    g_LastHeartbeatTime = 0;
    g_ProcessBreakerOpenCount = 0;
    g_LastProcessBreakerOpenTime = 0;
    g_LastProcessBreakerCloseTime = 0;
    g_ProcessVerdictTimeoutMs = PROCESS_VERDICT_TIMEOUT_MS_DEFAULT;
    g_ProcessVerdictFailMode = PROCESS_VERDICT_FAIL_OPEN;
    g_HeartbeatIntervalMs = PROCESS_HEARTBEAT_INTERVAL_MS_DEFAULT;
    g_HeartbeatTimeoutMs = PROCESS_HEARTBEAT_TIMEOUT_MS_DEFAULT;
    g_CaptureParentCommandLine = PROCESS_PARENT_CMDLINE_CAPTURE_DISABLED;
    g_NextProcessEventId = 0;
    g_PolicyEpoch = 0;
    RtlZeroMemory(g_ActiveConfigVersion, sizeof(g_ActiveConfigVersion));
    RtlZeroMemory(g_ActiveProfileName, sizeof(g_ActiveProfileName));
    RtlZeroMemory(g_ActiveGeneratedAt, sizeof(g_ActiveGeneratedAt));
    KeInitializeTimerEx(&g_HeartbeatCheckTimer, NotificationTimer);
    KeInitializeDpc(&g_HeartbeatCheckDpc, HeartbeatCheckDpcRoutine, NULL);
    InitializeProtectionMode();

    ExInitializeRundownProtection(&g_RundownRef);

    status = IoCreateDevice(
        DriverObject,
        0,
        &devName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &g_DeviceObject);
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

    status = FltStartFiltering(g_FilterHandle);
    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }

    SetRuntimeStatusFlag(DRIVER_STATUS_FLAG_DEVICE_READY, TRUE);
    heartbeatDueTime.QuadPart = -((LONGLONG)g_HeartbeatIntervalMs * 10 * 1000);
    KeSetTimerEx(
        &g_HeartbeatCheckTimer,
        heartbeatDueTime,
        (LONG)g_HeartbeatIntervalMs,
        &g_HeartbeatCheckDpc);
    KdPrint(("[PebMonitor] INFO: Driver Loaded Successfully with Process + Registry Protection.\n"));
    return STATUS_SUCCESS;

Cleanup:
    if (securityDescriptor != NULL) {
        FltFreeSecurityDescriptor(securityDescriptor);
        securityDescriptor = NULL;
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

    if (runtimeStatusLockInitialized) {
        ExDeleteResourceLite(&g_RuntimeStatusLock);
    }
    if (decisionCacheStateInitialized) {
        CleanupDecisionCacheState();
    }
    if (fastPathStateInitialized) {
        CleanupFastPathState();
    }
    if (ruleStoreStateLockInitialized) {
        CleanupRuleStoreState();
        ExDeleteResourceLite(&g_RuleStoreStateLock);
    }
    if (processPortLockInitialized) {
        ExDeleteResourceLite(&g_ProcessPortLock);
    }

    SetRuntimeStatusFlag(DRIVER_STATUS_FLAG_DEVICE_READY, FALSE);
    return status;
}
