/*
    核心入口: 全局变量的实体、驱动的装载与卸载
*/
#include "PebMonitor.h"

#include <initguid.h>
#include <wdmsec.h>

DEFINE_GUID(GUID_SD_PEBMONITOR, 0x8a923a1c, 0xc1d5, 0x4f2b, 0x9b, 0x11, 0x72, 0xa1, 0xd8, 0x3e, 0x5a, 0x9f);

PDEVICE_OBJECT g_DeviceObject = NULL;
EX_RUNDOWN_REF g_RundownRef;

LIST_ENTRY g_EventQueue;
KSPIN_LOCK g_QueueLock;
PIRP g_PendingEventIrp = NULL;
ULONG g_EventCount = 0;

LIST_ENTRY g_DriverEventQueue;
KSPIN_LOCK g_DriverQueueLock;
PIRP g_PendingDriverIrp = NULL;
ULONG g_DriverEventCount = 0;

WCHAR g_DriverBlacklist[MAX_BLACKLIST_ENTRIES][MAX_RULE_LENGTH];
ULONG g_BlacklistCount = 0;
KSPIN_LOCK g_BlacklistLock;

REGISTRY_RULE g_RegistryRules[MAX_REGISTRY_RULE_COUNT];
ULONG g_RegistryRuleCount = 0;
KSPIN_LOCK g_RegistryRuleLock;

REGISTRY_RULE g_RegistryAllowRules[MAX_REGISTRY_RULE_COUNT];
ULONG g_RegistryAllowRuleCount = 0;
KSPIN_LOCK g_RegistryAllowRuleLock;

FILE_RULE g_FileRules[MAX_FILE_RULE_COUNT];
ULONG g_FileRuleCount = 0;
KSPIN_LOCK g_FileRuleLock;

LARGE_INTEGER g_RegCookie = { 0 };
ULONG g_RuntimeStatusFlags = 0;
KSPIN_LOCK g_RuntimeStatusLock;
WCHAR g_ActiveConfigVersion[MAX_RULE_LENGTH];
WCHAR g_ActiveProfileName[MAX_RULE_LENGTH];
WCHAR g_ActiveGeneratedAt[MAX_RULE_LENGTH];
PFLT_FILTER g_FilterHandle = NULL;

static VOID SetRuntimeStatusFlag(_In_ ULONG flag, _In_ BOOLEAN enabled) {
    KIRQL oldIrql;
    KeAcquireSpinLock(&g_RuntimeStatusLock, &oldIrql);
    if (enabled) {
        g_RuntimeStatusFlags |= flag;
    }
    else {
        g_RuntimeStatusFlags &= ~flag;
    }
    KeReleaseSpinLock(&g_RuntimeStatusLock, oldIrql);
}

static VOID ResetRuntimeConfigInfo() {
    KIRQL oldIrql;
    KeAcquireSpinLock(&g_RuntimeStatusLock, &oldIrql);
    RtlZeroMemory(g_ActiveConfigVersion, sizeof(g_ActiveConfigVersion));
    RtlZeroMemory(g_ActiveProfileName, sizeof(g_ActiveProfileName));
    RtlZeroMemory(g_ActiveGeneratedAt, sizeof(g_ActiveGeneratedAt));
    KeReleaseSpinLock(&g_RuntimeStatusLock, oldIrql);
}

void UnloadDriver(PDRIVER_OBJECT DriverObject) {
    UNREFERENCED_PARAMETER(DriverObject);

    if (g_FilterHandle != NULL) {
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

    PIRP irpToCancel = (PIRP)InterlockedExchangePointer((PVOID*)&g_PendingEventIrp, NULL);
    if (irpToCancel) {
        if (IoSetCancelRoutine(irpToCancel, NULL)) {
            irpToCancel->IoStatus.Status = STATUS_CANCELLED;
            irpToCancel->IoStatus.Information = 0;
            IoCompleteRequest(irpToCancel, IO_NO_INCREMENT);
        }
    }

    irpToCancel = (PIRP)InterlockedExchangePointer((PVOID*)&g_PendingDriverIrp, NULL);
    if (irpToCancel) {
        if (IoSetCancelRoutine(irpToCancel, NULL)) {
            irpToCancel->IoStatus.Status = STATUS_CANCELLED;
            irpToCancel->IoStatus.Information = 0;
            IoCompleteRequest(irpToCancel, IO_NO_INCREMENT);
        }
    }

    KIRQL oldIrql;
    KeAcquireSpinLock(&g_QueueLock, &oldIrql);
    while (!IsListEmpty(&g_EventQueue)) {
        PLIST_ENTRY entry = RemoveHeadList(&g_EventQueue);
        PPROCESS_EVENT_NODE node = CONTAINING_RECORD(entry, PROCESS_EVENT_NODE, ListEntry);
        ExFreePoolWithTag(node, 'ndPM');
    }
    g_EventCount = 0;
    KeReleaseSpinLock(&g_QueueLock, oldIrql);

    KeAcquireSpinLock(&g_DriverQueueLock, &oldIrql);
    while (!IsListEmpty(&g_DriverEventQueue)) {
        PLIST_ENTRY drvEntry = RemoveHeadList(&g_DriverEventQueue);
        PDRIVER_EVENT_NODE drvNode = CONTAINING_RECORD(drvEntry, DRIVER_EVENT_NODE, ListEntry);
        ExFreePoolWithTag(drvNode, 'drPM');
    }
    g_DriverEventCount = 0;
    KeReleaseSpinLock(&g_DriverQueueLock, oldIrql);

    UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\DosDevices\\PebMonitor");
    IoDeleteSymbolicLink(&symLink);
    if (g_DeviceObject) IoDeleteDevice(g_DeviceObject);
    ResetRuntimeConfigInfo();
    SetRuntimeStatusFlag(DRIVER_STATUS_FLAG_DEVICE_READY, FALSE);

    KdPrint(("[PebMonitor] INFO: Driver Unloaded Safely.\n"));
}

extern "C" NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);
    DriverObject->DriverUnload = UnloadDriver;

    ExInitializeDriverRuntime(DrvRtPoolNxOptIn);

    InitializeListHead(&g_EventQueue);
    KeInitializeSpinLock(&g_QueueLock);
    g_EventCount = 0;

    InitializeListHead(&g_DriverEventQueue);
    KeInitializeSpinLock(&g_DriverQueueLock);
    g_DriverEventCount = 0;

    KeInitializeSpinLock(&g_BlacklistLock);
    g_BlacklistCount = 0;
    RtlZeroMemory(g_DriverBlacklist, sizeof(g_DriverBlacklist));

    KeInitializeSpinLock(&g_RegistryRuleLock);
    g_RegistryRuleCount = 0;
    RtlZeroMemory(g_RegistryRules, sizeof(g_RegistryRules));

    KeInitializeSpinLock(&g_RegistryAllowRuleLock);
    g_RegistryAllowRuleCount = 0;
    RtlZeroMemory(g_RegistryAllowRules, sizeof(g_RegistryAllowRules));

    KeInitializeSpinLock(&g_FileRuleLock);
    g_FileRuleCount = 0;
    RtlZeroMemory(g_FileRules, sizeof(g_FileRules));

    KeInitializeSpinLock(&g_RuntimeStatusLock);
    g_RuntimeStatusFlags = 0;
    RtlZeroMemory(g_ActiveConfigVersion, sizeof(g_ActiveConfigVersion));
    RtlZeroMemory(g_ActiveProfileName, sizeof(g_ActiveProfileName));
    RtlZeroMemory(g_ActiveGeneratedAt, sizeof(g_ActiveGeneratedAt));

    ExInitializeRundownProtection(&g_RundownRef);

    UNICODE_STRING devName = RTL_CONSTANT_STRING(L"\\Device\\PebMonitor");
    UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\DosDevices\\PebMonitor");
    UNICODE_STRING sddl = RTL_CONSTANT_STRING(L"D:P(A;;GA;;;SY)(A;;GA;;;BA)");

    NTSTATUS status = IoCreateDeviceSecure(
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
    if (!NT_SUCCESS(status)) return status;

    status = IoCreateSymbolicLink(&symLink, &devName);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(g_DeviceObject);
        return status;
    }

    DriverObject->MajorFunction[IRP_MJ_CREATE] = DispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = DispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchDeviceControl;

    status = FltRegisterFilter(DriverObject, &g_FilterRegistration, &g_FilterHandle);
    if (!NT_SUCCESS(status)) {
        IoDeleteSymbolicLink(&symLink);
        IoDeleteDevice(g_DeviceObject);
        g_DeviceObject = NULL;
        return status;
    }

    UNICODE_STRING altitude;
    RtlInitUnicodeString(&altitude, L"320000");
    status = CmRegisterCallbackEx(RegistryCallback, &altitude, DriverObject, NULL, &g_RegCookie, NULL);
    if (!NT_SUCCESS(status)) {
        FltUnregisterFilter(g_FilterHandle);
        g_FilterHandle = NULL;
        IoDeleteSymbolicLink(&symLink);
        IoDeleteDevice(g_DeviceObject);
        g_DeviceObject = NULL;
        return status;
    }
    SetRuntimeStatusFlag(DRIVER_STATUS_FLAG_REGISTRY_CALLBACK_REGISTERED, TRUE);

    status = PsSetCreateProcessNotifyRoutineEx(ProcessNotifyCallbackEx, FALSE);
    if (!NT_SUCCESS(status)) {
        CmUnRegisterCallback(g_RegCookie);
        g_RegCookie.QuadPart = 0;
        SetRuntimeStatusFlag(DRIVER_STATUS_FLAG_REGISTRY_CALLBACK_REGISTERED, FALSE);
        FltUnregisterFilter(g_FilterHandle);
        g_FilterHandle = NULL;
        IoDeleteSymbolicLink(&symLink);
        IoDeleteDevice(g_DeviceObject);
        g_DeviceObject = NULL;
        return status;
    }
    SetRuntimeStatusFlag(DRIVER_STATUS_FLAG_PROCESS_CALLBACK_REGISTERED, TRUE);

    status = PsSetLoadImageNotifyRoutine(ImageNotifyCallback);
    if (!NT_SUCCESS(status)) {
        CmUnRegisterCallback(g_RegCookie);
        g_RegCookie.QuadPart = 0;
        PsSetCreateProcessNotifyRoutineEx(ProcessNotifyCallbackEx, TRUE);
        SetRuntimeStatusFlag(DRIVER_STATUS_FLAG_REGISTRY_CALLBACK_REGISTERED, FALSE);
        SetRuntimeStatusFlag(DRIVER_STATUS_FLAG_PROCESS_CALLBACK_REGISTERED, FALSE);
        FltUnregisterFilter(g_FilterHandle);
        g_FilterHandle = NULL;
        IoDeleteSymbolicLink(&symLink);
        IoDeleteDevice(g_DeviceObject);
        g_DeviceObject = NULL;
        return status;
    }

    status = FltStartFiltering(g_FilterHandle);
    if (!NT_SUCCESS(status)) {
        PsRemoveLoadImageNotifyRoutine(ImageNotifyCallback);
        CmUnRegisterCallback(g_RegCookie);
        g_RegCookie.QuadPart = 0;
        PsSetCreateProcessNotifyRoutineEx(ProcessNotifyCallbackEx, TRUE);
        SetRuntimeStatusFlag(DRIVER_STATUS_FLAG_REGISTRY_CALLBACK_REGISTERED, FALSE);
        SetRuntimeStatusFlag(DRIVER_STATUS_FLAG_PROCESS_CALLBACK_REGISTERED, FALSE);
        FltUnregisterFilter(g_FilterHandle);
        g_FilterHandle = NULL;
        IoDeleteSymbolicLink(&symLink);
        IoDeleteDevice(g_DeviceObject);
        g_DeviceObject = NULL;
        return status;
    }

    SetRuntimeStatusFlag(DRIVER_STATUS_FLAG_IMAGE_CALLBACK_REGISTERED, TRUE);
    SetRuntimeStatusFlag(DRIVER_STATUS_FLAG_FILE_FILTER_READY, TRUE);
    SetRuntimeStatusFlag(DRIVER_STATUS_FLAG_DEVICE_READY, TRUE);

    KdPrint(("[PebMonitor] INFO: Driver Loaded Successfully with Registry + File Protection.\n"));
    return STATUS_SUCCESS;
}
