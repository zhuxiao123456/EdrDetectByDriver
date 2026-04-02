/*
	核心入口: 全局变量的实体、驱动的装载与卸载
*/
// =======================================================
// 【修复】：PebMonitor.h 必须放在第一位！让编译器先认识内核基础类型
// =======================================================
#include "PebMonitor.h"  

#include <initguid.h>
#include <wdmsec.h> // 现在编译器认识它了

// 为我们的安全设备定义一个随机生成的唯一 GUID
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

LARGE_INTEGER g_RegCookie = { 0 }; // 全局 Cookie

// ===========================================================================
// 驱动卸载例程
// ===========================================================================
void UnloadDriver(PDRIVER_OBJECT DriverObject) {
	UNREFERENCED_PARAMETER(DriverObject);

	if (g_RegCookie.QuadPart != 0) {
		CmUnRegisterCallback(g_RegCookie);
		g_RegCookie.QuadPart = 0;
	}

	PsRemoveLoadImageNotifyRoutine(ImageNotifyCallback);
	PsSetCreateProcessNotifyRoutineEx(ProcessNotifyCallbackEx, TRUE);

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

	KdPrint(("[PebMonitor] INFO: Driver Unloaded Safely.\n"));
}

// ===========================================================================
// 驱动入口点
// ===========================================================================
extern "C" NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath) {
	UNREFERENCED_PARAMETER(RegistryPath);
	DriverObject->DriverUnload = UnloadDriver;

	// 【修复】：补全丢失的初始化代码，否则一运行就蓝屏！
	InitializeListHead(&g_EventQueue);
	KeInitializeSpinLock(&g_QueueLock);
	g_EventCount = 0;

	InitializeListHead(&g_DriverEventQueue);
	KeInitializeSpinLock(&g_DriverQueueLock);
	g_DriverEventCount = 0;

	KeInitializeSpinLock(&g_BlacklistLock);
	g_BlacklistCount = 0;
	RtlZeroMemory(g_DriverBlacklist, sizeof(g_DriverBlacklist));

	ExInitializeRundownProtection(&g_RundownRef);

	UNICODE_STRING devName = RTL_CONSTANT_STRING(L"\\Device\\PebMonitor");
	UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\DosDevices\\PebMonitor");

	// 安全设备对象创建
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

	UNICODE_STRING altitude;
	RtlInitUnicodeString(&altitude, L"320000");
	status = CmRegisterCallbackEx(RegistryCallback, &altitude, DriverObject, NULL, &g_RegCookie, NULL);
	if (!NT_SUCCESS(status)) {
		IoDeleteSymbolicLink(&symLink);
		IoDeleteDevice(g_DeviceObject);
		return status;
	}

	status = PsSetCreateProcessNotifyRoutineEx(ProcessNotifyCallbackEx, FALSE);
	if (!NT_SUCCESS(status)) {
		CmUnRegisterCallback(g_RegCookie);
		IoDeleteSymbolicLink(&symLink);
		IoDeleteDevice(g_DeviceObject);
		return status;
	}

	status = PsSetLoadImageNotifyRoutine(ImageNotifyCallback);
	if (!NT_SUCCESS(status)) {
		CmUnRegisterCallback(g_RegCookie);
		PsSetCreateProcessNotifyRoutineEx(ProcessNotifyCallbackEx, TRUE);
		IoDeleteSymbolicLink(&symLink);
		IoDeleteDevice(g_DeviceObject);
		return status;
	}

	KdPrint(("[PebMonitor] INFO: Driver Loaded Successfully with Registry Protection.\n"));
	return STATUS_SUCCESS;
}