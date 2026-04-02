#pragma once
#include <ntifs.h>
#include <ntstrsafe.h>
#include <ntimage.h>
#include "Shared.h"

// ===========================================================================
// 【修复】：手动补全内核头文件中缺失的进程操作权限宏
// ===========================================================================
#ifndef PROCESS_TERMINATE
#define PROCESS_TERMINATE (0x0001)
#endif

#ifndef PROCESS_VM_READ
#define PROCESS_VM_READ (0x0010)
#endif

#define MAX_EVENT_COUNT 1000 
#define MAX_BLACKLIST_ENTRIES 1000

// ---------------------------------------------------------------------------
// [修复] 队列结构精简：删除了 WaitEvent 和 BlockVerdict，实现 0 阻塞！
// ---------------------------------------------------------------------------
typedef struct _PROCESS_EVENT_NODE {
	LIST_ENTRY ListEntry;
	PROCESS_EVENT EventData;
	BOOLEAN IsSentToUser;
} PROCESS_EVENT_NODE, *PPROCESS_EVENT_NODE;

typedef struct _DRIVER_EVENT_NODE {
	LIST_ENTRY ListEntry;
	DRIVER_EVENT EventData;
} DRIVER_EVENT_NODE, *PDRIVER_EVENT_NODE;

extern PDEVICE_OBJECT g_DeviceObject;
extern EX_RUNDOWN_REF g_RundownRef;

extern LIST_ENTRY g_EventQueue;
extern KSPIN_LOCK g_QueueLock;
extern PIRP g_PendingEventIrp;
extern ULONG g_EventCount;

extern LIST_ENTRY g_DriverEventQueue;
extern KSPIN_LOCK g_DriverQueueLock;
extern PIRP g_PendingDriverIrp;
extern ULONG g_DriverEventCount;

extern WCHAR g_DriverBlacklist[MAX_BLACKLIST_ENTRIES][MAX_RULE_LENGTH];
extern ULONG g_BlacklistCount;
extern KSPIN_LOCK g_BlacklistLock;

extern LARGE_INTEGER g_RegCookie;

void ProcessNotifyCallbackEx(_Inout_ PEPROCESS Process, _In_ HANDLE ProcessId, _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo);
VOID ImageNotifyCallback(_In_opt_ PUNICODE_STRING FullImageName, _In_ HANDLE ProcessId, _In_ PIMAGE_INFO ImageInfo);
NTSTATUS RegistryCallback(_In_ PVOID CallbackContext, _In_ PVOID Argument1, _In_ PVOID Argument2);

NTSTATUS DispatchCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS DispatchDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp);
VOID CancelPendingEventIrp(PDEVICE_OBJECT DeviceObject, PIRP Irp);
VOID CancelPendingDriverIrp(PDEVICE_OBJECT DeviceObject, PIRP Irp);

// --- 官方与未文档化 API 声明 ---
extern "C" NTSTATUS ZwQueryInformationProcess(
	_In_      HANDLE           ProcessHandle,
	_In_      PROCESSINFOCLASS ProcessInformationClass,
	_Out_     PVOID            ProcessInformation,
	_In_      ULONG            ProcessInformationLength,
	_Out_opt_ PULONG           ReturnLength
);