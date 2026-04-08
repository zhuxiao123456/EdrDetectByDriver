#pragma once
#include <fltKernel.h>
#include <ntstrsafe.h>
#include <ntimage.h>
#include "Shared.h"

#ifndef PROCESS_TERMINATE
#define PROCESS_TERMINATE (0x0001)
#endif

#define MAX_EVENT_COUNT 1000
#define MAX_BLACKLIST_ENTRIES 1000
#define PROCESS_EVENT_TIMEOUT_SECONDS 30

typedef struct _PROCESS_EVENT_NODE {
    LIST_ENTRY ListEntry;
    PROCESS_EVENT EventData;
    LARGE_INTEGER SentTime;
    PFILE_OBJECT OwnerFileObject;
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

extern REGISTRY_RULE g_RegistryRules[MAX_REGISTRY_RULE_COUNT];
extern ULONG g_RegistryRuleCount;
extern KSPIN_LOCK g_RegistryRuleLock;

extern REGISTRY_RULE g_RegistryAllowRules[MAX_REGISTRY_RULE_COUNT];
extern ULONG g_RegistryAllowRuleCount;
extern KSPIN_LOCK g_RegistryAllowRuleLock;

extern FILE_RULE g_FileRules[MAX_FILE_RULE_COUNT];
extern ULONG g_FileRuleCount;
extern KSPIN_LOCK g_FileRuleLock;

extern LARGE_INTEGER g_RegCookie;
extern ULONG g_RuntimeStatusFlags;
extern KSPIN_LOCK g_RuntimeStatusLock;
extern WCHAR g_ActiveConfigVersion[MAX_RULE_LENGTH];
extern WCHAR g_ActiveProfileName[MAX_RULE_LENGTH];
extern WCHAR g_ActiveGeneratedAt[MAX_RULE_LENGTH];
extern PFLT_FILTER g_FilterHandle;

extern const FLT_OPERATION_REGISTRATION g_FilterOperationCallbacks[];
extern const FLT_REGISTRATION g_FilterRegistration;

void ProcessNotifyCallbackEx(_Inout_ PEPROCESS Process, _In_ HANDLE ProcessId, _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo);
VOID ImageNotifyCallback(_In_opt_ PUNICODE_STRING FullImageName, _In_ HANDLE ProcessId, _In_ PIMAGE_INFO ImageInfo);
NTSTATUS RegistryCallback(_In_ PVOID CallbackContext, _In_ PVOID Argument1, _In_ PVOID Argument2);
NTSTATUS FileFilterUnload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags);
FLT_PREOP_CALLBACK_STATUS FilePreCreateOperation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext);

NTSTATUS DispatchCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS DispatchDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp);
VOID CancelPendingEventIrp(PDEVICE_OBJECT DeviceObject, PIRP Irp);
VOID CancelPendingDriverIrp(PDEVICE_OBJECT DeviceObject, PIRP Irp);
VOID PurgeExpiredProcessEvents();
VOID CleanupProcessEventsForFileObject(_In_opt_ PFILE_OBJECT FileObject);
VOID MarkProcessEventDelivered(_Inout_ PPROCESS_EVENT_NODE Node, _In_opt_ PFILE_OBJECT FileObject);
