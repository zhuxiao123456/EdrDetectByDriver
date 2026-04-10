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

typedef struct _DRIVER_EVENT_NODE {
    LIST_ENTRY ListEntry;
    DRIVER_EVENT EventData;
} DRIVER_EVENT_NODE, *PDRIVER_EVENT_NODE;

extern NPAGED_LOOKASIDE_LIST g_DriverEventLookaside;

FORCEINLINE VOID AcquireSharedPushLock(_Inout_ PEX_PUSH_LOCK lock) {
    KeEnterCriticalRegion();
    ExAcquirePushLockShared(lock);
}

FORCEINLINE VOID ReleaseSharedPushLock(_Inout_ PEX_PUSH_LOCK lock) {
    ExReleasePushLockShared(lock);
    KeLeaveCriticalRegion();
}

FORCEINLINE VOID AcquireExclusivePushLock(_Inout_ PEX_PUSH_LOCK lock) {
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(lock);
}

FORCEINLINE VOID ReleaseExclusivePushLock(_Inout_ PEX_PUSH_LOCK lock) {
    ExReleasePushLockExclusive(lock);
    KeLeaveCriticalRegion();
}

extern PDEVICE_OBJECT g_DeviceObject;
extern EX_RUNDOWN_REF g_RundownRef;
extern volatile LONG64 g_NextProcessEventId;
extern EX_PUSH_LOCK g_ProcessPortLock;
extern PFLT_PORT g_ProcessServerPort;
extern PFLT_PORT g_ProcessClientPort;

extern LIST_ENTRY g_DriverEventQueue;
extern KSPIN_LOCK g_DriverQueueLock;
extern PIRP g_PendingDriverIrp;
extern ULONG g_DriverEventCount;

extern ULONG g_BlacklistCount;
extern EX_PUSH_LOCK g_BlacklistLock;

extern REGISTRY_RULE g_RegistryRules[MAX_REGISTRY_RULE_COUNT];
extern ULONG g_RegistryRuleCount;
extern EX_PUSH_LOCK g_RegistryRuleLock;

extern REGISTRY_RULE g_RegistryAllowRules[MAX_REGISTRY_RULE_COUNT];
extern ULONG g_RegistryAllowRuleCount;
extern EX_PUSH_LOCK g_RegistryAllowRuleLock;

extern FILE_RULE g_FileRules[MAX_FILE_RULE_COUNT];
extern ULONG g_FileRuleCount;
extern EX_PUSH_LOCK g_FileRuleLock;

extern LARGE_INTEGER g_RegCookie;
extern ULONG g_RuntimeStatusFlags;
extern EX_PUSH_LOCK g_RuntimeStatusLock;
extern ULONGLONG g_ProcessVerdictRequestCount;
extern ULONGLONG g_ProcessVerdictTimeoutCount;
extern ULONGLONG g_ProcessPortConnectCount;
extern ULONGLONG g_ProcessPortDisconnectCount;
extern ULONGLONG g_LastProcessPortConnectTime;
extern ULONGLONG g_LastProcessPortDisconnectTime;
extern ULONGLONG g_LastProcessVerdictTimeoutTime;
extern ULONG g_ProcessVerdictTimeoutMs;
extern ULONG g_ProcessVerdictFailMode;
extern ULONG g_CaptureParentCommandLine;
extern WCHAR g_ActiveConfigVersion[MAX_RULE_LENGTH];
extern WCHAR g_ActiveProfileName[MAX_RULE_LENGTH];
extern WCHAR g_ActiveGeneratedAt[MAX_RULE_LENGTH];
extern PFLT_FILTER g_FilterHandle;

extern const FLT_OPERATION_REGISTRATION g_FilterOperationCallbacks[];
extern const FLT_REGISTRATION g_FilterRegistration;

FORCEINLINE PDRIVER_EVENT_NODE AllocateDriverEventNode() {
    PDRIVER_EVENT_NODE node =
        (PDRIVER_EVENT_NODE)ExAllocateFromNPagedLookasideList(&g_DriverEventLookaside);
    if (node != NULL) {
        RtlZeroMemory(node, sizeof(DRIVER_EVENT_NODE));
    }
    return node;
}

FORCEINLINE VOID FreeDriverEventNode(_In_opt_ PDRIVER_EVENT_NODE node) {
    if (node != NULL) {
        ExFreeToNPagedLookasideList(&g_DriverEventLookaside, node);
    }
}

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
VOID CancelPendingDriverIrp(PDEVICE_OBJECT DeviceObject, PIRP Irp);
BOOLEAN MatchDriverBlacklistRuleLocked(_In_ PCUNICODE_STRING FullImageName);
NTSTATUS InsertDriverBlacklistRuleLocked(_In_z_ PCWSTR RuleText);
VOID ClearDriverBlacklistRulesLocked();
VOID RecordProcessVerdictRequestEvent();
VOID RecordProcessVerdictTimeoutEvent();
NTSTATUS ProcessPortConnectNotify(
    _In_ PFLT_PORT ClientPort,
    _In_opt_ PVOID ServerPortCookie,
    _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
    _In_ ULONG SizeOfContext,
    _Outptr_result_maybenull_ PVOID* ConnectionCookie);
VOID ProcessPortDisconnectNotify(_In_opt_ PVOID ConnectionCookie);
NTSTATUS ProcessPortMessageNotify(
    _In_opt_ PVOID PortCookie,
    _In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _Out_writes_bytes_to_opt_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG ReturnOutputBufferLength);
