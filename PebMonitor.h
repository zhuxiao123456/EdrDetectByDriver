#pragma once
#include <fltKernel.h>
#include <ntstrsafe.h>
#include <ntimage.h>
#include "ApiCompatibility.h"
#include "FastPath.h"
#include "DecisionCache.h"
#include "RuleStore.h"
#include "Shared.h"

#ifndef PROCESS_TERMINATE
#define PROCESS_TERMINATE (0x0001)
#endif

#define MAX_EVENT_COUNT 1000

typedef struct _DRIVER_EVENT_NODE {
    LIST_ENTRY ListEntry;
    DRIVER_EVENT EventData;
} DRIVER_EVENT_NODE, *PDRIVER_EVENT_NODE;

extern NPAGED_LOOKASIDE_LIST g_DriverEventLookaside;

_IRQL_requires_max_(APC_LEVEL)
FORCEINLINE VOID AcquireSharedResourceLock(_Inout_ PERESOURCE lock) {
    NT_ASSERT(KeGetCurrentIrql() <= APC_LEVEL);
    KeEnterCriticalRegion();
    ExAcquireResourceSharedLite(lock, TRUE);
}

_IRQL_requires_max_(APC_LEVEL)
FORCEINLINE VOID ReleaseSharedResourceLock(_Inout_ PERESOURCE lock) {
    NT_ASSERT(KeGetCurrentIrql() <= APC_LEVEL);
    ExReleaseResourceLite(lock);
    KeLeaveCriticalRegion();
}

_IRQL_requires_max_(APC_LEVEL)
FORCEINLINE VOID AcquireExclusiveResourceLock(_Inout_ PERESOURCE lock) {
    NT_ASSERT(KeGetCurrentIrql() <= APC_LEVEL);
    KeEnterCriticalRegion();
    ExAcquireResourceExclusiveLite(lock, TRUE);
}

_IRQL_requires_max_(APC_LEVEL)
FORCEINLINE VOID ReleaseExclusiveResourceLock(_Inout_ PERESOURCE lock) {
    NT_ASSERT(KeGetCurrentIrql() <= APC_LEVEL);
    ExReleaseResourceLite(lock);
    KeLeaveCriticalRegion();
}

extern PDEVICE_OBJECT g_DeviceObject;
extern EX_RUNDOWN_REF g_RundownRef;
extern volatile LONG64 g_NextProcessEventId;
extern ERESOURCE g_ProcessPortLock;
extern PFLT_PORT g_ProcessServerPort;
extern PFLT_PORT g_ProcessClientPort;

extern LIST_ENTRY g_DriverEventQueue;
extern KSPIN_LOCK g_DriverQueueLock;
extern PIRP g_PendingDriverIrp;
extern ULONG g_DriverEventCount;
extern volatile LONG64 g_DriverEventDropCount;
extern volatile LONG64 g_DriverEventAllocFailCount;

extern PRULE_STORE g_RegistryBlockRuleStore;
extern PRULE_STORE g_RegistryAllowRuleStore;
extern ERESOURCE g_RuleStoreStateLock;
extern volatile LONG g_PolicyEpoch;
extern volatile LONG64 g_FastPathHitCount;
extern volatile LONG64 g_DecisionCacheHitCount;
extern volatile LONG64 g_DecisionCacheMissCount;
extern volatile LONG64 g_DecisionCacheFlushCount;
extern volatile LONG64 g_SlowPathCount;

extern LARGE_INTEGER g_RegCookie;
extern ULONG g_RuntimeStatusFlags;
extern HIPS_PROTECTION_MODE g_ProtectionMode;
extern ERESOURCE g_RuntimeStatusLock;
extern ULONGLONG g_ProcessVerdictRequestCount;
extern ULONGLONG g_ProcessVerdictTimeoutCount;
extern ULONGLONG g_ProcessPortConnectCount;
extern ULONGLONG g_ProcessPortDisconnectCount;
extern ULONGLONG g_LastProcessPortConnectTime;
extern ULONGLONG g_LastProcessPortDisconnectTime;
extern ULONGLONG g_LastProcessVerdictTimeoutTime;
extern volatile LONG g_ProcessVerdictBreakerOpen;
extern volatile LONG g_ProcessPortConnected;
extern volatile LONG64 g_LastHeartbeatInterruptTime;
extern volatile LONG64 g_LastHeartbeatTime;
extern volatile LONG64 g_ProcessBreakerOpenCount;
extern volatile LONG64 g_LastProcessBreakerOpenTime;
extern volatile LONG64 g_LastProcessBreakerCloseTime;
extern ULONG g_ProcessVerdictTimeoutMs;
extern ULONG g_ProcessVerdictFailMode;
extern ULONG g_HeartbeatIntervalMs;
extern ULONG g_HeartbeatTimeoutMs;
extern ULONG g_CaptureParentCommandLine;
extern WCHAR g_ActiveConfigVersion[MAX_RULE_LENGTH];
extern WCHAR g_ActiveProfileName[MAX_RULE_LENGTH];
extern WCHAR g_ActiveGeneratedAt[MAX_RULE_LENGTH];
extern PFLT_FILTER g_FilterHandle;
extern KTIMER g_HeartbeatCheckTimer;
extern KDPC g_HeartbeatCheckDpc;

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

_IRQL_requires_(PASSIVE_LEVEL)
void ProcessNotifyCallbackEx(_Inout_ PEPROCESS Process, _In_ HANDLE ProcessId, _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo);
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS RegistryCallback(_In_ PVOID CallbackContext, _In_ PVOID Argument1, _In_ PVOID Argument2);
NTSTATUS FileFilterUnload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags);

NTSTATUS DispatchCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS DispatchDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp);
VOID CancelPendingDriverIrp(PDEVICE_OBJECT DeviceObject, PIRP Irp);
VOID RecordProcessVerdictRequestEvent();
VOID RecordProcessVerdictTimeoutEvent();
VOID RecordProcessHeartbeatEvent();
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
