#include "PebMonitor.h"

// 辅助函数：后缀匹配
BOOLEAN MatchDriverName(PUNICODE_STRING FullImageName, PCWSTR TargetSuffix) {
	UNICODE_STRING usTarget;
	RtlInitUnicodeString(&usTarget, TargetSuffix);
	if (FullImageName->Length < usTarget.Length) return FALSE;

	PWCH pStart = (PWCH)((PUCHAR)FullImageName->Buffer + FullImageName->Length - usTarget.Length);
	UNICODE_STRING usSuffix;
	usSuffix.Length = usTarget.Length;
	usSuffix.MaximumLength = usTarget.Length;
	usSuffix.Buffer = pStart;

	return RtlEqualUnicodeString(&usSuffix, &usTarget, TRUE);
}

// ===========================================================================
// [新增] 注册表监控回调：在驱动注册为服务时，实施合法拦截！
// ===========================================================================
NTSTATUS RegistryCallback(_In_ PVOID CallbackContext, _In_ PVOID Argument1, _In_ PVOID Argument2) {
	UNREFERENCED_PARAMETER(CallbackContext);

	if (!ExAcquireRundownProtection(&g_RundownRef)) {
		return STATUS_SUCCESS;
	}

	REG_NOTIFY_CLASS notifyClass = (REG_NOTIFY_CLASS)(ULONG_PTR)Argument1;
	NTSTATUS status = STATUS_SUCCESS;

	if (notifyClass == RegNtPreSetValueKey) {
		PREG_SET_VALUE_KEY_INFORMATION info = (PREG_SET_VALUE_KEY_INFORMATION)Argument2;

		UNICODE_STRING targetValueName;
		RtlInitUnicodeString(&targetValueName, L"ImagePath");

		if (info->ValueName && RtlCompareUnicodeString(info->ValueName, &targetValueName, TRUE) == 0) {
			// 【修复】：将原先的 DataLength 修改为 WDK 正确的字段名 DataSize
			if ((info->Type == REG_SZ || info->Type == REG_EXPAND_SZ) && info->Data && info->DataSize > 0) {

				UNICODE_STRING imagePath;
				imagePath.Buffer = (PWCH)info->Data;
				// 【修复】：使用 DataSize
				imagePath.Length = (USHORT)info->DataSize;
				imagePath.MaximumLength = (USHORT)info->DataSize;

				while (imagePath.Length > 0 && imagePath.Buffer[(imagePath.Length / sizeof(WCHAR)) - 1] == L'\0') {
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
					KdPrint(("[EDR] 注册表拦截生效! 成功阻止恶意驱动创建服务: %wZ\n", &imagePath));
					status = STATUS_ACCESS_DENIED;
				}
			}
		}
	}

	ExReleaseRundownProtection(&g_RundownRef);
	return status;
}

// ===========================================================================
// 进程监控回调 (保持之前完美版本不变)
// ===========================================================================
void ProcessNotifyCallbackEx(_Inout_ PEPROCESS Process, _In_ HANDLE ProcessId, _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo) {
	UNREFERENCED_PARAMETER(Process);

	if (!ExAcquireRundownProtection(&g_RundownRef)) return;

	PPROCESS_EVENT_NODE node = NULL;
	if (CreateInfo == NULL) goto Cleanup; // 忽略退出事件

	WCHAR extractedCmdLine[1024];
	RtlZeroMemory(extractedCmdLine, sizeof(extractedCmdLine));
	USHORT extractedLen = 0;
	BOOLEAN gotCmdLine = FALSE;

	// 1. 尝试直接获取
	if (CreateInfo->CommandLine != NULL && CreateInfo->CommandLine->Buffer != NULL) {
		USHORT cmdLen = CreateInfo->CommandLine->Length;
		if (cmdLen > 0 && cmdLen < sizeof(extractedCmdLine) - sizeof(WCHAR)) {
			RtlCopyMemory(extractedCmdLine, CreateInfo->CommandLine->Buffer, cmdLen);
			extractedLen = cmdLen;
			gotCmdLine = TRUE;
		}
	}

	// 2. 备用 API 获取
	if (!gotCmdLine) {
		HANDLE hProcess = NULL;
		OBJECT_ATTRIBUTES objAttr;
		CLIENT_ID clientId;
		InitializeObjectAttributes(&objAttr, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
		clientId.UniqueProcess = ProcessId;
		clientId.UniqueThread = NULL;

		if (NT_SUCCESS(ZwOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &objAttr, &clientId))) {
			ULONG returnLength = 0;
			ZwQueryInformationProcess(hProcess, (PROCESSINFOCLASS)60, NULL, 0, &returnLength);
			if (returnLength > 0) {
				PUNICODE_STRING pCmdLineUni = (PUNICODE_STRING)ExAllocatePoolWithTag(PagedPool, returnLength, 'cmPM');
				if (pCmdLineUni) {
					if (NT_SUCCESS(ZwQueryInformationProcess(hProcess, (PROCESSINFOCLASS)60, pCmdLineUni, returnLength, &returnLength))) {
						if (pCmdLineUni->Buffer && pCmdLineUni->Length > 0) {
							USHORT copyLen = pCmdLineUni->Length;
							if (copyLen > sizeof(extractedCmdLine) - sizeof(WCHAR)) copyLen = sizeof(extractedCmdLine) - sizeof(WCHAR);
							RtlCopyMemory(extractedCmdLine, pCmdLineUni->Buffer, copyLen);
							extractedLen = copyLen;
							gotCmdLine = TRUE;
						}
					}
					ExFreePoolWithTag(pCmdLineUni, 'cmPM');
				}
			}
			ZwClose(hProcess);
		}
	}

	if (!gotCmdLine) goto Cleanup;

#pragma warning(push)
#pragma warning(disable: 4996)
	node = (PPROCESS_EVENT_NODE)ExAllocatePoolWithTag(NonPagedPool, sizeof(PROCESS_EVENT_NODE), 'ndPM');
#pragma warning(pop)
	if (!node) goto Cleanup;

	RtlZeroMemory(node, sizeof(PROCESS_EVENT_NODE));
	node->EventData.ProcessId = HandleToULong(ProcessId);
	node->EventData.ParentProcessId = HandleToULong(CreateInfo->ParentProcessId);

	ULONG maxDestBytes = sizeof(node->EventData.CommandLine) - sizeof(WCHAR);
	ULONG copyBytes = (extractedLen < maxDestBytes) ? extractedLen : maxDestBytes;
	RtlCopyMemory(node->EventData.CommandLine, extractedCmdLine, copyBytes);
	node->EventData.CommandLine[copyBytes / sizeof(WCHAR)] = L'\0';

	node->IsSentToUser = FALSE;

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
			irpToComplete = g_PendingEventIrp;
			g_PendingEventIrp = NULL;
			node->IsSentToUser = TRUE;
		}
	}
	KeReleaseSpinLock(&g_QueueLock, oldIrql);

	if (irpToComplete != NULL) {
		RtlCopyMemory(irpToComplete->AssociatedIrp.SystemBuffer, &node->EventData, sizeof(PROCESS_EVENT));
		irpToComplete->IoStatus.Information = sizeof(PROCESS_EVENT);
		irpToComplete->IoStatus.Status = STATUS_SUCCESS;
		IoCompleteRequest(irpToComplete, IO_NO_INCREMENT);
	}

	// =========================================================================
	// 【重磅修复】删除了所有等待代码！
	// 进程直接无损放行，交给用户态异步裁决，保证操作系统绝对丝滑。
	// node 留在队列里，将来由清理逻辑或发送逻辑释放。
	// =========================================================================

	node = NULL; // 防止 Cleanup 误杀刚入队的节点

Cleanup:
	if (node != NULL) {
		ExFreePoolWithTag(node, 'ndPM');
	}
	ExReleaseRundownProtection(&g_RundownRef);
}

// ===========================================================================
// [重构] 驱动加载监控回调：剥离 MDL 篡改，仅做纯净的事件上报（旁路监控）
// ===========================================================================
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

	// 如果命中黑名单，我们只负责记录并通知用户态（拦截动作已交由注册表回调完成）
	if (isMalicious) {
		KdPrint(("[EDR] 发现高危驱动加载记录 (监控告警): %wZ\n", FullImageName));

#pragma warning(push)
#pragma warning(disable: 4996)
		PDRIVER_EVENT_NODE node = (PDRIVER_EVENT_NODE)ExAllocatePoolWithTag(NonPagedPool, sizeof(DRIVER_EVENT_NODE), 'drPM');
#pragma warning(pop)
		if (node) {
			RtlZeroMemory(node, sizeof(DRIVER_EVENT_NODE));

			ULONG maxBytes = sizeof(node->EventData.ImagePath) - sizeof(WCHAR);
			ULONG copyLen = FullImageName->Length;
			if (copyLen > maxBytes) copyLen = maxBytes;
			RtlCopyMemory(node->EventData.ImagePath, FullImageName->Buffer, copyLen);
			node->EventData.ImagePath[copyLen / sizeof(WCHAR)] = L'\0';

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
	}
}