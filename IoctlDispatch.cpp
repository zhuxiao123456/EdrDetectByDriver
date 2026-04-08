#include "PebMonitor.h"

VOID CancelPendingDriverIrp(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
	UNREFERENCED_PARAMETER(DeviceObject);
	IoReleaseCancelSpinLock(Irp->CancelIrql);
	PIRP irpToCancel = (PIRP)InterlockedCompareExchangePointer((PVOID*)&g_PendingDriverIrp, NULL, Irp);
	if (irpToCancel != NULL) {
		irpToCancel->IoStatus.Status = STATUS_CANCELLED;
		irpToCancel->IoStatus.Information = 0;
		IoCompleteRequest(irpToCancel, IO_NO_INCREMENT);
	}
}

VOID CancelPendingEventIrp(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
	UNREFERENCED_PARAMETER(DeviceObject);
	IoReleaseCancelSpinLock(Irp->CancelIrql);
	PIRP irpToCancel = (PIRP)InterlockedCompareExchangePointer((PVOID*)&g_PendingEventIrp, NULL, Irp);
	if (irpToCancel != NULL) {
		irpToCancel->IoStatus.Status = STATUS_CANCELLED;
		irpToCancel->IoStatus.Information = 0;
		IoCompleteRequest(irpToCancel, IO_NO_INCREMENT);
	}
}

NTSTATUS DispatchCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
	UNREFERENCED_PARAMETER(DeviceObject);
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS DispatchDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
	UNREFERENCED_PARAMETER(DeviceObject);
	NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
	PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
	ULONG ioControlCode = irpSp->Parameters.DeviceIoControl.IoControlCode;
	ULONG outBufLength = irpSp->Parameters.DeviceIoControl.OutputBufferLength;
	ULONG inBufLength = irpSp->Parameters.DeviceIoControl.InputBufferLength;

	switch (ioControlCode) {
	case IOCTL_GET_PROCESS_EVENT: {
		if (outBufLength < sizeof(PROCESS_EVENT)) { status = STATUS_BUFFER_TOO_SMALL; break; }
		KIRQL oldIrql;
		KeAcquireSpinLock(&g_QueueLock, &oldIrql);

		PLIST_ENTRY entry = g_EventQueue.Flink;
		PPROCESS_EVENT_NODE pendingNode = NULL;
		while (entry != &g_EventQueue) {
			PPROCESS_EVENT_NODE node = CONTAINING_RECORD(entry, PROCESS_EVENT_NODE, ListEntry);
			if (!node->IsSentToUser) { pendingNode = node; break; }
			entry = entry->Flink;
		}

		if (pendingNode) {
			pendingNode->IsSentToUser = TRUE;
			PROCESS_EVENT tempEvent = pendingNode->EventData; // 锁内赋值
			KeReleaseSpinLock(&g_QueueLock, oldIrql);

			RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer, &tempEvent, sizeof(PROCESS_EVENT)); // 锁外拷贝
			Irp->IoStatus.Information = sizeof(PROCESS_EVENT);
			status = STATUS_SUCCESS;
		}
		else {
			KeReleaseSpinLock(&g_QueueLock, oldIrql);

			// 原子挂起 IRP
			IoMarkIrpPending(Irp);
			PIRP oldIrp = (PIRP)InterlockedExchangePointer((PVOID*)&g_PendingEventIrp, Irp);

			if (oldIrp != NULL) {
				if (IoSetCancelRoutine(oldIrp, NULL) != NULL) {
					oldIrp->IoStatus.Status = STATUS_CANCELLED;
					oldIrp->IoStatus.Information = 0;
					IoCompleteRequest(oldIrp, IO_NO_INCREMENT);
				}
			}

			IoSetCancelRoutine(Irp, CancelPendingEventIrp);
			if (Irp->Cancel) {
				if (IoSetCancelRoutine(Irp, NULL) != NULL) {
					PIRP irpToCancel = (PIRP)InterlockedCompareExchangePointer((PVOID*)&g_PendingEventIrp, NULL, Irp);
					if (irpToCancel != NULL) {
						irpToCancel->IoStatus.Status = STATUS_CANCELLED;
						irpToCancel->IoStatus.Information = 0;
						IoCompleteRequest(irpToCancel, IO_NO_INCREMENT);
					}
				}
			}
			return STATUS_PENDING;
		}
		break;
	}

	case IOCTL_SEND_VERDICT: {
		if (inBufLength < sizeof(PROCESS_VERDICT)) { status = STATUS_BUFFER_TOO_SMALL; break; }
		PPROCESS_VERDICT verdict = (PPROCESS_VERDICT)Irp->AssociatedIrp.SystemBuffer;

		// =========================================================
		// 【修复】异步斩首逻辑：无需遍历队列找事件，直接精准打击 PID！
		// =========================================================
		if (verdict->BlockProcess) {
			HANDLE hProcess = NULL;
			OBJECT_ATTRIBUTES objAttr;
			CLIENT_ID clientId;

			InitializeObjectAttributes(&objAttr, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
			clientId.UniqueProcess = ULongToHandle(verdict->ProcessId);
			clientId.UniqueThread = NULL;

			// 请求 PROCESS_TERMINATE 权限打开目标进程
			if (NT_SUCCESS(ZwOpenProcess(&hProcess, PROCESS_TERMINATE, &objAttr, &clientId))) {
				// 执行内核级强杀，退出码设为 STATUS_ACCESS_DENIED (0xC0000022)
				ZwTerminateProcess(hProcess, STATUS_ACCESS_DENIED);
				ZwClose(hProcess);
				KdPrint(("[EDR] 异步防御生效! 成功斩首恶意进程 PID: %d\n", verdict->ProcessId));
			}
		}

		// 注意：这里的节点清理交由 Get 事件或后续定时清理完成。
		// 为简单起见，既然用户态已经回传了 verdict，说明用户态拿到了数据，
		// 我们可以在这里顺手把该进程在队列里的节点释放掉，防止内存泄漏。
		KIRQL oldIrql;
		KeAcquireSpinLock(&g_QueueLock, &oldIrql);
		PLIST_ENTRY entry = g_EventQueue.Flink;
		while (entry != &g_EventQueue) {
			PPROCESS_EVENT_NODE node = CONTAINING_RECORD(entry, PROCESS_EVENT_NODE, ListEntry);
			if (node->EventData.ProcessId == verdict->ProcessId && node->IsSentToUser) {
				RemoveEntryList(entry);
				g_EventCount--;
				ExFreePoolWithTag(node, 'ndPM');
				break;
			}
			entry = entry->Flink;
		}
		KeReleaseSpinLock(&g_QueueLock, oldIrql);

		status = STATUS_SUCCESS;
		break;
	}

	case IOCTL_GET_DRIVER_EVENT: {
		if (outBufLength < sizeof(DRIVER_EVENT)) { status = STATUS_BUFFER_TOO_SMALL; break; }
		KIRQL oldIrql;
		KeAcquireSpinLock(&g_DriverQueueLock, &oldIrql);

		if (!IsListEmpty(&g_DriverEventQueue)) {
			PLIST_ENTRY entry = RemoveHeadList(&g_DriverEventQueue);
			g_DriverEventCount--;
			PDRIVER_EVENT_NODE node = CONTAINING_RECORD(entry, DRIVER_EVENT_NODE, ListEntry);
			DRIVER_EVENT tempEvent = node->EventData;
			KeReleaseSpinLock(&g_DriverQueueLock, oldIrql);

			ExFreePoolWithTag(node, 'drPM');
			RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer, &tempEvent, sizeof(DRIVER_EVENT));
			Irp->IoStatus.Information = sizeof(DRIVER_EVENT);
			status = STATUS_SUCCESS;
		}
		else {
			KeReleaseSpinLock(&g_DriverQueueLock, oldIrql);

			IoMarkIrpPending(Irp);
			PIRP oldIrp = (PIRP)InterlockedExchangePointer((PVOID*)&g_PendingDriverIrp, Irp);

			if (oldIrp != NULL) {
				if (IoSetCancelRoutine(oldIrp, NULL) != NULL) {
					oldIrp->IoStatus.Status = STATUS_CANCELLED;
					oldIrp->IoStatus.Information = 0;
					IoCompleteRequest(oldIrp, IO_NO_INCREMENT);
				}
			}

			IoSetCancelRoutine(Irp, CancelPendingDriverIrp);
			if (Irp->Cancel) {
				if (IoSetCancelRoutine(Irp, NULL) != NULL) {
					PIRP irpToCancel = (PIRP)InterlockedCompareExchangePointer((PVOID*)&g_PendingDriverIrp, NULL, Irp);
					if (irpToCancel != NULL) {
						irpToCancel->IoStatus.Status = STATUS_CANCELLED;
						irpToCancel->IoStatus.Information = 0;
						IoCompleteRequest(irpToCancel, IO_NO_INCREMENT);
					}
				}
			}
			return STATUS_PENDING;
		}
		break;
	}

	case IOCTL_ADD_DRIVER_RULE: {
		if (inBufLength < sizeof(BLACKLIST_RULE)) { status = STATUS_BUFFER_TOO_SMALL; break; }
		PBLACKLIST_RULE rule = (PBLACKLIST_RULE)Irp->AssociatedIrp.SystemBuffer;

		rule->DriverName[MAX_RULE_LENGTH - 1] = L'\0';

		KIRQL oldIrql;
		KeAcquireSpinLock(&g_BlacklistLock, &oldIrql);

		if (g_BlacklistCount < MAX_BLACKLIST_ENTRIES) {
			size_t lenBytes = (wcslen(rule->DriverName) + 1) * sizeof(WCHAR);
			if (lenBytes > sizeof(g_DriverBlacklist[g_BlacklistCount])) {
				lenBytes = sizeof(g_DriverBlacklist[g_BlacklistCount]);
			}
			RtlCopyMemory(g_DriverBlacklist[g_BlacklistCount], rule->DriverName, lenBytes);
			g_DriverBlacklist[g_BlacklistCount][MAX_RULE_LENGTH - 1] = L'\0';
			g_BlacklistCount++;
			status = STATUS_SUCCESS;
		}
		else { status = STATUS_INSUFFICIENT_RESOURCES; }

		KeReleaseSpinLock(&g_BlacklistLock, oldIrql);
		Irp->IoStatus.Information = 0;
		break;
	}

	case IOCTL_CLEAR_DRIVER_RULES: {
		KIRQL oldIrql;
		KeAcquireSpinLock(&g_BlacklistLock, &oldIrql);
		g_BlacklistCount = 0;
		RtlZeroMemory(g_DriverBlacklist, sizeof(g_DriverBlacklist));
		KeReleaseSpinLock(&g_BlacklistLock, oldIrql);
		status = STATUS_SUCCESS;
		Irp->IoStatus.Information = 0;
		break;
	}
	}

	if (status != STATUS_PENDING) {
		Irp->IoStatus.Status = status;
		IoCompleteRequest(Irp, IO_NO_INCREMENT);
	}
	return status;
}