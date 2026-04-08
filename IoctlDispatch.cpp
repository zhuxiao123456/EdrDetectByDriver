#include "PebMonitor.h"

static LONGLONG ProcessEventTimeoutTicks() {
    return (LONGLONG)PROCESS_EVENT_TIMEOUT_SECONDS * 10 * 1000 * 1000;
}

static VOID FillDriverRuntimeStatus(_Out_ PDRIVER_RUNTIME_STATUS runtimeStatus) {
    RtlZeroMemory(runtimeStatus, sizeof(DRIVER_RUNTIME_STATUS));

    KIRQL oldIrql;

    KeAcquireSpinLock(&g_RuntimeStatusLock, &oldIrql);
    runtimeStatus->StatusFlags = g_RuntimeStatusFlags;
    RtlStringCchCopyW(runtimeStatus->ConfigVersion, RTL_NUMBER_OF(runtimeStatus->ConfigVersion), g_ActiveConfigVersion);
    RtlStringCchCopyW(runtimeStatus->ProfileName, RTL_NUMBER_OF(runtimeStatus->ProfileName), g_ActiveProfileName);
    RtlStringCchCopyW(runtimeStatus->GeneratedAt, RTL_NUMBER_OF(runtimeStatus->GeneratedAt), g_ActiveGeneratedAt);
    KeReleaseSpinLock(&g_RuntimeStatusLock, oldIrql);

    KeAcquireSpinLock(&g_BlacklistLock, &oldIrql);
    runtimeStatus->DriverBlacklistCount = g_BlacklistCount;
    KeReleaseSpinLock(&g_BlacklistLock, oldIrql);

    KeAcquireSpinLock(&g_FileRuleLock, &oldIrql);
    runtimeStatus->FileRuleCount = g_FileRuleCount;
    KeReleaseSpinLock(&g_FileRuleLock, oldIrql);

    KeAcquireSpinLock(&g_RegistryRuleLock, &oldIrql);
    runtimeStatus->RegistryRuleCount = g_RegistryRuleCount;
    KeReleaseSpinLock(&g_RegistryRuleLock, oldIrql);

    KeAcquireSpinLock(&g_RegistryAllowRuleLock, &oldIrql);
    runtimeStatus->RegistryAllowRuleCount = g_RegistryAllowRuleCount;
    KeReleaseSpinLock(&g_RegistryAllowRuleLock, oldIrql);

    KeAcquireSpinLock(&g_QueueLock, &oldIrql);
    runtimeStatus->ProcessEventQueueCount = g_EventCount;
    KeReleaseSpinLock(&g_QueueLock, oldIrql);

    KeAcquireSpinLock(&g_DriverQueueLock, &oldIrql);
    runtimeStatus->DriverEventQueueCount = g_DriverEventCount;
    KeReleaseSpinLock(&g_DriverQueueLock, oldIrql);
}

static VOID PurgeExpiredProcessEventsLocked(_In_ LARGE_INTEGER now) {
    PLIST_ENTRY entry = g_EventQueue.Flink;
    while (entry != &g_EventQueue) {
        PLIST_ENTRY nextEntry = entry->Flink;
        PPROCESS_EVENT_NODE node = CONTAINING_RECORD(entry, PROCESS_EVENT_NODE, ListEntry);
        if (node->IsSentToUser &&
            node->SentTime.QuadPart != 0 &&
            now.QuadPart - node->SentTime.QuadPart >= ProcessEventTimeoutTicks()) {
            RemoveEntryList(entry);
            g_EventCount--;
            ExFreePoolWithTag(node, 'ndPM');
        }
        entry = nextEntry;
    }
}

VOID PurgeExpiredProcessEvents() {
    LARGE_INTEGER now;
    KeQuerySystemTime(&now);

    KIRQL oldIrql;
    KeAcquireSpinLock(&g_QueueLock, &oldIrql);
    PurgeExpiredProcessEventsLocked(now);
    KeReleaseSpinLock(&g_QueueLock, oldIrql);
}

VOID CleanupProcessEventsForFileObject(_In_opt_ PFILE_OBJECT FileObject) {
    if (FileObject == NULL) {
        return;
    }

    KIRQL oldIrql;
    KeAcquireSpinLock(&g_QueueLock, &oldIrql);

    PLIST_ENTRY entry = g_EventQueue.Flink;
    while (entry != &g_EventQueue) {
        PLIST_ENTRY nextEntry = entry->Flink;
        PPROCESS_EVENT_NODE node = CONTAINING_RECORD(entry, PROCESS_EVENT_NODE, ListEntry);
        if (node->IsSentToUser && node->OwnerFileObject == FileObject) {
            RemoveEntryList(entry);
            g_EventCount--;
            ExFreePoolWithTag(node, 'ndPM');
        }
        entry = nextEntry;
    }

    KeReleaseSpinLock(&g_QueueLock, oldIrql);
}

VOID MarkProcessEventDelivered(_Inout_ PPROCESS_EVENT_NODE Node, _In_opt_ PFILE_OBJECT FileObject) {
    Node->IsSentToUser = TRUE;
    Node->OwnerFileObject = FileObject;
    KeQuerySystemTime(&Node->SentTime);
}

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

    PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
    if (irpSp->MajorFunction == IRP_MJ_CLOSE) {
        CleanupProcessEventsForFileObject(irpSp->FileObject);
    }

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
    case IOCTL_QUERY_DRIVER_STATUS: {
        if (outBufLength < sizeof(DRIVER_RUNTIME_STATUS)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        PDRIVER_RUNTIME_STATUS runtimeStatus =
            (PDRIVER_RUNTIME_STATUS)Irp->AssociatedIrp.SystemBuffer;
        FillDriverRuntimeStatus(runtimeStatus);
        Irp->IoStatus.Information = sizeof(DRIVER_RUNTIME_STATUS);
        status = STATUS_SUCCESS;
        break;
    }

    case IOCTL_SET_ACTIVE_CONFIG_INFO: {
        if (inBufLength < sizeof(DRIVER_CONFIG_INFO)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        PDRIVER_CONFIG_INFO configInfo =
            (PDRIVER_CONFIG_INFO)Irp->AssociatedIrp.SystemBuffer;
        configInfo->ConfigVersion[MAX_RULE_LENGTH - 1] = L'\0';
        configInfo->ProfileName[MAX_RULE_LENGTH - 1] = L'\0';
        configInfo->GeneratedAt[MAX_RULE_LENGTH - 1] = L'\0';

        KIRQL oldIrql;
        KeAcquireSpinLock(&g_RuntimeStatusLock, &oldIrql);
        RtlZeroMemory(g_ActiveConfigVersion, sizeof(g_ActiveConfigVersion));
        RtlZeroMemory(g_ActiveProfileName, sizeof(g_ActiveProfileName));
        RtlZeroMemory(g_ActiveGeneratedAt, sizeof(g_ActiveGeneratedAt));
        RtlStringCchCopyW(g_ActiveConfigVersion, RTL_NUMBER_OF(g_ActiveConfigVersion), configInfo->ConfigVersion);
        RtlStringCchCopyW(g_ActiveProfileName, RTL_NUMBER_OF(g_ActiveProfileName), configInfo->ProfileName);
        RtlStringCchCopyW(g_ActiveGeneratedAt, RTL_NUMBER_OF(g_ActiveGeneratedAt), configInfo->GeneratedAt);
        KeReleaseSpinLock(&g_RuntimeStatusLock, oldIrql);

        status = STATUS_SUCCESS;
        Irp->IoStatus.Information = 0;
        break;
    }

    case IOCTL_GET_PROCESS_EVENT: {
        if (outBufLength < sizeof(PROCESS_EVENT)) { status = STATUS_BUFFER_TOO_SMALL; break; }

        PurgeExpiredProcessEvents();

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
            MarkProcessEventDelivered(pendingNode, irpSp->FileObject);
            PROCESS_EVENT tempEvent = pendingNode->EventData;
            KeReleaseSpinLock(&g_QueueLock, oldIrql);

            RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer, &tempEvent, sizeof(PROCESS_EVENT));
            Irp->IoStatus.Information = sizeof(PROCESS_EVENT);
            status = STATUS_SUCCESS;
        }
        else {
            KeReleaseSpinLock(&g_QueueLock, oldIrql);

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

        if (verdict->BlockProcess) {
            HANDLE hProcess = NULL;
            OBJECT_ATTRIBUTES objAttr;
            CLIENT_ID clientId;

            InitializeObjectAttributes(&objAttr, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
            clientId.UniqueProcess = ULongToHandle(verdict->ProcessId);
            clientId.UniqueThread = NULL;

            if (NT_SUCCESS(ZwOpenProcess(&hProcess, PROCESS_TERMINATE, &objAttr, &clientId))) {
                ZwTerminateProcess(hProcess, STATUS_ACCESS_DENIED);
                ZwClose(hProcess);
                KdPrint(("[EDR] 异步防御生效! 成功斩首恶意进程 PID: %d\n", verdict->ProcessId));
            }
        }

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

    case IOCTL_ADD_FILE_RULE: {
        if (inBufLength < sizeof(FILE_RULE)) { status = STATUS_BUFFER_TOO_SMALL; break; }
        PFILE_RULE rule = (PFILE_RULE)Irp->AssociatedIrp.SystemBuffer;

        rule->RuleId[MAX_RULE_ID_LENGTH - 1] = L'\0';
        rule->ProcessName[MAX_RULE_LENGTH - 1] = L'\0';
        rule->TargetPath[MAX_REG_PATH_LENGTH - 1] = L'\0';
        rule->Extension[MAX_RULE_LENGTH - 1] = L'\0';

        KIRQL oldIrql;
        KeAcquireSpinLock(&g_FileRuleLock, &oldIrql);

        if (g_FileRuleCount < MAX_FILE_RULE_COUNT) {
            RtlCopyMemory(&g_FileRules[g_FileRuleCount], rule, sizeof(FILE_RULE));
            g_FileRuleCount++;
            status = STATUS_SUCCESS;
        }
        else {
            status = STATUS_INSUFFICIENT_RESOURCES;
        }

        KeReleaseSpinLock(&g_FileRuleLock, oldIrql);
        Irp->IoStatus.Information = 0;
        break;
    }

    case IOCTL_CLEAR_FILE_RULES: {
        KIRQL oldIrql;
        KeAcquireSpinLock(&g_FileRuleLock, &oldIrql);
        g_FileRuleCount = 0;
        RtlZeroMemory(g_FileRules, sizeof(g_FileRules));
        KeReleaseSpinLock(&g_FileRuleLock, oldIrql);
        status = STATUS_SUCCESS;
        Irp->IoStatus.Information = 0;
        break;
    }

    case IOCTL_ADD_REGISTRY_RULE: {
        if (inBufLength < sizeof(REGISTRY_RULE)) { status = STATUS_BUFFER_TOO_SMALL; break; }
        PREGISTRY_RULE rule = (PREGISTRY_RULE)Irp->AssociatedIrp.SystemBuffer;

        rule->RuleId[MAX_RULE_ID_LENGTH - 1] = L'\0';
        rule->ProcessName[MAX_RULE_LENGTH - 1] = L'\0';
        rule->KeyPath[MAX_REG_PATH_LENGTH - 1] = L'\0';
        rule->InfoClass[MAX_RULE_LENGTH - 1] = L'\0';
        rule->ValueName[MAX_RULE_LENGTH - 1] = L'\0';
        rule->ValueData[MAX_RULE_LENGTH - 1] = L'\0';

        KIRQL oldIrql;
        KeAcquireSpinLock(&g_RegistryRuleLock, &oldIrql);

        if (g_RegistryRuleCount < MAX_REGISTRY_RULE_COUNT) {
            RtlCopyMemory(&g_RegistryRules[g_RegistryRuleCount], rule, sizeof(REGISTRY_RULE));
            g_RegistryRuleCount++;
            status = STATUS_SUCCESS;
        }
        else {
            status = STATUS_INSUFFICIENT_RESOURCES;
        }

        KeReleaseSpinLock(&g_RegistryRuleLock, oldIrql);
        Irp->IoStatus.Information = 0;
        break;
    }

    case IOCTL_CLEAR_REGISTRY_RULES: {
        KIRQL oldIrql;
        KeAcquireSpinLock(&g_RegistryRuleLock, &oldIrql);
        g_RegistryRuleCount = 0;
        RtlZeroMemory(g_RegistryRules, sizeof(g_RegistryRules));
        KeReleaseSpinLock(&g_RegistryRuleLock, oldIrql);
        status = STATUS_SUCCESS;
        Irp->IoStatus.Information = 0;
        break;
    }

    case IOCTL_ADD_REGISTRY_ALLOW_RULE: {
        if (inBufLength < sizeof(REGISTRY_RULE)) { status = STATUS_BUFFER_TOO_SMALL; break; }
        PREGISTRY_RULE rule = (PREGISTRY_RULE)Irp->AssociatedIrp.SystemBuffer;

        rule->RuleId[MAX_RULE_ID_LENGTH - 1] = L'\0';
        rule->ProcessName[MAX_RULE_LENGTH - 1] = L'\0';
        rule->KeyPath[MAX_REG_PATH_LENGTH - 1] = L'\0';
        rule->InfoClass[MAX_RULE_LENGTH - 1] = L'\0';
        rule->ValueName[MAX_RULE_LENGTH - 1] = L'\0';
        rule->ValueData[MAX_RULE_LENGTH - 1] = L'\0';

        KIRQL oldIrql;
        KeAcquireSpinLock(&g_RegistryAllowRuleLock, &oldIrql);

        if (g_RegistryAllowRuleCount < MAX_REGISTRY_RULE_COUNT) {
            RtlCopyMemory(&g_RegistryAllowRules[g_RegistryAllowRuleCount], rule, sizeof(REGISTRY_RULE));
            g_RegistryAllowRuleCount++;
            status = STATUS_SUCCESS;
        }
        else {
            status = STATUS_INSUFFICIENT_RESOURCES;
        }

        KeReleaseSpinLock(&g_RegistryAllowRuleLock, oldIrql);
        Irp->IoStatus.Information = 0;
        break;
    }

    case IOCTL_CLEAR_REGISTRY_ALLOW_RULES: {
        KIRQL oldIrql;
        KeAcquireSpinLock(&g_RegistryAllowRuleLock, &oldIrql);
        g_RegistryAllowRuleCount = 0;
        RtlZeroMemory(g_RegistryAllowRules, sizeof(g_RegistryAllowRules));
        KeReleaseSpinLock(&g_RegistryAllowRuleLock, oldIrql);
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
