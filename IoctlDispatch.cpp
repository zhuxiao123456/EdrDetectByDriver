#include "PebMonitor.h"

static VOID FillDriverRuntimeStatus(_Out_ PDRIVER_RUNTIME_STATUS runtimeStatus) {
    RtlZeroMemory(runtimeStatus, sizeof(DRIVER_RUNTIME_STATUS));

    AcquireSharedPushLock(&g_RuntimeStatusLock);
    runtimeStatus->StatusFlags = g_RuntimeStatusFlags;
    runtimeStatus->ProcessVerdictRequestCount = g_ProcessVerdictRequestCount;
    runtimeStatus->ProcessVerdictTimeoutCount = g_ProcessVerdictTimeoutCount;
    runtimeStatus->ProcessPortConnectCount = g_ProcessPortConnectCount;
    runtimeStatus->ProcessPortDisconnectCount = g_ProcessPortDisconnectCount;
    runtimeStatus->LastProcessPortConnectTime = g_LastProcessPortConnectTime;
    runtimeStatus->LastProcessPortDisconnectTime = g_LastProcessPortDisconnectTime;
    runtimeStatus->LastProcessVerdictTimeoutTime = g_LastProcessVerdictTimeoutTime;
    runtimeStatus->ProcessVerdictTimeoutMs = g_ProcessVerdictTimeoutMs;
    runtimeStatus->ProcessVerdictFailMode = g_ProcessVerdictFailMode;
    runtimeStatus->CaptureParentCommandLine = g_CaptureParentCommandLine;
    RtlStringCchCopyW(runtimeStatus->ConfigVersion, RTL_NUMBER_OF(runtimeStatus->ConfigVersion), g_ActiveConfigVersion);
    RtlStringCchCopyW(runtimeStatus->ProfileName, RTL_NUMBER_OF(runtimeStatus->ProfileName), g_ActiveProfileName);
    RtlStringCchCopyW(runtimeStatus->GeneratedAt, RTL_NUMBER_OF(runtimeStatus->GeneratedAt), g_ActiveGeneratedAt);
    ReleaseSharedPushLock(&g_RuntimeStatusLock);

    AcquireSharedPushLock(&g_BlacklistLock);
    runtimeStatus->DriverBlacklistCount = g_BlacklistCount;
    ReleaseSharedPushLock(&g_BlacklistLock);

    AcquireSharedPushLock(&g_FileRuleLock);
    runtimeStatus->FileRuleCount = g_FileRuleCount;
    ReleaseSharedPushLock(&g_FileRuleLock);

    AcquireSharedPushLock(&g_RegistryRuleLock);
    runtimeStatus->RegistryRuleCount = g_RegistryRuleCount;
    ReleaseSharedPushLock(&g_RegistryRuleLock);

    AcquireSharedPushLock(&g_RegistryAllowRuleLock);
    runtimeStatus->RegistryAllowRuleCount = g_RegistryAllowRuleCount;
    ReleaseSharedPushLock(&g_RegistryAllowRuleLock);

    KIRQL oldIrql;
    KeAcquireSpinLock(&g_DriverQueueLock, &oldIrql);
    runtimeStatus->DriverEventQueueCount = g_DriverEventCount;
    KeReleaseSpinLock(&g_DriverQueueLock, oldIrql);
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

        ULONG timeoutMs = configInfo->ProcessVerdictTimeoutMs;
        if (timeoutMs < PROCESS_VERDICT_TIMEOUT_MS_MIN ||
            timeoutMs > PROCESS_VERDICT_TIMEOUT_MS_MAX) {
            timeoutMs = PROCESS_VERDICT_TIMEOUT_MS_DEFAULT;
        }

        ULONG failMode = configInfo->ProcessVerdictFailMode;
        if (failMode != PROCESS_VERDICT_FAIL_OPEN &&
            failMode != PROCESS_VERDICT_FAIL_CLOSE) {
            failMode = PROCESS_VERDICT_FAIL_OPEN;
        }

        ULONG captureParentCmdline = configInfo->CaptureParentCommandLine;
        if (captureParentCmdline != PROCESS_PARENT_CMDLINE_CAPTURE_ENABLED) {
            captureParentCmdline = PROCESS_PARENT_CMDLINE_CAPTURE_DISABLED;
        }

        AcquireExclusivePushLock(&g_RuntimeStatusLock);
        RtlZeroMemory(g_ActiveConfigVersion, sizeof(g_ActiveConfigVersion));
        RtlZeroMemory(g_ActiveProfileName, sizeof(g_ActiveProfileName));
        RtlZeroMemory(g_ActiveGeneratedAt, sizeof(g_ActiveGeneratedAt));
        g_ProcessVerdictTimeoutMs = timeoutMs;
        g_ProcessVerdictFailMode = failMode;
        g_CaptureParentCommandLine = captureParentCmdline;
        RtlStringCchCopyW(g_ActiveConfigVersion, RTL_NUMBER_OF(g_ActiveConfigVersion), configInfo->ConfigVersion);
        RtlStringCchCopyW(g_ActiveProfileName, RTL_NUMBER_OF(g_ActiveProfileName), configInfo->ProfileName);
        RtlStringCchCopyW(g_ActiveGeneratedAt, RTL_NUMBER_OF(g_ActiveGeneratedAt), configInfo->GeneratedAt);
        ReleaseExclusivePushLock(&g_RuntimeStatusLock);

        status = STATUS_SUCCESS;
        Irp->IoStatus.Information = 0;
        break;
    }

    case IOCTL_GET_DRIVER_EVENT: {
        if (outBufLength < sizeof(DRIVER_EVENT)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        KIRQL oldIrql;
        KeAcquireSpinLock(&g_DriverQueueLock, &oldIrql);

        if (!IsListEmpty(&g_DriverEventQueue)) {
            PLIST_ENTRY entry = RemoveHeadList(&g_DriverEventQueue);
            g_DriverEventCount--;
            PDRIVER_EVENT_NODE node = CONTAINING_RECORD(entry, DRIVER_EVENT_NODE, ListEntry);
            DRIVER_EVENT tempEvent = node->EventData;
            KeReleaseSpinLock(&g_DriverQueueLock, oldIrql);

            FreeDriverEventNode(node);
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
        if (inBufLength < sizeof(BLACKLIST_RULE)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        PBLACKLIST_RULE rule = (PBLACKLIST_RULE)Irp->AssociatedIrp.SystemBuffer;

        rule->DriverName[MAX_RULE_LENGTH - 1] = L'\0';

        AcquireExclusivePushLock(&g_BlacklistLock);
        if (g_BlacklistCount < MAX_BLACKLIST_ENTRIES) {
            status = InsertDriverBlacklistRuleLocked(rule->DriverName);
            if (NT_SUCCESS(status)) {
                g_BlacklistCount++;
            }
        }
        else {
            status = STATUS_INSUFFICIENT_RESOURCES;
        }
        ReleaseExclusivePushLock(&g_BlacklistLock);
        Irp->IoStatus.Information = 0;
        break;
    }

    case IOCTL_CLEAR_DRIVER_RULES: {
        AcquireExclusivePushLock(&g_BlacklistLock);
        ClearDriverBlacklistRulesLocked();
        g_BlacklistCount = 0;
        ReleaseExclusivePushLock(&g_BlacklistLock);
        status = STATUS_SUCCESS;
        Irp->IoStatus.Information = 0;
        break;
    }

    case IOCTL_ADD_FILE_RULE: {
        if (inBufLength < sizeof(FILE_RULE)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        PFILE_RULE rule = (PFILE_RULE)Irp->AssociatedIrp.SystemBuffer;

        rule->RuleId[MAX_RULE_ID_LENGTH - 1] = L'\0';
        rule->ProcessName[MAX_RULE_LENGTH - 1] = L'\0';
        rule->TargetPath[MAX_REG_PATH_LENGTH - 1] = L'\0';
        rule->Extension[MAX_RULE_LENGTH - 1] = L'\0';

        AcquireExclusivePushLock(&g_FileRuleLock);
        if (g_FileRuleCount < MAX_FILE_RULE_COUNT) {
            RtlCopyMemory(&g_FileRules[g_FileRuleCount], rule, sizeof(FILE_RULE));
            g_FileRuleCount++;
            status = STATUS_SUCCESS;
        }
        else {
            status = STATUS_INSUFFICIENT_RESOURCES;
        }
        ReleaseExclusivePushLock(&g_FileRuleLock);
        Irp->IoStatus.Information = 0;
        break;
    }

    case IOCTL_CLEAR_FILE_RULES: {
        AcquireExclusivePushLock(&g_FileRuleLock);
        g_FileRuleCount = 0;
        RtlZeroMemory(g_FileRules, sizeof(g_FileRules));
        ReleaseExclusivePushLock(&g_FileRuleLock);
        status = STATUS_SUCCESS;
        Irp->IoStatus.Information = 0;
        break;
    }

    case IOCTL_ADD_REGISTRY_RULE: {
        if (inBufLength < sizeof(REGISTRY_RULE)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        PREGISTRY_RULE rule = (PREGISTRY_RULE)Irp->AssociatedIrp.SystemBuffer;

        rule->RuleId[MAX_RULE_ID_LENGTH - 1] = L'\0';
        rule->ProcessName[MAX_RULE_LENGTH - 1] = L'\0';
        rule->KeyPath[MAX_REG_PATH_LENGTH - 1] = L'\0';
        rule->InfoClass[MAX_RULE_LENGTH - 1] = L'\0';
        rule->ValueName[MAX_RULE_LENGTH - 1] = L'\0';
        rule->ValueData[MAX_RULE_LENGTH - 1] = L'\0';

        AcquireExclusivePushLock(&g_RegistryRuleLock);
        if (g_RegistryRuleCount < MAX_REGISTRY_RULE_COUNT) {
            RtlCopyMemory(&g_RegistryRules[g_RegistryRuleCount], rule, sizeof(REGISTRY_RULE));
            g_RegistryRuleCount++;
            status = STATUS_SUCCESS;
        }
        else {
            status = STATUS_INSUFFICIENT_RESOURCES;
        }
        ReleaseExclusivePushLock(&g_RegistryRuleLock);
        Irp->IoStatus.Information = 0;
        break;
    }

    case IOCTL_CLEAR_REGISTRY_RULES: {
        AcquireExclusivePushLock(&g_RegistryRuleLock);
        g_RegistryRuleCount = 0;
        RtlZeroMemory(g_RegistryRules, sizeof(g_RegistryRules));
        ReleaseExclusivePushLock(&g_RegistryRuleLock);
        status = STATUS_SUCCESS;
        Irp->IoStatus.Information = 0;
        break;
    }

    case IOCTL_ADD_REGISTRY_ALLOW_RULE: {
        if (inBufLength < sizeof(REGISTRY_RULE)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        PREGISTRY_RULE rule = (PREGISTRY_RULE)Irp->AssociatedIrp.SystemBuffer;

        rule->RuleId[MAX_RULE_ID_LENGTH - 1] = L'\0';
        rule->ProcessName[MAX_RULE_LENGTH - 1] = L'\0';
        rule->KeyPath[MAX_REG_PATH_LENGTH - 1] = L'\0';
        rule->InfoClass[MAX_RULE_LENGTH - 1] = L'\0';
        rule->ValueName[MAX_RULE_LENGTH - 1] = L'\0';
        rule->ValueData[MAX_RULE_LENGTH - 1] = L'\0';

        AcquireExclusivePushLock(&g_RegistryAllowRuleLock);
        if (g_RegistryAllowRuleCount < MAX_REGISTRY_RULE_COUNT) {
            RtlCopyMemory(&g_RegistryAllowRules[g_RegistryAllowRuleCount], rule, sizeof(REGISTRY_RULE));
            g_RegistryAllowRuleCount++;
            status = STATUS_SUCCESS;
        }
        else {
            status = STATUS_INSUFFICIENT_RESOURCES;
        }
        ReleaseExclusivePushLock(&g_RegistryAllowRuleLock);
        Irp->IoStatus.Information = 0;
        break;
    }

    case IOCTL_CLEAR_REGISTRY_ALLOW_RULES: {
        AcquireExclusivePushLock(&g_RegistryAllowRuleLock);
        g_RegistryAllowRuleCount = 0;
        RtlZeroMemory(g_RegistryAllowRules, sizeof(g_RegistryAllowRules));
        ReleaseExclusivePushLock(&g_RegistryAllowRuleLock);
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
