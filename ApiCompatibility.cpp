#include "ApiCompatibility.h"

#include "OsVersionHelper.h"

PEBMONITOR_API_SUPPORT g_ApiSupport = {};
PFN_CM_CALLBACK_GET_KEY_OBJECT_ID_EX g_pCmCallbackGetKeyObjectIDEx = NULL;
PFN_CM_CALLBACK_RELEASE_KEY_OBJECT_ID_EX g_pCmCallbackReleaseKeyObjectIDEx = NULL;
PFN_PS_GET_PROCESS_PEB g_pPsGetProcessPeb = NULL;
PFN_SE_LOCATE_PROCESS_IMAGE_NAME g_pSeLocateProcessImageName = NULL;

static PVOID ResolveKernelRoutine(_In_z_ PCWSTR routineName) {
    UNICODE_STRING routine = {};
    RtlInitUnicodeString(&routine, routineName);
    return MmGetSystemRoutineAddress(&routine);
}

VOID InitializeApiCompatibility() {
    RtlZeroMemory(&g_ApiSupport, sizeof(g_ApiSupport));

    OS_VERSION_INFO versionInfo = {};
    if (QueryOsVersionInfo(&versionInfo)) {
        g_ApiSupport.OsMajorVersion = versionInfo.MajorVersion;
        g_ApiSupport.OsMinorVersion = versionInfo.MinorVersion;
        g_ApiSupport.OsBuildNumber = versionInfo.BuildNumber;
    }

    g_pCmCallbackGetKeyObjectIDEx =
        (PFN_CM_CALLBACK_GET_KEY_OBJECT_ID_EX)ResolveKernelRoutine(L"CmCallbackGetKeyObjectIDEx");
    g_pCmCallbackReleaseKeyObjectIDEx =
        (PFN_CM_CALLBACK_RELEASE_KEY_OBJECT_ID_EX)ResolveKernelRoutine(L"CmCallbackReleaseKeyObjectIDEx");
    g_pPsGetProcessPeb =
        (PFN_PS_GET_PROCESS_PEB)ResolveKernelRoutine(L"PsGetProcessPeb");
    g_pSeLocateProcessImageName =
        (PFN_SE_LOCATE_PROCESS_IMAGE_NAME)ResolveKernelRoutine(L"SeLocateProcessImageName");

    g_ApiSupport.HasCmCallbackGetKeyObjectIDEx =
        (g_pCmCallbackGetKeyObjectIDEx != NULL && g_pCmCallbackReleaseKeyObjectIDEx != NULL);
    g_ApiSupport.HasCmCallbackReleaseKeyObjectIDEx = (g_pCmCallbackReleaseKeyObjectIDEx != NULL);
    g_ApiSupport.HasPsGetProcessPeb = (g_pPsGetProcessPeb != NULL);
    g_ApiSupport.HasSeLocateProcessImageName = (g_pSeLocateProcessImageName != NULL);

    KdPrint((
        "[PebMonitor] INFO: ApiCompatibility initialized. OS=%lu.%lu build=%lu CmCallbackGetKeyObjectIDEx=%s PsGetProcessPeb=%s SeLocateProcessImageName=%s\n",
        g_ApiSupport.OsMajorVersion,
        g_ApiSupport.OsMinorVersion,
        g_ApiSupport.OsBuildNumber,
        g_ApiSupport.HasCmCallbackGetKeyObjectIDEx ? "enabled" : "fallback",
        g_ApiSupport.HasPsGetProcessPeb ? "enabled" : "disabled",
        g_ApiSupport.HasSeLocateProcessImageName ? "enabled" : "disabled"));
}

NTSTATUS QueryRegistryObjectNameCompat(
    _In_ PLARGE_INTEGER cookie,
    _In_ PVOID object,
    _Outptr_result_maybenull_ PCUNICODE_STRING* objectName,
    _Out_opt_ PBOOLEAN releaseRequired) {
    if (cookie == NULL || object == NULL || objectName == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *objectName = NULL;
    if (releaseRequired != NULL) {
        *releaseRequired = FALSE;
    }

    if (g_ApiSupport.HasCmCallbackGetKeyObjectIDEx && g_pCmCallbackGetKeyObjectIDEx != NULL) {
        NTSTATUS status = g_pCmCallbackGetKeyObjectIDEx(cookie, object, NULL, objectName, 0);
        if (NT_SUCCESS(status) && releaseRequired != NULL) {
            *releaseRequired = TRUE;
        }
        return status;
    }

    return CmCallbackGetKeyObjectID(cookie, object, NULL, objectName);
}

VOID ReleaseRegistryObjectNameCompat(
    _In_opt_ PCUNICODE_STRING objectName,
    _In_ BOOLEAN releaseRequired) {
    if (!releaseRequired || objectName == NULL) {
        return;
    }

    if (g_pCmCallbackReleaseKeyObjectIDEx != NULL) {
        g_pCmCallbackReleaseKeyObjectIDEx(objectName);
    }
}

PVOID QueryProcessPebCompat(_In_ PEPROCESS process) {
    if (process == NULL || g_pPsGetProcessPeb == NULL) {
        return NULL;
    }

    return g_pPsGetProcessPeb(process);
}

NTSTATUS QueryProcessImageNameCompat(
    _In_ PEPROCESS process,
    _Outptr_ PUNICODE_STRING* imagePath) {
    if (process == NULL || imagePath == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *imagePath = NULL;
    if (g_pSeLocateProcessImageName == NULL) {
        return STATUS_NOT_SUPPORTED;
    }

    return g_pSeLocateProcessImageName(process, imagePath);
}
