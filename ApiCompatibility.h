#pragma once

#include <fltKernel.h>

typedef NTSTATUS(NTAPI* PFN_CM_CALLBACK_GET_KEY_OBJECT_ID_EX)(
    _In_ PLARGE_INTEGER Cookie,
    _In_ PVOID Object,
    _Out_opt_ PULONG_PTR ObjectId,
    _Outptr_result_maybenull_ PCUNICODE_STRING* ObjectName,
    _In_ ULONG Flags);

typedef VOID(NTAPI* PFN_CM_CALLBACK_RELEASE_KEY_OBJECT_ID_EX)(
    _In_ PCUNICODE_STRING ObjectName);

typedef PVOID(NTAPI* PFN_PS_GET_PROCESS_PEB)(
    _In_ PEPROCESS Process);

typedef NTSTATUS(NTAPI* PFN_SE_LOCATE_PROCESS_IMAGE_NAME)(
    _In_ PEPROCESS Process,
    _Outptr_ PUNICODE_STRING* ProcessImageName);

typedef VOID(NTAPI* PFN_EX_INITIALIZE_DRIVER_RUNTIME)(
    _In_ ULONG Flags);

typedef struct _PEBMONITOR_API_SUPPORT {
    ULONG OsMajorVersion;
    ULONG OsMinorVersion;
    ULONG OsBuildNumber;
    BOOLEAN HasExInitializeDriverRuntime;
    BOOLEAN HasCmCallbackGetKeyObjectIDEx;
    BOOLEAN HasCmCallbackReleaseKeyObjectIDEx;
    BOOLEAN HasPsGetProcessPeb;
    BOOLEAN HasSeLocateProcessImageName;
} PEBMONITOR_API_SUPPORT, *PPEBMONITOR_API_SUPPORT;

extern PEBMONITOR_API_SUPPORT g_ApiSupport;
extern PFN_EX_INITIALIZE_DRIVER_RUNTIME g_pExInitializeDriverRuntime;
extern PFN_CM_CALLBACK_GET_KEY_OBJECT_ID_EX g_pCmCallbackGetKeyObjectIDEx;
extern PFN_CM_CALLBACK_RELEASE_KEY_OBJECT_ID_EX g_pCmCallbackReleaseKeyObjectIDEx;
extern PFN_PS_GET_PROCESS_PEB g_pPsGetProcessPeb;
extern PFN_SE_LOCATE_PROCESS_IMAGE_NAME g_pSeLocateProcessImageName;

VOID InitializeApiCompatibility();
VOID TryInitializeDriverRuntimeCompat();
NTSTATUS QueryRegistryObjectNameCompat(
    _In_ PLARGE_INTEGER cookie,
    _In_ PVOID object,
    _Outptr_result_maybenull_ PCUNICODE_STRING* objectName,
    _Out_opt_ PBOOLEAN releaseRequired);
VOID ReleaseRegistryObjectNameCompat(
    _In_opt_ PCUNICODE_STRING objectName,
    _In_ BOOLEAN releaseRequired);
PVOID QueryProcessPebCompat(_In_ PEPROCESS process);
NTSTATUS QueryProcessImageNameCompat(
    _In_ PEPROCESS process,
    _Outptr_ PUNICODE_STRING* imagePath);
