#include "OsVersionHelper.h"

BOOLEAN QueryOsVersionInfo(_Out_ POS_VERSION_INFO versionInfo) {
    if (versionInfo == NULL) {
        return FALSE;
    }

    RtlZeroMemory(versionInfo, sizeof(*versionInfo));

    RTL_OSVERSIONINFOW osVersion = {};
    osVersion.dwOSVersionInfoSize = sizeof(osVersion);
    if (!NT_SUCCESS(RtlGetVersion(&osVersion))) {
        return FALSE;
    }

    versionInfo->MajorVersion = osVersion.dwMajorVersion;
    versionInfo->MinorVersion = osVersion.dwMinorVersion;
    versionInfo->BuildNumber = osVersion.dwBuildNumber;
    return TRUE;
}
