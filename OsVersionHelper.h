#pragma once

#include <ntddk.h>

typedef struct _OS_VERSION_INFO {
    ULONG MajorVersion;
    ULONG MinorVersion;
    ULONG BuildNumber;
} OS_VERSION_INFO, *POS_VERSION_INFO;

BOOLEAN QueryOsVersionInfo(_Out_ POS_VERSION_INFO versionInfo);
