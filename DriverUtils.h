#pragma once
#include <windows.h>
#include <string>
#include "Shared.h"

// ===========================================================================
// 系统权限与路径辅助
// ===========================================================================
bool IsRunAsAdmin();
bool IsFileExists(const std::wstring& filePath);
bool QueryWin32ServiceState(
    const std::wstring& serviceName,
    DWORD& outState,
    bool& outExists);
bool InstallWin32Service(
    const std::wstring& serviceName,
    const std::wstring& displayName,
    const std::wstring& binaryPath,
    DWORD startType);
bool StartWin32Service(const std::wstring& serviceName);
bool StopWin32Service(const std::wstring& serviceName);
bool RemoveWin32Service(const std::wstring& serviceName);
bool QueryKernelDriverServiceState(
    const std::wstring& serviceName,
    DWORD& outState,
    bool& outExists);

// ===========================================================================
// 驱动生命周期管理
// ===========================================================================
bool LoadKernelDriver(const std::wstring& driverPath, const std::wstring& serviceName);
bool UnloadKernelDriver(const std::wstring& serviceName);

// ===========================================================================
// 驱动 IOCTL 通信
// ===========================================================================
bool AddDriverRule(HANDLE hDevice, const std::wstring& driverName);
bool ClearDriverRules(HANDLE hDevice);
bool AddFileRule(HANDLE hDevice, const FILE_RULE& rule);
bool ClearFileRules(HANDLE hDevice);
bool AddRegistryRule(HANDLE hDevice, const REGISTRY_RULE& rule);
bool ClearRegistryRules(HANDLE hDevice);
bool AddRegistryAllowRule(HANDLE hDevice, const REGISTRY_RULE& rule);
bool ClearRegistryAllowRules(HANDLE hDevice);
bool QueryDriverStatus(HANDLE hDevice, DRIVER_RUNTIME_STATUS& outStatus);
bool SetActiveDriverConfigInfo(
    HANDLE hDevice,
    const std::wstring& configVersion,
    const std::wstring& profileName,
    const std::wstring& generatedAt,
    ULONG processVerdictTimeoutMs,
    ULONG processVerdictFailMode);
