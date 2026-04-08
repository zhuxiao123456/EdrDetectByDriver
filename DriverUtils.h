#pragma once
#include <windows.h>
#include <string>

// ===========================================================================
// 系统权限与路径辅助
// ===========================================================================
bool IsRunAsAdmin();
bool IsFileExists(const std::wstring& filePath);

// ===========================================================================
// 驱动生命周期管理
// ===========================================================================
bool DropDriverFromResource(int resourceId, const std::wstring& outputPath);
bool LoadKernelDriver(const std::wstring& driverPath, const std::wstring& serviceName);

// ===========================================================================
// 驱动 IOCTL 通信
// ===========================================================================
bool AddDriverRule(HANDLE hDevice, const std::wstring& driverName);
bool ClearDriverRules(HANDLE hDevice);