#include "DriverUtils.h"
#include <iostream>
#include "Shared.h" 
#include "resource.h" 

// ===========================================================================
// 辅助函数：检查当前是否以管理员权限运行 [修复问题 1, 3]
// ===========================================================================
bool IsRunAsAdmin() {
	BOOL fIsRunAsAdmin = FALSE;
	PSID pAdministratorsGroup = NULL;
	SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
	if (AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0, &pAdministratorsGroup)) {
		CheckTokenMembership(NULL, pAdministratorsGroup, &fIsRunAsAdmin);
		FreeSid(pAdministratorsGroup);
	}
	return fIsRunAsAdmin == TRUE;
}

// ===========================================================================
// 辅助函数：检查文件是否存在 [修复问题 8]
// ===========================================================================
bool IsFileExists(const std::wstring& filePath) {
	DWORD dwAttrib = GetFileAttributesW(filePath.c_str());
	return (dwAttrib != INVALID_FILE_ATTRIBUTES && !(dwAttrib & FILE_ATTRIBUTE_DIRECTORY));
}

// ===========================================================================
// 释放驱动文件
// ===========================================================================
bool DropDriverFromResource(int resourceId, const std::wstring& outputPath) {
	if (!IsRunAsAdmin()) {
		std::wcerr << L"[-] 错误：释放驱动需要管理员权限！" << std::endl;
		return false;
	}

	HRSRC hRes = FindResource(NULL, MAKEINTRESOURCE(resourceId), L"SYSFILE");
	if (!hRes) {
		std::wcerr << L"[-] 错误：找不到驱动资源，ID: " << resourceId << std::endl;
		return false;
	}

	HGLOBAL hMem = LoadResource(NULL, hRes);
	if (!hMem) {
		std::wcerr << L"[-] 错误：无法加载驱动资源！" << std::endl;
		return false;
	}

	void* pData = LockResource(hMem);
	DWORD size = SizeofResource(NULL, hRes);
	if (!pData || size == 0) {
		std::wcerr << L"[-] 错误：资源锁定失败或大小为 0！" << std::endl;
		return false;
	}

	// [修复问题 2]: 抛弃 ofstream，使用 CreateFileW 原生支持宽字符与 Unicode 路径
	HANDLE hFile = CreateFileW(outputPath.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		std::wcerr << L"[-] 错误：无法创建驱动文件 (错误码: " << GetLastError() << L") 路径: " << outputPath << std::endl;
		return false;
	}

	DWORD bytesWritten = 0;
	BOOL bResult = WriteFile(hFile, pData, size, &bytesWritten, NULL);
	CloseHandle(hFile);

	// [修复问题 5]: 严格来说 Win32 会自动管理 LockResource 的内存，但良好的规范要求记录
	// 注意：16位时代的 FreeResource 在 32/64 位 Windows 中已废弃 (宏定义为啥也不做)，所以无需调用

	if (!bResult || bytesWritten != size) {
		std::wcerr << L"[-] 错误：驱动文件写入不完整！" << std::endl;
		DeleteFileW(outputPath.c_str()); // 写入失败时清理残次品
		return false;
	}

	return true;
}

// ===========================================================================
// 加载内核驱动
// ===========================================================================
bool LoadKernelDriver(const std::wstring& driverPath, const std::wstring& serviceName) {
	if (!IsRunAsAdmin()) {
		std::wcerr << L"[-] 错误：加载驱动需要管理员权限！" << std::endl;
		return false;
	}

	if (!IsFileExists(driverPath)) {
		std::wcerr << L"[-] 错误：驱动文件不存在，无法注册服务！路径: " << driverPath << std::endl;
		return false;
	}

	SC_HANDLE hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (!hSCManager) {
		std::wcerr << L"[-] 错误：无法打开服务控制管理器 (错误码: " << GetLastError() << L")" << std::endl;
		return false;
	}

	SC_HANDLE hService = CreateServiceW(hSCManager, serviceName.c_str(), serviceName.c_str(),
		SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL,
		driverPath.c_str(), NULL, NULL, NULL, NULL, NULL);

	if (!hService) {
		if (GetLastError() == ERROR_SERVICE_EXISTS) {
			hService = OpenServiceW(hSCManager, serviceName.c_str(), SERVICE_ALL_ACCESS);
		}
		else {
			std::wcerr << L"[-] 错误：创建服务失败 (错误码: " << GetLastError() << L")" << std::endl;
			CloseServiceHandle(hSCManager);
			return false;
		}
	}

	bool success = true;
	if (!StartServiceW(hService, 0, NULL)) {
		DWORD err = GetLastError();
		if (err != ERROR_SERVICE_ALREADY_RUNNING) {
			std::wcerr << L"[-] 错误：驱动服务启动失败 (错误码: " << err << L")" << std::endl;
			success = false;

			// [修复问题 4]: 启动失败时，立刻清理刚创建的服务，防止产生僵尸服务
			DeleteService(hService);
		}
	}

	CloseServiceHandle(hService);
	CloseServiceHandle(hSCManager);
	return success;
}

// ===========================================================================
// 添加黑名单规则
// ===========================================================================
bool AddDriverRule(HANDLE hDevice, const std::wstring& driverName) {
	// [修复问题 7]: 判断句柄有效性
	if (hDevice == INVALID_HANDLE_VALUE || hDevice == NULL) {
		std::wcerr << L"[-] 错误：传入的驱动通信句柄无效！" << std::endl;
		return false;
	}

	// [修复问题 6]: 校验字符串长度，防止 wcsncpy_s 发生静默截断
	if (driverName.length() >= MAX_RULE_LENGTH) {
		std::wcerr << L"[-] 错误：规则字符串过长，超过最大限制 (" << MAX_RULE_LENGTH << L")" << std::endl;
		return false;
	}

	BLACKLIST_RULE rule;
	ZeroMemory(&rule, sizeof(BLACKLIST_RULE));

	// 使用 wcscpy_s 替代，结合上面的长度判断，更加安全
	wcscpy_s(rule.DriverName, MAX_RULE_LENGTH, driverName.c_str());

	DWORD bytesReturned = 0;
	BOOL result = DeviceIoControl(
		hDevice,
		IOCTL_ADD_DRIVER_RULE,
		&rule,
		sizeof(BLACKLIST_RULE),
		NULL,
		0,
		&bytesReturned,
		NULL
	);

	if (!result) {
		// [修复问题 9]: 提供详细的系统错误码追踪
		std::wcerr << L"[-] 错误：下发规则失败，IOCTL 拒绝 (错误码: " << GetLastError() << L")" << std::endl;
		return false;
	}
	return true;
}

// ===========================================================================
// 清空黑名单规则
// ===========================================================================
bool ClearDriverRules(HANDLE hDevice) {
	if (hDevice == INVALID_HANDLE_VALUE || hDevice == NULL) {
		std::wcerr << L"[-] 错误：传入的驱动通信句柄无效！" << std::endl;
		return false;
	}

	DWORD bytesReturned = 0;
	BOOL result = DeviceIoControl(hDevice, IOCTL_CLEAR_DRIVER_RULES, NULL, 0, NULL, 0, &bytesReturned, NULL);

	if (!result) {
		std::wcerr << L"[-] 错误：清空规则失败 (错误码: " << GetLastError() << L")" << std::endl;
		return false;
	}
	return true;
}