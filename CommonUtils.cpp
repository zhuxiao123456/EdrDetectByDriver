#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <fstream>
#include <cwctype>
#include <codecvt>
#include <algorithm>

#include "CommonUtils.h"

std::wstring Utf8ToWString(const std::string& utf8Str) {
	if (utf8Str.empty()) return std::wstring();
	int sizeNeeded = MultiByteToWideChar(CP_UTF8, 0, &utf8Str[0], (int)utf8Str.size(), NULL, 0);
	std::wstring wstrTo(sizeNeeded, 0);
	MultiByteToWideChar(CP_UTF8, 0, &utf8Str[0], (int)utf8Str.size(), &wstrTo[0], sizeNeeded);
	return wstrTo;
}

std::wstring GetExeDirectory() {
	wchar_t path[MAX_PATH] = { 0 };

	if (GetModuleFileNameW(NULL, path, MAX_PATH) == 0) {
		return L"";
	}

	std::wstring wsPath(path);
	size_t pos = wsPath.find_last_of(L"\\/");
	if (pos != std::wstring::npos) {
		return wsPath.substr(0, pos + 1);
	}
	return L"";
}

// ==============================
// 判断是否 64 位系统（完整）
// ==============================
bool Is64BitOS() {
	SYSTEM_INFO si = { 0 };
	GetNativeSystemInfo(&si);

	return (
		si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 ||
		si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_ARM64 ||
		si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_IA64
		);
}

void LogMessage(const std::wstring& message) {
	SYSTEMTIME st;
	GetLocalTime(&st);
	wchar_t timeBuf[64];
	swprintf_s(timeBuf, L"[%04d-%02d-%02d %02d:%02d:%02d] ",
		st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);

	std::wstring fullMessage = timeBuf + message;

	std::wcout << fullMessage << std::endl;

	std::wstring logPath = g_ExeDirectory + L"detect.log";
	std::wofstream logFile(logPath, std::ios::app);
	if (logFile.is_open()) {
		logFile.imbue(std::locale(std::locale(), new std::codecvt_utf8<wchar_t>));  // 强制utf8输出
		logFile << fullMessage << std::endl;
		logFile.close();
	}
}

std::wstring GetProcessNameByPid(DWORD pid) {
	std::wstring processName = L"<Unknown>";
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (hSnapshot == INVALID_HANDLE_VALUE) {
		LogMessage(L"CreateToolhelp32Snapshot 失败: " + std::to_wstring(GetLastError()));
		return processName;
	}

	if (hSnapshot != INVALID_HANDLE_VALUE) {
		PROCESSENTRY32W pe32;
		pe32.dwSize = sizeof(PROCESSENTRY32W);
		if (Process32FirstW(hSnapshot, &pe32)) {
			do {
				if (pe32.th32ProcessID == pid) {
					processName = pe32.szExeFile;
					break;
				}
			} while (Process32NextW(hSnapshot, &pe32));
		}
	}
	else {
		LogMessage(L"Process32FirstW 失败: " + std::to_wstring(GetLastError()));
	}
	CloseHandle(hSnapshot);
	std::transform(processName.begin(), processName.end(), processName.begin(),
		[](wchar_t c) { return (wchar_t)towlower((wint_t)c); }
	);
	return processName;
}

bool IsSensitiveParent(const std::wstring& parentName) {
	if (parentName.find(L"sqlservr.exe") != std::wstring::npos ||
		parentName.find(L"tomcat") != std::wstring::npos ||
		parentName.find(L"java.exe") != std::wstring::npos ||
		parentName.find(L"w3wp.exe") != std::wstring::npos) {
		return true;
	}
	return false;
}

bool IsMaliciousCommand(const std::wstring& cmdLine) {
	std::wstring lowerCmd = cmdLine;
	std::transform(lowerCmd.begin(), lowerCmd.end(), lowerCmd.begin(), ::towlower);

	const std::wstring blacklist[] = {
		L"whoami", L"ping", L"certutil", L"bitsadmin",
		L"powershell -enc", L"powershell -nop", L"net user", L"vssadmin"
	};

	for (const auto& keyword : blacklist) {
		if (lowerCmd.find(keyword) != std::wstring::npos) {
			return true;
		}
	}
	return false;
}