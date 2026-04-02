#pragma once
#include <windows.h>
#include <string>

// 声明全局变量（在 cpp 中定义）
extern std::wstring g_ExeDirectory;

// ===========================================================================
// 基础辅助函数
// ===========================================================================
std::wstring Utf8ToWString(const std::string& utf8Str);
std::wstring GetExeDirectory();
bool Is64BitOS();

// ===========================================================================
// 日志与进程辅助函数
// ===========================================================================
void LogMessage(const std::wstring& message);
std::wstring GetProcessNameByPid(DWORD pid);

// ===========================================================================
// 恶意特征检测辅助函数 (遗留或简单检测)
// ===========================================================================
bool IsSensitiveParent(const std::wstring& parentName);
bool IsMaliciousCommand(const std::wstring& cmdLine);