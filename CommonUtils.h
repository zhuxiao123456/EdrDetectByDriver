#pragma once
#include <windows.h>
#include <string>
#include <nlohmann/json.hpp>

// 声明全局变量（在 cpp 中定义）
extern std::wstring g_ExeDirectory;

// ===========================================================================
// 基础辅助函数
// ===========================================================================
std::wstring Utf8ToWString(const std::string& utf8Str);
std::string WStringToUtf8(const std::wstring& wideStr);
std::wstring GetExeDirectory();
std::wstring GetProgramDataDirectory();
std::wstring GetHostGuardDataDirectory();
std::wstring ResolveRulesFilePath();
std::wstring GetHostGuardLogFilePath();
std::wstring GetHostGuardJsonLogFilePath();
std::wstring GetCurrentTimestampForJson();
bool EnsureDirectoryExists(const std::wstring& directoryPath);
bool Is64BitOS();

// ===========================================================================
// 日志与进程辅助函数
// ===========================================================================
void LogMessage(const std::wstring& message);
void SetLogRuleContext(
    const std::wstring& profileName,
    const std::wstring& configVersion,
    const std::wstring& generatedAt);
void PopulateCommonJsonEventFields(
    nlohmann::json& event,
    const char* eventType,
    const char* level);
void PopulateRuleContextJsonFields(
    nlohmann::json& event,
    const std::wstring& profileName,
    const std::wstring& configVersion,
    const std::wstring& generatedAt);
void AppendJsonLogLine(const std::string& utf8JsonLine);
std::wstring GetProcessNameByPid(DWORD pid);

// ===========================================================================
// 恶意特征检测辅助函数 (遗留或简单检测)
// ===========================================================================
bool IsSensitiveParent(const std::wstring& parentName);
bool IsMaliciousCommand(const std::wstring& cmdLine);
