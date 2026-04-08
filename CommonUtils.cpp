#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <fstream>
#include <cstdio>
#include <cwctype>
#include <codecvt>
#include <algorithm>
#include <mutex>
#include <vector>

#include "CommonUtils.h"
#include <nlohmann/json.hpp>

using json = nlohmann::json;

namespace {
    std::mutex g_LogLock;
    std::wstring g_LogProfileName;
    std::wstring g_LogConfigVersion;
    std::wstring g_LogGeneratedAt;
    const ULONGLONG kMaxJsonLogSizeBytes = 10ULL * 1024ULL * 1024ULL;
    const int kMaxJsonLogBackups = 5;
    const char kJsonSchemaVersion[] = "1.0";
    const char kAgentName[] = "HostGuard";

    std::string DetectLogLevel(const std::wstring& message) {
        if (message.find(L"[!]") != std::wstring::npos || message.find(L"[-]") != std::wstring::npos) {
            return "warn";
        }
        if (message.find(L"[+]") != std::wstring::npos) {
            return "info";
        }
        return "debug";
    }

    bool IsCurrentProcessElevatedForLogging() {
        HANDLE tokenHandle = NULL;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tokenHandle)) {
            return false;
        }

        TOKEN_ELEVATION elevation = {};
        DWORD bytesReturned = 0;
        BOOL result = GetTokenInformation(
            tokenHandle,
            TokenElevation,
            &elevation,
            sizeof(elevation),
            &bytesReturned);
        CloseHandle(tokenHandle);

        return result == TRUE && elevation.TokenIsElevated != 0;
    }

    bool AppendUtf8LineToFileLocked(
        const std::wstring& filePath,
        const std::string& utf8Line,
        bool writeUtf8BomIfNew = false) {
        bool shouldWriteBom = false;
        if (writeUtf8BomIfNew) {
            WIN32_FILE_ATTRIBUTE_DATA attributes = {};
            if (!GetFileAttributesExW(filePath.c_str(), GetFileExInfoStandard, &attributes)) {
                shouldWriteBom = true;
            }
            else if (attributes.nFileSizeHigh == 0 && attributes.nFileSizeLow == 0) {
                shouldWriteBom = true;
            }
        }

        FILE* file = NULL;
        if (_wfopen_s(&file, filePath.c_str(), L"a+b") != 0 || file == NULL) {
            return false;
        }

        if (shouldWriteBom) {
            const unsigned char utf8Bom[] = { 0xEF, 0xBB, 0xBF };
            fwrite(utf8Bom, 1, sizeof(utf8Bom), file);
        }

        fwrite(utf8Line.data(), 1, utf8Line.size(), file);
        fwrite("\n", 1, 1, file);
        fclose(file);
        return true;
    }

    std::wstring GetCurrentProcessPathCached() {
        static const std::wstring cachedPath = []() -> std::wstring {
            wchar_t path[MAX_PATH] = {};
            if (GetModuleFileNameW(NULL, path, RTL_NUMBER_OF(path)) == 0) {
                return L"";
            }

            return std::wstring(path);
            }();

        return cachedPath;
    }

    std::wstring GetHostNameCached() {
        static const std::wstring cachedHostName = []() -> std::wstring {
            wchar_t computerName[MAX_COMPUTERNAME_LENGTH + 1] = {};
            DWORD size = RTL_NUMBER_OF(computerName);
            if (!GetComputerNameW(computerName, &size)) {
                return L"";
            }

            return std::wstring(computerName, size);
            }();

        return cachedHostName;
    }

    ULONGLONG GetFileSizeBytes(const WIN32_FILE_ATTRIBUTE_DATA& attributes) {
        return (static_cast<ULONGLONG>(attributes.nFileSizeHigh) << 32) |
            static_cast<ULONGLONG>(attributes.nFileSizeLow);
    }

    std::wstring BuildRotatedJsonLogPath(const std::wstring& filePath, int index) {
        return filePath + L"." + std::to_wstring(index);
    }

    void DeleteFileIfExists(const std::wstring& filePath) {
        DWORD attributes = GetFileAttributesW(filePath.c_str());
        if (attributes == INVALID_FILE_ATTRIBUTES || (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
            return;
        }

        DeleteFileW(filePath.c_str());
    }

    bool RotateFileToArchive(const std::wstring& sourcePath, const std::wstring& destinationPath) {
        if (sourcePath.empty() || destinationPath.empty()) {
            return false;
        }

        DeleteFileIfExists(destinationPath);
        if (CopyFileW(sourcePath.c_str(), destinationPath.c_str(), FALSE)) {
            DeleteFileW(sourcePath.c_str());
            return true;
        }

        return MoveFileExW(sourcePath.c_str(), destinationPath.c_str(), MOVEFILE_REPLACE_EXISTING) == TRUE;
    }

    void RotateJsonLogIfNeededLocked(const std::wstring& filePath, size_t nextLineSizeBytes) {
        WIN32_FILE_ATTRIBUTE_DATA attributes = {};
        if (!GetFileAttributesExW(filePath.c_str(), GetFileExInfoStandard, &attributes)) {
            return;
        }

        if ((attributes.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
            return;
        }

        const ULONGLONG currentSize = GetFileSizeBytes(attributes);
        const ULONGLONG projectedSize = currentSize + static_cast<ULONGLONG>(nextLineSizeBytes) + 1ULL;
        if (projectedSize <= kMaxJsonLogSizeBytes) {
            return;
        }

        DeleteFileIfExists(BuildRotatedJsonLogPath(filePath, kMaxJsonLogBackups));
        for (int index = kMaxJsonLogBackups - 1; index >= 1; --index) {
            const std::wstring sourcePath = BuildRotatedJsonLogPath(filePath, index);
            const std::wstring destinationPath = BuildRotatedJsonLogPath(filePath, index + 1);
            RotateFileToArchive(sourcePath, destinationPath);
        }

        const std::wstring rotatedPath = BuildRotatedJsonLogPath(filePath, 1);
        RotateFileToArchive(filePath, rotatedPath);
    }

    bool AppendJsonLineToFileLocked(const std::wstring& filePath, const std::string& utf8JsonLine) {
        RotateJsonLogIfNeededLocked(filePath, utf8JsonLine.size());
        return AppendUtf8LineToFileLocked(filePath, utf8JsonLine);
    }
}

std::wstring Utf8ToWString(const std::string& utf8Str) {
    if (utf8Str.empty()) return std::wstring();
    int sizeNeeded = MultiByteToWideChar(CP_UTF8, 0, utf8Str.data(), (int)utf8Str.size(), NULL, 0);
    if (sizeNeeded <= 0) return std::wstring();

    std::wstring wstrTo(sizeNeeded, 0);
    if (MultiByteToWideChar(CP_UTF8, 0, utf8Str.data(), (int)utf8Str.size(), &wstrTo[0], sizeNeeded) == 0) {
        return std::wstring();
    }
    return wstrTo;
}

std::string WStringToUtf8(const std::wstring& wideStr) {
    if (wideStr.empty()) {
        return std::string();
    }

    int sizeNeeded = WideCharToMultiByte(CP_UTF8, 0, wideStr.data(), (int)wideStr.size(), NULL, 0, NULL, NULL);
    if (sizeNeeded <= 0) {
        return std::string();
    }

    std::string utf8(sizeNeeded, 0);
    if (WideCharToMultiByte(CP_UTF8, 0, wideStr.data(), (int)wideStr.size(), &utf8[0], sizeNeeded, NULL, NULL) == 0) {
        return std::string();
    }

    return utf8;
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

std::wstring GetProgramDataDirectory() {
    wchar_t buffer[MAX_PATH] = {};
    DWORD length = GetEnvironmentVariableW(L"ProgramData", buffer, RTL_NUMBER_OF(buffer));
    if (length == 0 || length >= RTL_NUMBER_OF(buffer)) {
        return L"";
    }

    std::wstring path(buffer);
    if (!path.empty() && path.back() != L'\\' && path.back() != L'/') {
        path += L"\\";
    }
    return path;
}

bool EnsureDirectoryExists(const std::wstring& directoryPath) {
    if (directoryPath.empty()) {
        return false;
    }

    DWORD attributes = GetFileAttributesW(directoryPath.c_str());
    if (attributes != INVALID_FILE_ATTRIBUTES) {
        return (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
    }

    if (CreateDirectoryW(directoryPath.c_str(), NULL)) {
        return true;
    }

    return GetLastError() == ERROR_ALREADY_EXISTS;
}

std::wstring GetHostGuardDataDirectory() {
    std::wstring programData = GetProgramDataDirectory();
    if (programData.empty()) {
        return L"";
    }

    std::wstring hostGuardPath = programData + L"HostGuard\\";
    return hostGuardPath;
}

std::wstring ResolveRulesFilePath() {
    std::wstring hostGuardDataDirectory = GetHostGuardDataDirectory();
    if (!hostGuardDataDirectory.empty()) {
        std::wstring programDataRulesPath = hostGuardDataDirectory + L"rules.json";
        DWORD attributes = GetFileAttributesW(programDataRulesPath.c_str());
        if (attributes != INVALID_FILE_ATTRIBUTES && !(attributes & FILE_ATTRIBUTE_DIRECTORY)) {
            return programDataRulesPath;
        }
    }

    return g_ExeDirectory + L"rules.json";
}

std::wstring GetHostGuardLogFilePath() {
    std::wstring hostGuardDataDirectory = GetHostGuardDataDirectory();
    if (IsCurrentProcessElevatedForLogging() &&
        !hostGuardDataDirectory.empty() &&
        EnsureDirectoryExists(hostGuardDataDirectory)) {
        return hostGuardDataDirectory + L"detect.log";
    }

    return g_ExeDirectory + L"detect.log";
}

std::wstring GetHostGuardJsonLogFilePath() {
    std::wstring hostGuardDataDirectory = GetHostGuardDataDirectory();
    if (IsCurrentProcessElevatedForLogging() &&
        !hostGuardDataDirectory.empty() &&
        EnsureDirectoryExists(hostGuardDataDirectory)) {
        return hostGuardDataDirectory + L"events.jsonl";
    }

    return g_ExeDirectory + L"events.jsonl";
}

std::wstring GetCurrentTimestampForJson() {
    SYSTEMTIME st;
    GetLocalTime(&st);

    wchar_t timeBuf[64];
    swprintf_s(
        timeBuf,
        L"%04d-%02d-%02dT%02d:%02d:%02d.%03d",
        st.wYear,
        st.wMonth,
        st.wDay,
        st.wHour,
        st.wMinute,
        st.wSecond,
        st.wMilliseconds);
    return std::wstring(timeBuf);
}

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

    {
        std::lock_guard<std::mutex> lock(g_LogLock);

        std::wcout << fullMessage << std::endl;

        std::wstring primaryLogPath = GetHostGuardLogFilePath();
        std::wstring fallbackLogPath = g_ExeDirectory + L"detect.log";
        if (!AppendUtf8LineToFileLocked(primaryLogPath, WStringToUtf8(fullMessage), true) &&
            _wcsicmp(primaryLogPath.c_str(), fallbackLogPath.c_str()) != 0) {
            AppendUtf8LineToFileLocked(fallbackLogPath, WStringToUtf8(fullMessage), true);
        }

        json event;
        const std::string level = DetectLogLevel(message);
        PopulateCommonJsonEventFields(event, "log", level.c_str());
        event["message"] = WStringToUtf8(message);
        PopulateRuleContextJsonFields(event, g_LogProfileName, g_LogConfigVersion, g_LogGeneratedAt);

        std::wstring primaryJsonPath = GetHostGuardJsonLogFilePath();
        std::wstring fallbackJsonPath = g_ExeDirectory + L"events.jsonl";
        if (!AppendJsonLineToFileLocked(primaryJsonPath, event.dump(-1, ' ', true)) &&
            _wcsicmp(primaryJsonPath.c_str(), fallbackJsonPath.c_str()) != 0) {
            AppendJsonLineToFileLocked(fallbackJsonPath, event.dump(-1, ' ', true));
        }
    }
}

void SetLogRuleContext(
    const std::wstring& profileName,
    const std::wstring& configVersion,
    const std::wstring& generatedAt) {
    std::lock_guard<std::mutex> lock(g_LogLock);
    g_LogProfileName = profileName;
    g_LogConfigVersion = configVersion;
    g_LogGeneratedAt = generatedAt;
}

void PopulateCommonJsonEventFields(
    nlohmann::json& event,
    const char* eventType,
    const char* level) {
    event["time"] = WStringToUtf8(GetCurrentTimestampForJson());
    event["schema_version"] = kJsonSchemaVersion;
    event["agent_name"] = kAgentName;
    event["event_type"] = (eventType != nullptr) ? eventType : "unknown";
    event["level"] = (level != nullptr) ? level : "info";
    event["agent_pid"] = static_cast<ULONG>(GetCurrentProcessId());

    const std::wstring hostName = GetHostNameCached();
    if (!hostName.empty()) {
        event["host_name"] = WStringToUtf8(hostName);
    }

    const std::wstring agentPath = GetCurrentProcessPathCached();
    if (!agentPath.empty()) {
        event["agent_path"] = WStringToUtf8(agentPath);
    }
}

void PopulateRuleContextJsonFields(
    nlohmann::json& event,
    const std::wstring& profileName,
    const std::wstring& configVersion,
    const std::wstring& generatedAt) {
    if (!profileName.empty()) {
        event["profile_name"] = WStringToUtf8(profileName);
    }
    if (!configVersion.empty()) {
        event["config_version"] = WStringToUtf8(configVersion);
    }
    if (!generatedAt.empty()) {
        event["generated_at"] = WStringToUtf8(generatedAt);
    }
}

void AppendJsonLogLine(const std::string& utf8JsonLine) {
    if (utf8JsonLine.empty()) {
        return;
    }

    std::lock_guard<std::mutex> lock(g_LogLock);
    std::wstring primaryJsonPath = GetHostGuardJsonLogFilePath();
    std::wstring fallbackJsonPath = g_ExeDirectory + L"events.jsonl";
    if (!AppendJsonLineToFileLocked(primaryJsonPath, utf8JsonLine) &&
        _wcsicmp(primaryJsonPath.c_str(), fallbackJsonPath.c_str()) != 0) {
        AppendJsonLineToFileLocked(fallbackJsonPath, utf8JsonLine);
    }
}

std::wstring GetProcessNameByPid(DWORD pid) {
    std::wstring processName = L"<Unknown>";
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (hSnapshot == INVALID_HANDLE_VALUE) {
        LogMessage(L"CreateToolhelp32Snapshot 失败: " + std::to_wstring(GetLastError()));
        return processName;
    }

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
    std::transform(lowerCmd.begin(), lowerCmd.end(), lowerCmd.begin(),
        [](wchar_t c) { return (wchar_t)towlower((wint_t)c); });

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
