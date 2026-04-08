#include <windows.h>
#include <iostream>
#include <atomic>
#include <mutex>
#include <nlohmann/json.hpp>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>
#include <string>

#include "CommonUtils.h"
#include "DriverUtils.h"
#include "Shared.h"
#include "RuleManager.h"

using json = nlohmann::json;

RuleManager g_RuleManager;
std::wstring g_ExeDirectory;

namespace {
    const wchar_t kHostGuardServiceName[] = L"HostGuard";
    const wchar_t kHostGuardDisplayName[] = L"HostGuard Endpoint Protection";
    const wchar_t kDriverServiceName[] = L"PebMonitor";

    HANDLE g_StopEvent = NULL;
    HANDLE g_ShutdownCompleteEvent = NULL;
    std::atomic<void*> g_MainDeviceHandle{ INVALID_HANDLE_VALUE };
    std::atomic<void*> g_DriverEventDeviceHandle{ INVALID_HANDLE_VALUE };
    SERVICE_STATUS_HANDLE g_ServiceStatusHandle = NULL;
    SERVICE_STATUS g_ServiceStatus = {};
    bool g_IsServiceMode = false;

    struct ProcessCacheEntry {
        std::wstring processName;
        std::wstring commandLine;
        ULONGLONG lastSeenTick = 0;
    };

    struct FileState {
        bool exists = false;
        FILETIME lastWriteTime = {};
        DWORD fileSizeHigh = 0;
        DWORD fileSizeLow = 0;
    };

    std::mutex g_ProcessCacheLock;
    std::unordered_map<DWORD, ProcessCacheEntry> g_ProcessCache;
    const size_t kMaxProcessCacheEntries = 4096;
    const ULONGLONG kProcessCacheTtlMs = 10ULL * 60ULL * 1000ULL;

    bool IsTrackedHandleValid(HANDLE handle) {
        return handle != NULL && handle != INVALID_HANDLE_VALUE;
    }

    void TrackDeviceHandle(std::atomic<void*>& slot, HANDLE handle) {
        slot.store(handle, std::memory_order_release);
    }

    void UntrackDeviceHandle(std::atomic<void*>& slot, HANDLE handle) {
        void* expected = handle;
        slot.compare_exchange_strong(
            expected,
            INVALID_HANDLE_VALUE,
            std::memory_order_acq_rel,
            std::memory_order_acquire);
    }

    void CloseTrackedHandle(HANDLE& handle, std::atomic<void*>& slot) {
        if (!IsTrackedHandleValid(handle)) {
            handle = INVALID_HANDLE_VALUE;
            return;
        }

        UntrackDeviceHandle(slot, handle);
        CloseHandle(handle);
        handle = INVALID_HANDLE_VALUE;
    }

    bool IsShutdownRequested() {
        return g_StopEvent != NULL && WaitForSingleObject(g_StopEvent, 0) == WAIT_OBJECT_0;
    }

    bool WaitForShutdown(DWORD timeoutMs) {
        return g_StopEvent != NULL && WaitForSingleObject(g_StopEvent, timeoutMs) == WAIT_OBJECT_0;
    }

    void RequestShutdown() {
        if (g_StopEvent != NULL) {
            SetEvent(g_StopEvent);
        }

        HANDLE mainDeviceHandle = reinterpret_cast<HANDLE>(g_MainDeviceHandle.load(std::memory_order_acquire));
        if (IsTrackedHandleValid(mainDeviceHandle)) {
            CancelIoEx(mainDeviceHandle, NULL);
        }

        HANDLE driverEventHandle = reinterpret_cast<HANDLE>(g_DriverEventDeviceHandle.load(std::memory_order_acquire));
        if (IsTrackedHandleValid(driverEventHandle) && driverEventHandle != mainDeviceHandle) {
            CancelIoEx(driverEventHandle, NULL);
        }
    }

    bool EnsureRuntimeEvents() {
        if (g_StopEvent == NULL) {
            g_StopEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
        }
        if (g_ShutdownCompleteEvent == NULL) {
            g_ShutdownCompleteEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
        }

        if (g_StopEvent == NULL || g_ShutdownCompleteEvent == NULL) {
            return false;
        }

        ResetEvent(g_StopEvent);
        ResetEvent(g_ShutdownCompleteEvent);
        return true;
    }

    void CleanupRuntimeEvents() {
        if (g_StopEvent != NULL) {
            CloseHandle(g_StopEvent);
            g_StopEvent = NULL;
        }
        if (g_ShutdownCompleteEvent != NULL) {
            CloseHandle(g_ShutdownCompleteEvent);
            g_ShutdownCompleteEvent = NULL;
        }
    }

    void ReportServiceStatus(DWORD currentState, DWORD win32ExitCode, DWORD waitHint) {
        if (g_ServiceStatusHandle == NULL) {
            return;
        }

        g_ServiceStatus.dwCurrentState = currentState;
        g_ServiceStatus.dwWin32ExitCode = win32ExitCode;
        g_ServiceStatus.dwWaitHint = waitHint;
        g_ServiceStatus.dwControlsAccepted =
            (currentState == SERVICE_START_PENDING) ? 0 : (SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN);
        g_ServiceStatus.dwCheckPoint =
            (currentState == SERVICE_RUNNING || currentState == SERVICE_STOPPED) ? 0 : g_ServiceStatus.dwCheckPoint + 1;

        SetServiceStatus(g_ServiceStatusHandle, &g_ServiceStatus);
    }

    DWORD WINAPI ServiceControlHandlerEx(
        DWORD control,
        DWORD eventType,
        LPVOID eventData,
        LPVOID context) {
        UNREFERENCED_PARAMETER(eventType);
        UNREFERENCED_PARAMETER(eventData);
        UNREFERENCED_PARAMETER(context);

        switch (control) {
        case SERVICE_CONTROL_STOP:
        case SERVICE_CONTROL_SHUTDOWN:
            ReportServiceStatus(SERVICE_STOP_PENDING, NO_ERROR, 15000);
            RequestShutdown();
            return NO_ERROR;
        case SERVICE_CONTROL_INTERROGATE:
            ReportServiceStatus(g_ServiceStatus.dwCurrentState, NO_ERROR, 0);
            return NO_ERROR;
        default:
            return ERROR_CALL_NOT_IMPLEMENTED;
        }
    }

    BOOL WINAPI ConsoleCtrlHandler(DWORD ctrlType) {
        switch (ctrlType) {
        case CTRL_C_EVENT:
        case CTRL_BREAK_EVENT:
        case CTRL_CLOSE_EVENT:
        case CTRL_LOGOFF_EVENT:
        case CTRL_SHUTDOWN_EVENT:
            RequestShutdown();
            if (g_ShutdownCompleteEvent != NULL) {
                WaitForSingleObject(g_ShutdownCompleteEvent, 15000);
            }
            return TRUE;
        default:
            return FALSE;
        }
    }

    bool QueryFileState(const std::wstring& filePath, FileState& state) {
        WIN32_FILE_ATTRIBUTE_DATA attributes = {};
        if (!GetFileAttributesExW(filePath.c_str(), GetFileExInfoStandard, &attributes)) {
            state = FileState{};
            return false;
        }

        state.exists = true;
        state.lastWriteTime = attributes.ftLastWriteTime;
        state.fileSizeHigh = attributes.nFileSizeHigh;
        state.fileSizeLow = attributes.nFileSizeLow;
        return true;
    }

    bool IsSameFileState(const FileState& left, const FileState& right) {
        return left.exists == right.exists &&
            left.fileSizeHigh == right.fileSizeHigh &&
            left.fileSizeLow == right.fileSizeLow &&
            left.lastWriteTime.dwLowDateTime == right.lastWriteTime.dwLowDateTime &&
            left.lastWriteTime.dwHighDateTime == right.lastWriteTime.dwHighDateTime;
    }

    std::wstring RegistryOperationToString(ULONG operation) {
        switch (operation) {
        case REGISTRY_OPERATION_SET_VALUE:
            return L"set_value";
        case REGISTRY_OPERATION_CREATE_KEY:
            return L"create_key";
        case REGISTRY_OPERATION_DELETE_VALUE:
            return L"delete_value";
        case REGISTRY_OPERATION_DELETE_KEY:
            return L"delete_key";
        case REGISTRY_OPERATION_RENAME_KEY:
            return L"rename_key";
        case REGISTRY_OPERATION_SET_INFORMATION_KEY:
            return L"set_information_key";
        default:
            return L"unknown";
        }
    }

    std::wstring FileOperationToString(ULONG operation) {
        switch (operation) {
        case FILE_OPERATION_CREATE:
            return L"create";
        case FILE_OPERATION_WRITE:
            return L"write";
        case FILE_OPERATION_CREATE_OR_WRITE:
            return L"create_or_write";
        default:
            return L"unknown";
        }
    }

    std::wstring DescribeConfigIdentity(const RuleConfiguration& config) {
        std::wstring description =
            L"Profile=" + (config.profileName.empty() ? L"default" : config.profileName) +
            L", Version=" + (config.configVersion.empty() ? L"unversioned" : config.configVersion);
        if (!config.generatedAt.empty()) {
            description += L", GeneratedAt=" + config.generatedAt;
        }
        if (!config.sourcePath.empty()) {
            description += L", RulesPath=" + config.sourcePath;
        }

        return description;
    }

    bool HasConfigIdentityChanged(const RuleConfiguration& previousConfig, const RuleConfiguration& newConfig) {
        return previousConfig.profileName != newConfig.profileName ||
            previousConfig.configVersion != newConfig.configVersion ||
            previousConfig.generatedAt != newConfig.generatedAt ||
            previousConfig.sourcePath != newConfig.sourcePath;
    }

    void AppendPrefixedConfigFields(
        json& event,
        const RuleConfiguration& config,
        const char* prefix) {
        const std::string keyPrefix = (prefix != nullptr) ? prefix : "";

        if (!config.profileName.empty()) {
            event[keyPrefix + "profile_name"] = WStringToUtf8(config.profileName);
        }
        if (!config.configVersion.empty()) {
            event[keyPrefix + "config_version"] = WStringToUtf8(config.configVersion);
        }
        if (!config.generatedAt.empty()) {
            event[keyPrefix + "generated_at"] = WStringToUtf8(config.generatedAt);
        }
        if (!config.sourcePath.empty()) {
            event[keyPrefix + "rules_path"] = WStringToUtf8(config.sourcePath);
        }
    }

    void LogConfigSummary(const RuleConfiguration& config) {
        std::wstring prefix = L"[+] 当前配置已生效";
        if (!config.profileName.empty() || !config.configVersion.empty()) {
            prefix += L" (Profile=" +
                (config.profileName.empty() ? L"default" : config.profileName) +
                L", Version=" +
                (config.configVersion.empty() ? L"unversioned" : config.configVersion) +
                L")";
        }
        if (!config.generatedAt.empty()) {
            prefix += L" [GeneratedAt=" + config.generatedAt + L"]";
        }

        LogMessage(
            prefix +
            L": 进程规则 " + std::to_wstring(config.processRules.size()) +
            L" 条, 进程白名单 " + std::to_wstring(config.processAllowRules.size()) +
            L" 条, 文件规则 " + std::to_wstring(config.fileRuleDefinitions.size()) +
            L" 条, 注册表规则 " + std::to_wstring(config.registryRuleDefinitions.size()) +
            L" 条, 注册表白名单 " + std::to_wstring(config.registryAllowRuleDefinitions.size()) +
            L" 条, 驱动黑名单 " + std::to_wstring(config.driverBlacklist.size()) + L" 条。");
    }

    void LogDriverStatusSnapshot(const DRIVER_RUNTIME_STATUS& status) {
        std::wstring flagsText;
        if (status.StatusFlags & DRIVER_STATUS_FLAG_DEVICE_READY) {
            flagsText += L"device ";
        }
        if (status.StatusFlags & DRIVER_STATUS_FLAG_PROCESS_CALLBACK_REGISTERED) {
            flagsText += L"process_cb ";
        }
        if (status.StatusFlags & DRIVER_STATUS_FLAG_IMAGE_CALLBACK_REGISTERED) {
            flagsText += L"image_cb ";
        }
        if (status.StatusFlags & DRIVER_STATUS_FLAG_REGISTRY_CALLBACK_REGISTERED) {
            flagsText += L"registry_cb ";
        }
        if (status.StatusFlags & DRIVER_STATUS_FLAG_FILE_FILTER_READY) {
            flagsText += L"file_filter ";
        }
        if (flagsText.empty()) {
            flagsText = L"<none>";
        }

        LogMessage(
            L"[+] 驱动状态: Flags=" + flagsText +
            L", 驱动黑名单=" + std::to_wstring(status.DriverBlacklistCount) +
            L", 文件规则=" + std::to_wstring(status.FileRuleCount) +
            L", 注册表拦截规则=" + std::to_wstring(status.RegistryRuleCount) +
            L", 注册表白名单规则=" + std::to_wstring(status.RegistryAllowRuleCount) +
            L", 进程事件队列=" + std::to_wstring(status.ProcessEventQueueCount) +
            L", 驱动事件队列=" + std::to_wstring(status.DriverEventQueueCount));

        if (status.ConfigVersion[0] != L'\0' || status.ProfileName[0] != L'\0') {
            LogMessage(
                L"[+] 驱动当前配置: Profile=" + std::wstring(status.ProfileName) +
                L", Version=" + std::wstring(status.ConfigVersion) +
                (status.GeneratedAt[0] != L'\0' ? (L", GeneratedAt=" + std::wstring(status.GeneratedAt)) : L""));
        }
    }

    bool QueryAndLogDriverStatus(HANDLE hDevice) {
        DRIVER_RUNTIME_STATUS status = {};
        if (!QueryDriverStatus(hDevice, status)) {
            LogMessage(L"[!] 警告：查询驱动状态失败，无法确认内核规则同步是否完成。");
            return false;
        }

        LogDriverStatusSnapshot(status);
        return true;
    }

    json BuildBaseJsonEvent(
        const char* eventType,
        const char* level,
        const RuleConfiguration& config) {
        json event;
        PopulateCommonJsonEventFields(event, eventType, level);
        PopulateRuleContextJsonFields(event, config.profileName, config.configVersion, config.generatedAt);
        if (!config.sourcePath.empty()) {
            event["rules_path"] = WStringToUtf8(config.sourcePath);
        }
        return event;
    }

    json BuildBaseJsonEvent(const char* eventType, const char* level) {
        return BuildBaseJsonEvent(eventType, level, g_RuleManager.GetRuleConfigurationSnapshot());
    }

    void EmitJsonEvent(const json& event) {
        AppendJsonLogLine(event.dump(-1, ' ', true));
    }

    void PruneProcessCacheLocked(ULONGLONG nowTick) {
        for (std::unordered_map<DWORD, ProcessCacheEntry>::iterator it = g_ProcessCache.begin();
            it != g_ProcessCache.end();) {
            if (nowTick - it->second.lastSeenTick > kProcessCacheTtlMs) {
                it = g_ProcessCache.erase(it);
            }
            else {
                ++it;
            }
        }

        while (g_ProcessCache.size() > kMaxProcessCacheEntries) {
            std::unordered_map<DWORD, ProcessCacheEntry>::iterator oldestIt = g_ProcessCache.begin();
            for (std::unordered_map<DWORD, ProcessCacheEntry>::iterator it = g_ProcessCache.begin();
                it != g_ProcessCache.end();
                ++it) {
                if (it->second.lastSeenTick < oldestIt->second.lastSeenTick) {
                    oldestIt = it;
                }
            }
            g_ProcessCache.erase(oldestIt);
        }
    }

    void CacheProcessContext(DWORD pid, const std::wstring& processName, const std::wstring& commandLine) {
        if (pid == 0 || (processName.empty() && commandLine.empty())) {
            return;
        }

        std::lock_guard<std::mutex> lock(g_ProcessCacheLock);
        ProcessCacheEntry& entry = g_ProcessCache[pid];
        if (!processName.empty() && processName != L"<unknown>") {
            entry.processName = processName;
        }
        if (!commandLine.empty()) {
            entry.commandLine = commandLine;
        }
        entry.lastSeenTick = GetTickCount64();
        PruneProcessCacheLocked(entry.lastSeenTick);
    }

    std::wstring GetCachedProcessName(DWORD pid) {
        if (pid == 0) {
            return L"";
        }

        std::lock_guard<std::mutex> lock(g_ProcessCacheLock);
        std::unordered_map<DWORD, ProcessCacheEntry>::const_iterator it = g_ProcessCache.find(pid);
        if (it == g_ProcessCache.end()) {
            return L"";
        }
        return it->second.processName;
    }

    std::wstring GetCachedProcessCommandLine(DWORD pid) {
        if (pid == 0) {
            return L"";
        }

        std::lock_guard<std::mutex> lock(g_ProcessCacheLock);
        std::unordered_map<DWORD, ProcessCacheEntry>::const_iterator it = g_ProcessCache.find(pid);
        if (it == g_ProcessCache.end()) {
            return L"";
        }
        return it->second.commandLine;
    }
}

static std::wstring FindLocalDriverPath() {
    const std::wstring candidates[] = {
        g_ExeDirectory + L"PebMonitor.sys",
        g_ExeDirectory + L"DriverModule.sys"
    };

    for (const auto& candidate : candidates) {
        if (IsFileExists(candidate)) {
            return candidate;
        }
    }
    return L"";
}

static HANDLE OpenDriverDevice() {
    return CreateFileW(L"\\\\.\\PebMonitor", GENERIC_READ | GENERIC_WRITE,
        0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
}

static std::wstring GetCurrentExePath() {
    wchar_t path[MAX_PATH] = {};
    if (GetModuleFileNameW(NULL, path, RTL_NUMBER_OF(path)) == 0) {
        return L"";
    }

    return std::wstring(path);
}

static std::wstring ServiceStateToString(DWORD state) {
    switch (state) {
    case SERVICE_STOPPED:
        return L"stopped";
    case SERVICE_START_PENDING:
        return L"start_pending";
    case SERVICE_STOP_PENDING:
        return L"stop_pending";
    case SERVICE_RUNNING:
        return L"running";
    default:
        return L"state_" + std::to_wstring(state);
    }
}

static int RunStatusCommand(const std::wstring& rulesPath) {
    RuleConfiguration pendingConfig;
    std::wstring loadError;
    const bool loadSucceeded = g_RuleManager.TryLoadRulesFromJson(rulesPath, pendingConfig, &loadError);
    if (loadSucceeded) {
        SetLogRuleContext(pendingConfig.profileName, pendingConfig.configVersion, pendingConfig.generatedAt);
    }

    LogMessage(L"[*] 正在执行状态检查...");
    LogMessage(L"[*] 规则文件路径: " + rulesPath);
    std::wstring dataDirectory = GetHostGuardDataDirectory();
    if (!dataDirectory.empty()) {
        LogMessage(L"[*] 预期数据目录: " + dataDirectory);
    }

    if (!loadSucceeded) {
        if (IsFileExists(rulesPath)) {
            LogMessage(L"[!] rules.json 存在但解析失败: " + loadError);
        }
        else {
            LogMessage(L"[!] 未找到可用的 rules.json。");
        }
    }
    else {
        LogConfigSummary(pendingConfig);
    }

    DWORD hostGuardServiceState = SERVICE_STOPPED;
    bool hostGuardServiceExists = false;
    if (QueryWin32ServiceState(kHostGuardServiceName, hostGuardServiceState, hostGuardServiceExists)) {
        if (hostGuardServiceExists) {
            LogMessage(L"[+] HostGuard 服务状态: " + ServiceStateToString(hostGuardServiceState));
        }
        else {
            LogMessage(L"[!] HostGuard 服务不存在: " + std::wstring(kHostGuardServiceName));
        }
    }

    DWORD driverServiceState = SERVICE_STOPPED;
    bool driverServiceExists = false;
    if (QueryKernelDriverServiceState(kDriverServiceName, driverServiceState, driverServiceExists)) {
        if (driverServiceExists) {
            LogMessage(L"[+] 驱动服务状态: " + ServiceStateToString(driverServiceState));
        }
        else {
            LogMessage(L"[!] 驱动服务不存在: " + std::wstring(kDriverServiceName));
        }
    }

    std::wstring localDriverPath = FindLocalDriverPath();
    if (!localDriverPath.empty()) {
        LogMessage(L"[+] 当前目录驱动文件: " + localDriverPath);
    }
    else {
        LogMessage(L"[!] 当前目录未找到 PebMonitor.sys 或 DriverModule.sys。");
    }

    HANDLE hDevice = OpenDriverDevice();
    if (hDevice == INVALID_HANDLE_VALUE) {
        LogMessage(L"[!] 当前无法连接驱动设备，错误码: " + std::to_wstring(GetLastError()));
        return 0;
    }

    QueryAndLogDriverStatus(hDevice);
    CloseHandle(hDevice);
    return 0;
}

static int RunInstallServiceCommand() {
    std::wstring exePath = GetCurrentExePath();
    if (exePath.empty()) {
        std::wcerr << L"[-] 错误：无法获取当前可执行文件路径。" << std::endl;
        return 1;
    }

    std::wstring binaryPath = L"\"" + exePath + L"\"";
    if (!InstallWin32Service(
        kHostGuardServiceName,
        kHostGuardDisplayName,
        binaryPath,
        SERVICE_AUTO_START)) {
        return 1;
    }

    std::wcout << L"[+] HostGuard 服务安装成功: " << kHostGuardServiceName << std::endl;
    return 0;
}

static int RunStartServiceCommand() {
    if (!StartWin32Service(kHostGuardServiceName)) {
        return 1;
    }

    std::wcout << L"[+] HostGuard 服务已启动。" << std::endl;
    return 0;
}

static int RunStopServiceCommand() {
    if (!StopWin32Service(kHostGuardServiceName)) {
        return 1;
    }

    std::wcout << L"[+] HostGuard 服务已停止。" << std::endl;
    return 0;
}

static int RunUninstallServiceCommand() {
    if (!RemoveWin32Service(kHostGuardServiceName)) {
        return 1;
    }

    std::wcout << L"[+] HostGuard 服务已卸载。" << std::endl;
    return 0;
}

static bool ApplyDriverRules(HANDLE hDevice, const RuleConfiguration& config) {
    if (!ClearDriverRules(hDevice)) {
        LogMessage(L"[!] 警告：清空驱动黑名单失败，继续尝试下发配置中的规则。");
    }

    bool allSucceeded = true;
    for (std::vector<std::wstring>::const_iterator it = config.driverBlacklist.begin();
        it != config.driverBlacklist.end();
        ++it) {
        const std::wstring& driver = *it;
        if (AddDriverRule(hDevice, driver)) {
            LogMessage(L"[+] 成功下发驱动黑名单规则: " + driver);
        }
        else {
            allSucceeded = false;
        }
    }

    LogMessage(L"[+] 已同步驱动黑名单规则数量: " + std::to_wstring(config.driverBlacklist.size()));
    return allSucceeded;
}

static bool ApplyFileRules(HANDLE hDevice, const RuleConfiguration& config) {
    if (!ClearFileRules(hDevice)) {
        LogMessage(L"[!] 警告：清空驱动文件规则失败，继续尝试下发配置中的规则。");
    }

    bool allSucceeded = true;
    for (std::vector<FILE_RULE>::const_iterator it = config.fileRules.begin();
        it != config.fileRules.end();
        ++it) {
        if (!AddFileRule(hDevice, *it)) {
            allSucceeded = false;
        }
    }

    LogMessage(L"[+] 已同步文件拦截规则数量: " + std::to_wstring(config.fileRules.size()));
    return allSucceeded;
}

static bool ApplyRegistryRules(HANDLE hDevice, const RuleConfiguration& config) {
    if (!ClearRegistryRules(hDevice)) {
        LogMessage(L"[!] 警告：清空驱动注册表规则失败，继续尝试下发配置中的规则。");
    }

    if (!ClearRegistryAllowRules(hDevice)) {
        LogMessage(L"[!] 警告：清空驱动注册表白名单失败，继续尝试下发配置中的规则。");
    }

    bool allSucceeded = true;
    for (std::vector<REGISTRY_RULE>::const_iterator it = config.registryRules.begin();
        it != config.registryRules.end();
        ++it) {
        if (!AddRegistryRule(hDevice, *it)) {
            allSucceeded = false;
        }
    }

    for (std::vector<REGISTRY_RULE>::const_iterator it = config.registryAllowRules.begin();
        it != config.registryAllowRules.end();
        ++it) {
        if (!AddRegistryAllowRule(hDevice, *it)) {
            allSucceeded = false;
        }
    }

    LogMessage(L"[+] 已同步注册表拦截规则数量: " + std::to_wstring(config.registryRules.size()));
    LogMessage(L"[+] 已同步注册表白名单规则数量: " + std::to_wstring(config.registryAllowRules.size()));
    return allSucceeded;
}

static bool SyncDriverConfigInfo(HANDLE hDevice, const RuleConfiguration& config) {
    if (!SetActiveDriverConfigInfo(hDevice, config.configVersion, config.profileName, config.generatedAt)) {
        LogMessage(L"[!] 警告：驱动配置版本同步失败。");
        return false;
    }

    return true;
}

static bool ApplyKernelRules(HANDLE hDevice, const RuleConfiguration& config) {
    bool driverRulesOk = ApplyDriverRules(hDevice, config);
    bool fileRulesOk = ApplyFileRules(hDevice, config);
    bool registryRulesOk = ApplyRegistryRules(hDevice, config);
    bool configInfoOk = SyncDriverConfigInfo(hDevice, config);

    if (driverRulesOk && fileRulesOk && registryRulesOk && configInfoOk) {
        QueryAndLogDriverStatus(hDevice);
    }

    return driverRulesOk && fileRulesOk && registryRulesOk && configInfoOk;
}

static bool ApplyKernelRules(HANDLE hDevice) {
    RuleConfiguration activeConfig = g_RuleManager.GetRuleConfigurationSnapshot();
    return ApplyKernelRules(hDevice, activeConfig);
}

static bool ApplyKernelRulesWithFreshHandle(const RuleConfiguration& config) {
    HANDLE hDevice = OpenDriverDevice();
    if (hDevice == INVALID_HANDLE_VALUE) {
        LogMessage(L"[!] 当前无法连接驱动设备，内核拦截规则更新将延迟到下次连接恢复后再同步。");
        return false;
    }

    bool success = ApplyKernelRules(hDevice, config);
    CloseHandle(hDevice);
    return success;
}

static bool ReloadRulesFromDisk(
    const std::wstring& rulesPath,
    bool applyDriverRulesAfterLoad,
    bool isHotReload = false) {
    const RuleConfiguration previousConfig = g_RuleManager.GetRuleConfigurationSnapshot();

    if (isHotReload) {
        json startEvent = BuildBaseJsonEvent("config_reload_started", "info", previousConfig);
        startEvent["action"] = "reload";
        startEvent["result"] = "started";
        startEvent["trigger"] = "rules_file_changed";
        startEvent["rules_path"] = WStringToUtf8(rulesPath);
        AppendPrefixedConfigFields(startEvent, previousConfig, "previous_");
        EmitJsonEvent(startEvent);
    }

    RuleConfiguration pendingConfig;
    std::wstring loadError;
    if (!g_RuleManager.TryLoadRulesFromJson(rulesPath, pendingConfig, &loadError)) {
        if (!loadError.empty()) {
            LogMessage(L"[!] rules.json 解析失败: " + loadError);
        }

        if (isHotReload) {
            LogMessage(L"[!] rules.json 热更新解析失败，已回滚并继续保留旧配置: " + DescribeConfigIdentity(previousConfig));

            json rollbackEvent = BuildBaseJsonEvent("config_reload_rollback", "warn", previousConfig);
            rollbackEvent["action"] = "reload";
            rollbackEvent["result"] = "rollback_retained";
            rollbackEvent["reload_stage"] = "parse";
            rollbackEvent["rules_path"] = WStringToUtf8(rulesPath);
            rollbackEvent["error"] = WStringToUtf8(loadError.empty() ? L"unknown_parse_error" : loadError);
            AppendPrefixedConfigFields(rollbackEvent, previousConfig, "previous_");
            EmitJsonEvent(rollbackEvent);
        }

        return false;
    }

    if (applyDriverRulesAfterLoad && !ApplyKernelRulesWithFreshHandle(pendingConfig)) {
        if (isHotReload) {
            LogMessage(L"[!] rules.json 热更新内核同步失败，已回滚并继续保留旧配置: " + DescribeConfigIdentity(previousConfig));
            LogMessage(L"    └─ 候选配置: " + DescribeConfigIdentity(pendingConfig));

            json rollbackEvent = BuildBaseJsonEvent("config_reload_rollback", "warn", previousConfig);
            rollbackEvent["action"] = "reload";
            rollbackEvent["result"] = "rollback_retained";
            rollbackEvent["reload_stage"] = "kernel_sync";
            rollbackEvent["rules_path"] = WStringToUtf8(rulesPath);
            rollbackEvent["error"] = "kernel_rule_sync_failed";
            AppendPrefixedConfigFields(rollbackEvent, previousConfig, "previous_");
            AppendPrefixedConfigFields(rollbackEvent, pendingConfig, "candidate_");
            EmitJsonEvent(rollbackEvent);
        }
        else {
            LogMessage(L"[!] 候选配置未能成功同步到驱动，继续保留旧版本配置。");
        }

        return false;
    }

    g_RuleManager.ApplyLoadedRules(std::move(pendingConfig));
    RuleConfiguration activeConfig = g_RuleManager.GetRuleConfigurationSnapshot();
    SetLogRuleContext(activeConfig.profileName, activeConfig.configVersion, activeConfig.generatedAt);

    if (isHotReload && HasConfigIdentityChanged(previousConfig, activeConfig)) {
        LogMessage(L"[+] 规则版本变更: " + DescribeConfigIdentity(previousConfig) + L" -> " + DescribeConfigIdentity(activeConfig));

        json versionChangedEvent = BuildBaseJsonEvent("config_version_changed", "info", activeConfig);
        versionChangedEvent["action"] = "reload";
        versionChangedEvent["result"] = "updated";
        versionChangedEvent["rules_path"] = WStringToUtf8(rulesPath);
        AppendPrefixedConfigFields(versionChangedEvent, previousConfig, "previous_");
        AppendPrefixedConfigFields(versionChangedEvent, activeConfig, "new_");
        EmitJsonEvent(versionChangedEvent);
    }

    LogConfigSummary(activeConfig);

    json configEvent = BuildBaseJsonEvent("config_applied", "info", activeConfig);
    configEvent["action"] = isHotReload ? "reload" : "load";
    configEvent["result"] = "success";
    configEvent["load_mode"] = isHotReload ? "hot_reload" : "initial";
    configEvent["process_rule_count"] = activeConfig.processRules.size();
    configEvent["process_allow_rule_count"] = activeConfig.processAllowRules.size();
    configEvent["file_rule_count"] = activeConfig.fileRules.size();
    configEvent["registry_rule_count"] = activeConfig.registryRules.size();
    configEvent["registry_allow_rule_count"] = activeConfig.registryAllowRules.size();
    configEvent["driver_blacklist_count"] = activeConfig.driverBlacklist.size();
    if (isHotReload) {
        AppendPrefixedConfigFields(configEvent, previousConfig, "previous_");
    }
    EmitJsonEvent(configEvent);
    return true;
}

static bool ReconnectMainDevice(HANDLE& hDevice) {
    CloseTrackedHandle(hDevice, g_MainDeviceHandle);

    for (int attempt = 1; attempt <= 5; ++attempt) {
        if (WaitForShutdown(1000)) {
            return false;
        }

        hDevice = OpenDriverDevice();
        if (hDevice != INVALID_HANDLE_VALUE) {
            TrackDeviceHandle(g_MainDeviceHandle, hDevice);
            LogMessage(L"[+] 驱动通信已恢复，重新下发配置中的内核拦截规则。");
            if (ApplyKernelRules(hDevice)) {
                return true;
            }

            LogMessage(L"[!] 驱动已重连，但内核规则重新同步失败，将继续重试。");
            CloseTrackedHandle(hDevice, g_MainDeviceHandle);
        }
    }

    if (IsShutdownRequested()) {
        return false;
    }

    LogMessage(L"[-] 多次尝试后仍无法重新连接驱动设备。程序将退出。");
    return false;
}

void RulesHotReloadThread(std::wstring rulesPath) {
    FileState lastState;
    QueryFileState(rulesPath, lastState);

    while (!WaitForShutdown(2000)) {
        FileState currentState;
        QueryFileState(rulesPath, currentState);
        if (IsSameFileState(lastState, currentState)) {
            continue;
        }

        lastState = currentState;
        if (!currentState.exists) {
            RuleConfiguration activeConfig = g_RuleManager.GetRuleConfigurationSnapshot();
            LogMessage(L"[!] 检测到 rules.json 被删除，继续保留当前已生效配置: " + DescribeConfigIdentity(activeConfig));

            json rollbackEvent = BuildBaseJsonEvent("config_reload_rollback", "warn", activeConfig);
            rollbackEvent["action"] = "reload";
            rollbackEvent["result"] = "rollback_retained";
            rollbackEvent["reload_stage"] = "file_missing";
            rollbackEvent["rules_path"] = WStringToUtf8(rulesPath);
            rollbackEvent["error"] = "rules_file_deleted";
            AppendPrefixedConfigFields(rollbackEvent, activeConfig, "previous_");
            EmitJsonEvent(rollbackEvent);
            continue;
        }

        LogMessage(L"[*] 检测到 rules.json 变化，开始热更新配置。");
        if (ReloadRulesFromDisk(rulesPath, true, true)) {
            LogMessage(L"[+] rules.json 热更新成功。");
        }
        else {
            LogMessage(L"[!] rules.json 热更新失败，继续保留旧配置。");
        }
    }
}

void DriverEventMonitorThread() {
    while (!IsShutdownRequested()) {
        HANDLE hDriverDevice = OpenDriverDevice();
        if (hDriverDevice == INVALID_HANDLE_VALUE) {
            LogMessage(L"[-] 驱动遥测通道连接失败，1 秒后重试。");
            if (WaitForShutdown(1000)) {
                break;
            }
            continue;
        }

        TrackDeviceHandle(g_DriverEventDeviceHandle, hDriverDevice);
        DRIVER_EVENT driverEvent = { 0 };
        DWORD bytesReturned = 0;
        LogMessage(L"[+] 驱动防御遥测通道已开启，正在监听底层拦截事件...");

        while (!IsShutdownRequested()) {
            BOOL success = DeviceIoControl(hDriverDevice, IOCTL_GET_DRIVER_EVENT,
                NULL, 0, &driverEvent, sizeof(DRIVER_EVENT), &bytesReturned, NULL);

            if (success && bytesReturned == sizeof(DRIVER_EVENT)) {
                std::wstring targetPath(driverEvent.TargetPath);
                std::wstring processName(driverEvent.ProcessName);
                std::wstring ruleId(driverEvent.RuleId);
                std::wstring infoClass(driverEvent.InfoClass);
                std::wstring valueName(driverEvent.ValueName);
                std::wstring valueData(driverEvent.ValueData);
                std::wstring threatDesc;
                int severity = static_cast<int>(driverEvent.Severity);
                std::wstring registryOperation = RegistryOperationToString(driverEvent.RegistryOperation);
                std::wstring fileOperation = FileOperationToString(driverEvent.FileOperation);

                if (driverEvent.EventType == DRIVER_EVENT_TYPE_BLOCKED_FILE_OPERATION && !ruleId.empty()) {
                    int configuredSeverity = 0;
                    if (g_RuleManager.TryGetFileRuleMetadata(ruleId, threatDesc, configuredSeverity) &&
                        severity == 0) {
                        severity = configuredSeverity;
                    }
                }
                else if (!ruleId.empty()) {
                    int configuredSeverity = 0;
                    if (g_RuleManager.TryGetRegistryRuleMetadata(ruleId, threatDesc, configuredSeverity) &&
                        severity == 0) {
                        severity = configuredSeverity;
                    }
                }

                LogMessage(L"#########################################################");
                if (driverEvent.EventType == DRIVER_EVENT_TYPE_BLOCKED_SERVICE) {
                    LogMessage(L"[!] 已在驱动服务注册阶段阻止高危驱动。");
                    LogMessage(L"    └─ 目标驱动: " + targetPath);
                }
                else if (driverEvent.EventType == DRIVER_EVENT_TYPE_BLOCKED_FILE_OPERATION) {
                    LogMessage(L"[!] 已在文件创建/写入阶段阻止高危文件落地。");
                    LogMessage(L"    └─ 操作类型: " + fileOperation);
                    if (!ruleId.empty()) {
                        LogMessage(L"    └─ 规则 ID: " + ruleId);
                    }
                    if (!threatDesc.empty()) {
                        LogMessage(L"    └─ 威胁描述: " + threatDesc);
                    }
                    if (severity > 0) {
                        LogMessage(L"    └─ Severity: " + std::to_wstring(severity));
                    }
                    if (!processName.empty()) {
                        LogMessage(L"    └─ 发起进程: " + processName + L" (PID: " + std::to_wstring(driverEvent.ProcessId) + L")");
                    }
                    if (!targetPath.empty()) {
                        LogMessage(L"    └─ 目标文件: " + targetPath);
                    }
                    if (!valueData.empty()) {
                        LogMessage(L"    └─ 文件扩展名: " + valueData);
                    }
                }
                else if (driverEvent.EventType == DRIVER_EVENT_TYPE_BLOCKED_REGISTRY_OPERATION) {
                    LogMessage(L"[!] 已在注册表操作阶段阻止高危修改。");
                    LogMessage(L"    └─ 操作类型: " + registryOperation);
                    if (!ruleId.empty()) {
                        LogMessage(L"    └─ 规则 ID: " + ruleId);
                    }
                    if (!threatDesc.empty()) {
                        LogMessage(L"    └─ 威胁描述: " + threatDesc);
                    }
                    if (severity > 0) {
                        LogMessage(L"    └─ Severity: " + std::to_wstring(severity));
                    }
                    if (!processName.empty()) {
                        LogMessage(L"    └─ 发起进程: " + processName + L" (PID: " + std::to_wstring(driverEvent.ProcessId) + L")");
                    }
                    LogMessage(L"    └─ 注册表路径: " + targetPath);
                    if (!infoClass.empty()) {
                        LogMessage(L"    └─ InfoClass: " + infoClass);
                    }
                    if (!valueName.empty()) {
                        LogMessage(L"    └─ 值名称: " + valueName);
                    }
                    if (!valueData.empty()) {
                        if (driverEvent.RegistryOperation == REGISTRY_OPERATION_RENAME_KEY) {
                            LogMessage(L"    └─ 新名称: " + valueData);
                        }
                        else {
                            LogMessage(L"    └─ 值数据: " + valueData);
                        }
                    }
                }
                else {
                    LogMessage(L"[!] 发现高危驱动加载告警（该事件不表示已阻断）。");
                    LogMessage(L"    └─ 目标驱动: " + targetPath);
                }

                json driverEventJson = BuildBaseJsonEvent("driver_event", "warn");
                driverEventJson["driver_event_type"] = driverEvent.EventType;
                driverEventJson["process_id"] = driverEvent.ProcessId;
                driverEventJson["severity"] = severity;
                if (driverEvent.EventType == DRIVER_EVENT_TYPE_BLOCKED_FILE_OPERATION) {
                    driverEventJson["file_operation"] = WStringToUtf8(fileOperation);
                }
                else {
                    driverEventJson["registry_operation"] = WStringToUtf8(registryOperation);
                }
                if (!processName.empty()) {
                    driverEventJson["process_name"] = WStringToUtf8(processName);
                }
                if (!ruleId.empty()) {
                    driverEventJson["rule_id"] = WStringToUtf8(ruleId);
                }
                if (!threatDesc.empty()) {
                    driverEventJson["threat_desc"] = WStringToUtf8(threatDesc);
                }
                if (!targetPath.empty()) {
                    driverEventJson["target_path"] = WStringToUtf8(targetPath);
                }
                if (!infoClass.empty()) {
                    driverEventJson["info_class"] = WStringToUtf8(infoClass);
                }
                if (!valueName.empty()) {
                    driverEventJson["value_name"] = WStringToUtf8(valueName);
                }
                if (!valueData.empty()) {
                    if (driverEvent.EventType == DRIVER_EVENT_TYPE_BLOCKED_FILE_OPERATION) {
                        driverEventJson["file_extension"] = WStringToUtf8(valueData);
                    }
                    else if (driverEvent.RegistryOperation == REGISTRY_OPERATION_RENAME_KEY) {
                        driverEventJson["new_name"] = WStringToUtf8(valueData);
                    }
                    else {
                        driverEventJson["value_data"] = WStringToUtf8(valueData);
                    }
                }
                EmitJsonEvent(driverEventJson);

                LogMessage(L"#########################################################");
            }
            else {
                DWORD err = GetLastError();
                if (!IsShutdownRequested() && err != ERROR_OPERATION_ABORTED && err != ERROR_INVALID_HANDLE) {
                    LogMessage(L"[!] 驱动遥测通道异常断开，错误码: " + std::to_wstring(err));
                }
                break;
            }
        }

        CloseTrackedHandle(hDriverDevice, g_DriverEventDeviceHandle);
    }
}

static int RunProtectionEngine(bool serviceMode) {
    if (!serviceMode && !IsRunAsAdmin()) {
        std::wcout << L"[-] 致命错误：必须以【管理员身份】运行此防御系统！" << std::endl;
        std::wcout << L"    请右键点击 exe，选择“以管理员身份运行”。" << std::endl;
        system("pause");
        return 1;
    }

    if (!EnsureRuntimeEvents()) {
        std::wcerr << L"[-] 致命错误：初始化退出同步对象失败 (错误码: " << GetLastError() << L")" << std::endl;
        CleanupRuntimeEvents();
        if (!serviceMode) {
            system("pause");
        }
        return 1;
    }

    if (!serviceMode) {
        if (!SetConsoleCtrlHandler(ConsoleCtrlHandler, TRUE)) {
            std::wcerr << L"[!] 警告：注册控制台退出处理器失败 (错误码: " << GetLastError() << L")，关闭窗口时可能无法自动卸载驱动。" << std::endl;
        }

        HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
        DWORD mode = 0;
        if (GetConsoleMode(hStdin, &mode)) {
            mode &= ~ENABLE_QUICK_EDIT_MODE;
            mode &= ~ENABLE_INSERT_MODE;
            SetConsoleMode(hStdin, mode);
        }
    }

    HANDLE hDevice = INVALID_HANDLE_VALUE;
    std::thread driverThread;
    std::thread ruleReloadThread;
    int exitCode = 0;
    PROCESS_EVENT eventBuffer = { 0 };
    DWORD bytesReturned = 0;
    std::wstring rulesPath = ResolveRulesFilePath();

    LogMessage(serviceMode ? L"[*] HostGuard 服务模式启动中..." : L"[*] 正在初始化 HostGuard 终端防御系统...");
    LogMessage(L"[*] 当前工作目录: " + g_ExeDirectory);
    LogMessage(L"[*] 探测到操作系统架构: " + std::wstring(Is64BitOS() ? L"x64" : L"x86"));
    LogMessage(L"[*] 当前规则文件路径: " + rulesPath);

    if (!ReloadRulesFromDisk(rulesPath, false)) {
        LogMessage(L"[!] 警告: 未能成功加载 JSON 规则库或文件不存在，将以空规则模式运行。");
    }

    std::wstring driverPath = FindLocalDriverPath();
    if (!driverPath.empty()) {
        LogMessage(L"[*] 当前目录发现驱动文件: " + driverPath);
        LogMessage(L"[*] 正在向内核注册 PebMonitor 服务...");
        if (LoadKernelDriver(driverPath, kDriverServiceName)) {
            LogMessage(L"[+] 内核驱动加载成功，雷达已上线。");
        }
        else {
            LogMessage(L"[!] 驱动加载尝试失败，将继续尝试连接已加载的驱动设备。");
        }
    }
    else {
        LogMessage(L"[!] 当前目录未找到 PebMonitor.sys 或 DriverModule.sys，跳过驱动加载步骤。");
    }

    hDevice = OpenDriverDevice();
    if (hDevice == INVALID_HANDLE_VALUE) {
        LogMessage(L"[!] 无法连接驱动通信端口。请确认驱动已加载，或将 PebMonitor.sys / DriverModule.sys 放在当前目录后重试。");
        exitCode = 1;
        goto Cleanup;
    }
    TrackDeviceHandle(g_MainDeviceHandle, hDevice);

    if (!ApplyKernelRules(hDevice)) {
        LogMessage(L"[!] 警告：初始内核规则同步未完全成功，程序将继续运行并在后续重连时重试。");
    }

    driverThread = std::thread(DriverEventMonitorThread);
    ruleReloadThread = std::thread(RulesHotReloadThread, rulesPath);

    LogMessage(L"[+] HostGuard 主引擎启动完毕，开始实时进程研判...");

    while (!IsShutdownRequested()) {
        BOOL success = DeviceIoControl(hDevice, IOCTL_GET_PROCESS_EVENT,
            NULL, 0, &eventBuffer, sizeof(PROCESS_EVENT), &bytesReturned, NULL);

        if (success && bytesReturned == sizeof(PROCESS_EVENT)) {
            std::wstring parentName = GetProcessNameByPid(eventBuffer.ParentProcessId);
            std::wstring childName = GetProcessNameByPid(eventBuffer.ProcessId);
            std::wstring cmdLine(eventBuffer.CommandLine);
            if (childName == L"<unknown>") {
                childName = GetCachedProcessName(eventBuffer.ProcessId);
            }
            if (parentName == L"<unknown>") {
                parentName = GetCachedProcessName(eventBuffer.ParentProcessId);
            }

            CacheProcessContext(eventBuffer.ProcessId, childName, cmdLine);

            std::wstring parentCmdLine = GetCachedProcessCommandLine(eventBuffer.ParentProcessId);

            PROCESS_VERDICT verdict = { 0 };
            verdict.ProcessId = eventBuffer.ProcessId;
            verdict.BlockProcess = FALSE;

            DetectionRule matchedAllowRule;
            if (g_RuleManager.TryMatchProcessAllowRule(parentName, childName, cmdLine, parentCmdLine, matchedAllowRule)) {
                LogMessage(L"[+] 命中进程白名单，跳过拦截。");
                LogMessage(L"    └─ 白名单 ID: " + matchedAllowRule.id);
                LogMessage(L"    └─ 父进程名: " + parentName);
                LogMessage(L"    └─ 子进程名: " + childName);
                if (!parentCmdLine.empty()) {
                    LogMessage(L"    └─ 父进程命令行: " + parentCmdLine);
                }
                LogMessage(L"    └─ 命令行: " + cmdLine);

                json allowEvent = BuildBaseJsonEvent("process_allow", "info");
                allowEvent["rule_id"] = WStringToUtf8(matchedAllowRule.id);
                allowEvent["severity"] = matchedAllowRule.severity;
                allowEvent["parent_name"] = WStringToUtf8(parentName);
                allowEvent["child_name"] = WStringToUtf8(childName);
                allowEvent["command_line"] = WStringToUtf8(cmdLine);
                if (!parentCmdLine.empty()) {
                    allowEvent["parent_command_line"] = WStringToUtf8(parentCmdLine);
                }
                EmitJsonEvent(allowEvent);
            }
            else {
                DetectionRule matchedRule;
                if (g_RuleManager.EvaluateProcessAgainstRules(parentName, childName, cmdLine, parentCmdLine, matchedRule)) {
                    LogMessage(L"[!] ==================================================");
                    LogMessage(L"[!] 触发规则 ID: " + matchedRule.id);
                    LogMessage(L"[!] 威胁描述: " + matchedRule.threatDesc);
                    LogMessage(L"[!] 父进程名: " + parentName);
                    LogMessage(L"[!] 子进程名: " + childName);
                    if (!parentCmdLine.empty()) {
                        LogMessage(L"[!] 父进程命令行: " + parentCmdLine);
                    }
                    LogMessage(L"[!] 命中的命令行: " + cmdLine);
                    LogMessage(L"[!] 执行动作: 拦截 (Severity: " + std::to_wstring(matchedRule.severity) + L")");
                    LogMessage(L"[!] ==================================================");

                    json blockEvent = BuildBaseJsonEvent("process_block", "warn");
                    blockEvent["rule_id"] = WStringToUtf8(matchedRule.id);
                    blockEvent["threat_desc"] = WStringToUtf8(matchedRule.threatDesc);
                    blockEvent["severity"] = matchedRule.severity;
                    blockEvent["parent_name"] = WStringToUtf8(parentName);
                    blockEvent["child_name"] = WStringToUtf8(childName);
                    blockEvent["command_line"] = WStringToUtf8(cmdLine);
                    if (!parentCmdLine.empty()) {
                        blockEvent["parent_command_line"] = WStringToUtf8(parentCmdLine);
                    }
                    EmitJsonEvent(blockEvent);

                    verdict.BlockProcess = TRUE;
                }
            }

            if (!DeviceIoControl(hDevice, IOCTL_SEND_VERDICT,
                &verdict, sizeof(PROCESS_VERDICT),
                NULL, 0, &bytesReturned, NULL)) {
                DWORD err = GetLastError();
                if (IsShutdownRequested() && (err == ERROR_OPERATION_ABORTED || err == ERROR_INVALID_HANDLE)) {
                    break;
                }
                LogMessage(L"[!] 向驱动发送判决失败，错误码: " + std::to_wstring(err));
                if (!ReconnectMainDevice(hDevice)) {
                    exitCode = IsShutdownRequested() ? 0 : 1;
                    break;
                }
            }
        }
        else {
            DWORD err = GetLastError();
            if (IsShutdownRequested() && (err == ERROR_OPERATION_ABORTED || err == ERROR_INVALID_HANDLE)) {
                break;
            }
            LogMessage(L"[!] 获取进程事件失败，错误码: " + std::to_wstring(err));
            if (!ReconnectMainDevice(hDevice)) {
                exitCode = IsShutdownRequested() ? 0 : 1;
                break;
            }
        }
    }

Cleanup:
    RequestShutdown();
    CloseTrackedHandle(hDevice, g_MainDeviceHandle);

    if (ruleReloadThread.joinable()) {
        ruleReloadThread.join();
    }
    if (driverThread.joinable()) {
        driverThread.join();
    }

    LogMessage(L"[*] 正在停止并卸载 PebMonitor 驱动服务...");
    if (UnloadKernelDriver(kDriverServiceName)) {
        LogMessage(L"[+] PebMonitor 驱动已停止并卸载。");
    }
    else {
        LogMessage(L"[!] PebMonitor 驱动停止或卸载失败，请检查服务状态。");
        if (exitCode == 0) {
            exitCode = 1;
        }
    }

    if (g_ShutdownCompleteEvent != NULL) {
        SetEvent(g_ShutdownCompleteEvent);
    }
    if (!serviceMode) {
        SetConsoleCtrlHandler(ConsoleCtrlHandler, FALSE);
    }

    CleanupRuntimeEvents();
    return exitCode;
}

static VOID WINAPI HostGuardServiceMain(DWORD argc, LPWSTR* argv) {
    UNREFERENCED_PARAMETER(argc);
    UNREFERENCED_PARAMETER(argv);

    g_IsServiceMode = true;
    ZeroMemory(&g_ServiceStatus, sizeof(g_ServiceStatus));
    g_ServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;

    g_ServiceStatusHandle = RegisterServiceCtrlHandlerExW(
        kHostGuardServiceName,
        ServiceControlHandlerEx,
        NULL);
    if (g_ServiceStatusHandle == NULL) {
        g_IsServiceMode = false;
        return;
    }

    ReportServiceStatus(SERVICE_START_PENDING, NO_ERROR, 15000);
    ReportServiceStatus(SERVICE_RUNNING, NO_ERROR, 0);

    int exitCode = RunProtectionEngine(true);
    ReportServiceStatus(SERVICE_STOPPED, exitCode == 0 ? NO_ERROR : static_cast<DWORD>(exitCode), 0);

    g_ServiceStatusHandle = NULL;
    g_IsServiceMode = false;
}

static bool TryRunAsService(int& outExitCode) {
    SERVICE_TABLE_ENTRYW serviceTable[] = {
        { const_cast<LPWSTR>(kHostGuardServiceName), HostGuardServiceMain },
        { NULL, NULL }
    };

    if (StartServiceCtrlDispatcherW(serviceTable)) {
        outExitCode = 0;
        return true;
    }

    DWORD err = GetLastError();
    if (err == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT) {
        return false;
    }

    std::wcerr << L"[-] 错误：连接服务控制管理器失败 (错误码: " << err << L")" << std::endl;
    outExitCode = 1;
    return true;
}

int wmain(int argc, wchar_t* argv[]) {
    setlocale(LC_ALL, "");

    g_ExeDirectory = GetExeDirectory();
    std::wstring rulesPath = ResolveRulesFilePath();

    if (argc > 1) {
        if (_wcsicmp(argv[1], L"install") == 0) {
            return RunInstallServiceCommand();
        }

        if (_wcsicmp(argv[1], L"start") == 0) {
            return RunStartServiceCommand();
        }

        if (_wcsicmp(argv[1], L"stop") == 0) {
            return RunStopServiceCommand();
        }

        if (_wcsicmp(argv[1], L"uninstall") == 0 || _wcsicmp(argv[1], L"remove") == 0) {
            return RunUninstallServiceCommand();
        }

        if (_wcsicmp(argv[1], L"status") == 0 || _wcsicmp(argv[1], L"--status") == 0) {
            return RunStatusCommand(rulesPath);
        }

        if (_wcsicmp(argv[1], L"help") == 0 || _wcsicmp(argv[1], L"--help") == 0 || _wcsicmp(argv[1], L"/?") == 0) {
            std::wcout << L"Usage:" << std::endl;
            std::wcout << L"  HostGuard.exe              启动实时防护或由 SCM 拉起服务" << std::endl;
            std::wcout << L"  HostGuard.exe install      安装 HostGuard 服务" << std::endl;
            std::wcout << L"  HostGuard.exe start        启动 HostGuard 服务" << std::endl;
            std::wcout << L"  HostGuard.exe stop         停止 HostGuard 服务" << std::endl;
            std::wcout << L"  HostGuard.exe uninstall    卸载 HostGuard 服务" << std::endl;
            std::wcout << L"  HostGuard.exe status       查看规则和驱动状态" << std::endl;
            return 0;
        }
    }

    int serviceExitCode = 0;
    if (TryRunAsService(serviceExitCode)) {
        return serviceExitCode;
    }

    return RunProtectionEngine(false);
}
