#pragma once
#include <mutex>
#include <regex>
#include <string>
#include <vector>
#include "Shared.h"

struct RuleRegexGroup {
    bool enabled = false;
    std::vector<std::wstring> patternTexts;
    std::vector<std::wregex> patterns;
};

struct DetectionRule {
    std::wstring id;
    std::wstring threatDesc;
    int severity = 0;
    RuleRegexGroup parentProcessRules;
    RuleRegexGroup childProcessRules;
    RuleRegexGroup cmdLineRules;
    RuleRegexGroup parentCmdLineRules;
};

struct RegistryRuleField {
    bool enabled = false;
    ULONG matchType = REGISTRY_MATCH_TYPE_EXACT;
    std::vector<std::wstring> values;
};

struct RegistryRuleDefinition {
    std::wstring id;
    std::wstring threatDesc;
    int severity = 0;
    ULONG operation = REGISTRY_OPERATION_SET_VALUE;
    RegistryRuleField processNameRule;
    RegistryRuleField keyPathRule;
    RegistryRuleField infoClassRule;
    RegistryRuleField valueNameRule;
    RegistryRuleField valueDataRule;
};

// Keep HostGuard-side contains expansion aligned with the driver rule store limit.
#define MAX_REGISTRY_CONTAINS_RULES 16UL

struct RegistryRuleClassStats {
    ULONG totalRules = 0;
    ULONG exactRules = 0;
    ULONG prefixRules = 0;
    ULONG suffixRules = 0;
    ULONG containsRules = 0;
};

struct AutoResponseConfiguration {
    bool terminateOnRegistryBlock = false;
    int minSeverity = 0;
    ULONG cooldownMs = 5000;
};

struct RuleConfiguration {
    std::wstring sourcePath;
    std::wstring configVersion;
    std::wstring profileName;
    std::wstring generatedAt;
    ULONG processVerdictTimeoutMs = PROCESS_VERDICT_TIMEOUT_MS_DEFAULT;
    ULONG processVerdictFailMode = PROCESS_VERDICT_FAIL_OPEN;
    ULONG captureParentCommandLine = PROCESS_PARENT_CMDLINE_CAPTURE_DISABLED;
    AutoResponseConfiguration autoResponse;
    std::vector<DetectionRule> processRules;
    std::vector<DetectionRule> processAllowRules;
    std::vector<RegistryRuleDefinition> registryRuleDefinitions;
    std::vector<REGISTRY_RULE> registryRules;
    RegistryRuleClassStats registryRuleClassStats;
    std::vector<RegistryRuleDefinition> registryAllowRuleDefinitions;
    std::vector<REGISTRY_RULE> registryAllowRules;
    RegistryRuleClassStats registryAllowRuleClassStats;
};

class RuleManager {
public:
    RuleManager();
    ~RuleManager();

    bool LoadRulesFromJson(const std::wstring& jsonFilePath);
    bool TryLoadRulesFromJson(
        const std::wstring& jsonFilePath,
        RuleConfiguration& outConfig,
        std::wstring* outError = nullptr) const;
    void ApplyLoadedRules(RuleConfiguration&& loadedConfig);
    RuleConfiguration GetRuleConfigurationSnapshot() const;

    bool EvaluateProcessAgainstRules(
        const std::wstring& parentName,
        const std::wstring& childName,
        const std::wstring& cmdLine,
        const std::wstring& parentCmdLine,
        DetectionRule& outMatchedRule
    );
    bool TryMatchProcessAllowRule(
        const std::wstring& parentName,
        const std::wstring& childName,
        const std::wstring& cmdLine,
        const std::wstring& parentCmdLine,
        DetectionRule& outMatchedRule
    ) const;

    size_t GetRuleCount() const;
    size_t GetProcessAllowRuleCount() const;
    size_t GetRegistryRuleCount() const;
    size_t GetRegistryAllowRuleCount() const;
    std::vector<REGISTRY_RULE> GetRegistryRules() const;
    std::vector<REGISTRY_RULE> GetRegistryAllowRules() const;
    std::wstring GetConfigVersion() const;
    std::wstring GetProfileName() const;
    bool TryGetRegistryRuleMetadata(
        const std::wstring& ruleId,
        std::wstring& outThreatDesc,
        int& outSeverity
    ) const;

private:
    mutable std::mutex m_Lock;
    RuleConfiguration m_ActiveConfig;
};
