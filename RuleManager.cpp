#include "RuleManager.h"

#include <windows.h>

#include <algorithm>
#include <cctype>
#include <codecvt>
#include <cwctype>
#include <fstream>
#include <iostream>
#include <limits>
#include <sstream>
#include <utility>

#include <nlohmann/json.hpp>

using json = nlohmann::json;

namespace {
    std::wstring Utf8ToWStringLocal(const std::string& utf8Str) {
        if (utf8Str.empty()) {
            return std::wstring();
        }

        int sizeNeeded = MultiByteToWideChar(
            CP_UTF8,
            0,
            utf8Str.data(),
            static_cast<int>(utf8Str.size()),
            NULL,
            0);
        if (sizeNeeded <= 0) {
            return std::wstring();
        }

        std::wstring wstrTo(sizeNeeded, 0);
        int result = MultiByteToWideChar(
            CP_UTF8,
            0,
            utf8Str.data(),
            static_cast<int>(utf8Str.size()),
            &wstrTo[0],
            sizeNeeded);
        if (result == 0) {
            return std::wstring();
        }

        return wstrTo;
    }

    std::string ToLowerAscii(const std::string& value) {
        std::string lowered = value;
        std::transform(lowered.begin(), lowered.end(), lowered.begin(),
            [](unsigned char ch) {
                return static_cast<char>(std::tolower(ch));
            });
        return lowered;
    }

    bool TryMapProcessVerdictFailModeString(
        const std::string& value,
        ULONG& outMode) {
        const std::string lowered = ToLowerAscii(value);
        if (lowered == "fail_open" || lowered == "open" || lowered == "allow") {
            outMode = PROCESS_VERDICT_FAIL_OPEN;
            return true;
        }

        if (lowered == "fail_close" || lowered == "close" || lowered == "block") {
            outMode = PROCESS_VERDICT_FAIL_CLOSE;
            return true;
        }

        return false;
    }

    std::wstring TrimRuleText(const std::wstring& value) {
        size_t begin = 0;
        while (begin < value.size() && iswspace(value[begin])) {
            ++begin;
        }

        size_t end = value.size();
        while (end > begin && iswspace(value[end - 1])) {
            --end;
        }

        return value.substr(begin, end - begin);
    }

    std::wstring ToLowerWide(const std::wstring& value) {
        std::wstring lowered = value;
        std::transform(lowered.begin(), lowered.end(), lowered.begin(),
            [](wchar_t ch) {
                return static_cast<wchar_t>(towlower(ch));
            });
        return lowered;
    }

            bool TryParseFlexibleBoolean(const json& node, bool& outValue);

    bool ParseProcessVerdictConfig(
        const json& root,
        RuleConfiguration& outConfig,
        std::wstring* outError) {
        const json* verdictNode = nullptr;
        if (root.contains("process_verdict")) {
            if (!root["process_verdict"].is_object()) {
                if (outError != nullptr) {
                    *outError = L"process_verdict must be an object";
                }
                return false;
            }
            verdictNode = &root["process_verdict"];
        }

        const json* timeoutNode = nullptr;
        if (verdictNode != nullptr && verdictNode->contains("timeout_ms")) {
            timeoutNode = &(*verdictNode)["timeout_ms"];
        }
        else if (root.contains("process_verdict_timeout_ms")) {
            timeoutNode = &root["process_verdict_timeout_ms"];
        }

        if (timeoutNode != nullptr) {
            if (!timeoutNode->is_number_unsigned() && !timeoutNode->is_number_integer()) {
                if (outError != nullptr) {
                    *outError = L"process verdict timeout_ms must be an integer";
                }
                return false;
            }

            long long timeoutValue = timeoutNode->get<long long>();
            if (timeoutValue < static_cast<long long>(PROCESS_VERDICT_TIMEOUT_MS_MIN) ||
                timeoutValue > static_cast<long long>(PROCESS_VERDICT_TIMEOUT_MS_MAX)) {
                if (outError != nullptr) {
                    *outError =
                        L"process verdict timeout_ms out of range (" +
                        std::to_wstring(PROCESS_VERDICT_TIMEOUT_MS_MIN) +
                        L"-" +
                        std::to_wstring(PROCESS_VERDICT_TIMEOUT_MS_MAX) +
                        L")";
                }
                return false;
            }

            outConfig.processVerdictTimeoutMs = static_cast<ULONG>(timeoutValue);
        }

        const json* failModeNode = nullptr;
        if (verdictNode != nullptr && verdictNode->contains("fail_mode")) {
            failModeNode = &(*verdictNode)["fail_mode"];
        }
        else if (root.contains("process_verdict_fail_mode")) {
            failModeNode = &root["process_verdict_fail_mode"];
        }

        if (failModeNode != nullptr) {
            ULONG failMode = PROCESS_VERDICT_FAIL_OPEN;
            bool parsed = false;

            if (failModeNode->is_string()) {
                parsed = TryMapProcessVerdictFailModeString(
                    failModeNode->get<std::string>(),
                    failMode);
            }
            else if (failModeNode->is_number_unsigned() || failModeNode->is_number_integer()) {
                long long modeValue = failModeNode->get<long long>();
                if (modeValue == PROCESS_VERDICT_FAIL_OPEN || modeValue == PROCESS_VERDICT_FAIL_CLOSE) {
                    failMode = static_cast<ULONG>(modeValue);
                    parsed = true;
                }
            }

            if (!parsed) {
                if (outError != nullptr) {
                    *outError = L"process verdict fail_mode must be fail_open or fail_close";
                }
                return false;
            }

            outConfig.processVerdictFailMode = failMode;
        }

        const json* captureParentNode = nullptr;
        if (verdictNode != nullptr && verdictNode->contains("capture_parent_cmdline")) {
            captureParentNode = &(*verdictNode)["capture_parent_cmdline"];
        }
        else if (root.contains("capture_parent_cmdline")) {
            captureParentNode = &root["capture_parent_cmdline"];
        }

        if (captureParentNode != nullptr) {
            if (captureParentNode->is_boolean()) {
                outConfig.captureParentCommandLine =
                    captureParentNode->get<bool>()
                    ? PROCESS_PARENT_CMDLINE_CAPTURE_ENABLED
                    : PROCESS_PARENT_CMDLINE_CAPTURE_DISABLED;
            }
            else if (captureParentNode->is_number_unsigned() || captureParentNode->is_number_integer()) {
                long long raw = captureParentNode->get<long long>();
                outConfig.captureParentCommandLine =
                    (raw == PROCESS_PARENT_CMDLINE_CAPTURE_ENABLED)
                    ? PROCESS_PARENT_CMDLINE_CAPTURE_ENABLED
                    : PROCESS_PARENT_CMDLINE_CAPTURE_DISABLED;
            }
            else {
                if (outError != nullptr) {
                    *outError = L"capture_parent_cmdline must be boolean or 0/1";
                }
                return false;
            }
        }

        return true;
    }

        bool TryParseFlexibleBoolean(const json& node, bool& outValue) {
        if (node.is_boolean()) {
            outValue = node.get<bool>();
            return true;
        }

        if (node.is_number_unsigned() || node.is_number_integer()) {
            const long long rawValue = node.get<long long>();
            if (rawValue == 0 || rawValue == 1) {
                outValue = (rawValue == 1);
                return true;
            }
        }

        return false;
    }

    bool ParseAutoResponseConfig(
        const json& root,
        RuleConfiguration& outConfig,
        std::wstring* outError) {
        const json* responseNode = nullptr;
        if (root.contains("response")) {
            if (!root["response"].is_object()) {
                if (outError != nullptr) {
                    *outError = L"response must be an object";
                }
                return false;
            }

            responseNode = &root["response"];
        }

        const auto findNode = [&](const char* nestedName, const char* flatName) -> const json* {
            if (responseNode != nullptr && responseNode->contains(nestedName)) {
                return &(*responseNode)[nestedName];
            }
            if (flatName != nullptr && root.contains(flatName)) {
                return &root[flatName];
            }
            return nullptr;
        };

        const json* terminateOnRegistryNode =
            findNode("auto_terminate_on_registry_block", "auto_terminate_on_registry_block");
        if (terminateOnRegistryNode != nullptr &&
            !TryParseFlexibleBoolean(*terminateOnRegistryNode, outConfig.autoResponse.terminateOnRegistryBlock)) {
            if (outError != nullptr) {
                *outError = L"auto_terminate_on_registry_block must be boolean or 0/1";
            }
            return false;
        }

        const json* minSeverityNode =
            findNode("auto_terminate_min_severity", "auto_terminate_min_severity");
        if (minSeverityNode != nullptr) {
            if (!minSeverityNode->is_number_unsigned() && !minSeverityNode->is_number_integer()) {
                if (outError != nullptr) {
                    *outError = L"auto_terminate_min_severity must be an integer";
                }
                return false;
            }

            const long long rawSeverity = minSeverityNode->get<long long>();
            if (rawSeverity < 0 ||
                rawSeverity > static_cast<long long>((std::numeric_limits<int>::max)())) {
                if (outError != nullptr) {
                    *outError = L"auto_terminate_min_severity out of range";
                }
                return false;
            }

            outConfig.autoResponse.minSeverity = static_cast<int>(rawSeverity);
        }

        const json* cooldownNode =
            findNode("auto_terminate_cooldown_ms", "auto_terminate_cooldown_ms");
        if (cooldownNode != nullptr) {
            if (!cooldownNode->is_number_unsigned() && !cooldownNode->is_number_integer()) {
                if (outError != nullptr) {
                    *outError = L"auto_terminate_cooldown_ms must be an integer";
                }
                return false;
            }

            const long long rawCooldown = cooldownNode->get<long long>();
            if (rawCooldown < 0 ||
                rawCooldown > static_cast<long long>((std::numeric_limits<unsigned long>::max)())) {
                if (outError != nullptr) {
                    *outError = L"auto_terminate_cooldown_ms out of range";
                }
                return false;
            }

            outConfig.autoResponse.cooldownMs = static_cast<ULONG>(rawCooldown);
        }

        return true;
    }

    RuleRegexGroup* GetRuleGroupByPosition(DetectionRule& rule, int position) {
        switch (position) {
        case 1:
            return &rule.parentProcessRules;
        case 2:
            return &rule.childProcessRules;
        case 3:
            return &rule.cmdLineRules;
        case 4:
            return &rule.parentCmdLineRules;
        default:
            return nullptr;
        }
    }

    bool HasAnyEnabledGroup(const DetectionRule& rule) {
        return rule.parentProcessRules.enabled ||
            rule.childProcessRules.enabled ||
            rule.cmdLineRules.enabled ||
            rule.parentCmdLineRules.enabled;
    }

    bool MatchRegexGroup(const RuleRegexGroup& group, const std::wstring& input) {
        if (!group.enabled) {
            return true;
        }

        if (input.empty()) {
            return false;
        }

        for (std::vector<std::wregex>::const_iterator it = group.patterns.begin();
            it != group.patterns.end();
            ++it) {
            if (std::regex_search(input, *it)) {
                return true;
            }
        }

        return false;
    }

    bool MatchDetectionRule(
        const DetectionRule& rule,
        const std::wstring& parentName,
        const std::wstring& childName,
        const std::wstring& cmdLine,
        const std::wstring& parentCmdLine) {
        return MatchRegexGroup(rule.parentProcessRules, parentName) &&
            MatchRegexGroup(rule.childProcessRules, childName) &&
            MatchRegexGroup(rule.cmdLineRules, cmdLine) &&
            MatchRegexGroup(rule.parentCmdLineRules, parentCmdLine);
    }

    bool TryMatchDetectionRuleCollection(
        const std::vector<DetectionRule>& rules,
        const std::wstring& parentName,
        const std::wstring& childName,
        const std::wstring& cmdLine,
        const std::wstring& parentCmdLine,
        DetectionRule& outMatchedRule) {
        for (std::vector<DetectionRule>::const_iterator it = rules.begin(); it != rules.end(); ++it) {
            if (MatchDetectionRule(*it, parentName, childName, cmdLine, parentCmdLine)) {
                outMatchedRule = *it;
                return true;
            }
        }

        return false;
    }

    std::wstring TrimWhitespace(const std::wstring& value) {
        size_t begin = 0;
        while (begin < value.size() && iswspace(value[begin])) {
            ++begin;
        }

        size_t end = value.size();
        while (end > begin && iswspace(value[end - 1])) {
            --end;
        }

        return value.substr(begin, end - begin);
    }

    void AppendRegexPattern(
        RuleRegexGroup& group,
        const std::string& rawPattern) {
        std::wstring patternText = TrimWhitespace(Utf8ToWStringLocal(rawPattern));
        if (patternText.empty()) {
            return;
        }

        try {
            group.patternTexts.push_back(patternText);
            group.patterns.push_back(std::wregex(
                patternText,
                std::regex_constants::ECMAScript | std::regex_constants::icase));
        }
        catch (const std::regex_error& e) {
            std::cerr << "[RuleManager] invalid regex in rule "
                << rawPattern << ": " << e.what() << std::endl;
        }
    }

    bool ParseSingleDetectionRule(
        const json& item,
        DetectionRule& outRule) {
        outRule.id = Utf8ToWStringLocal(item.value("id", ""));
        outRule.threatDesc = Utf8ToWStringLocal(item.value("threat_desc", ""));
        outRule.severity = item.value("severity", 0);

        json innerRule = json::object();
        if (item.contains("rule")) {
            if (item["rule"].is_string()) {
                innerRule = json::parse(item["rule"].get<std::string>());
            }
            else if (item["rule"].is_object()) {
                innerRule = item["rule"];
            }
        }

        if (!innerRule.contains("matchArray") || !innerRule["matchArray"].is_array()) {
            return false;
        }

        for (json::const_iterator matchItem = innerRule["matchArray"].begin();
            matchItem != innerRule["matchArray"].end();
            ++matchItem) {
            int position = matchItem->value("position", 0);
            RuleRegexGroup* group = GetRuleGroupByPosition(outRule, position);
            if (group == nullptr) {
                continue;
            }

            group->enabled = true;
            if (!matchItem->contains("value")) {
                std::wcerr << L"[RuleManager] Skip rule " << outRule.id
                    << L": position " << position << L" has no value." << std::endl;
                return false;
            }

            const json& values = (*matchItem)["value"];
            if (values.is_string()) {
                AppendRegexPattern(*group, values.get<std::string>());
            }
            else if (values.is_array()) {
                for (json::const_iterator val = values.begin(); val != values.end(); ++val) {
                    if (val->is_string()) {
                        AppendRegexPattern(*group, val->get<std::string>());
                    }
                }
            }

            if (group->patterns.empty()) {
                std::wcerr << L"[RuleManager] Skip rule " << outRule.id
                    << L": position " << position << L" has no valid regex." << std::endl;
                return false;
            }
        }

        return HasAnyEnabledGroup(outRule);
    }

    bool ParseDetectionRuleArray(
        const json& ruleArray,
        std::vector<DetectionRule>& outRules) {
        if (!ruleArray.is_array()) {
            return false;
        }

        for (json::const_iterator item = ruleArray.begin(); item != ruleArray.end(); ++item) {
            DetectionRule rule;
            if (ParseSingleDetectionRule(*item, rule)) {
                outRules.push_back(rule);
            }
        }

        return true;
    }

        bool HasAnyEnabledRegistryField(const RegistryRuleDefinition& rule) {
        return rule.processNameRule.enabled ||
            rule.keyPathRule.enabled ||
            rule.infoClassRule.enabled ||
            rule.valueNameRule.enabled ||
            rule.valueDataRule.enabled;
    }

    bool IsValidRegistryMatchType(ULONG matchType) {
        return matchType == REGISTRY_MATCH_TYPE_EXACT ||
            matchType == REGISTRY_MATCH_TYPE_PREFIX ||
            matchType == REGISTRY_MATCH_TYPE_SUFFIX ||
            matchType == REGISTRY_MATCH_TYPE_CONTAINS;
    }

    bool TryParseRegistryMatchType(const std::string& rawType, ULONG& outMatchType) {
        const std::string lowered = ToLowerAscii(rawType);
        if (lowered == "exact") {
            outMatchType = REGISTRY_MATCH_TYPE_EXACT;
            return true;
        }
        if (lowered == "prefix") {
            outMatchType = REGISTRY_MATCH_TYPE_PREFIX;
            return true;
        }
        if (lowered == "suffix") {
            outMatchType = REGISTRY_MATCH_TYPE_SUFFIX;
            return true;
        }
        if (lowered == "contains") {
            outMatchType = REGISTRY_MATCH_TYPE_CONTAINS;
            return true;
        }
        return false;
    }

    void AppendRegistryFieldValue(std::vector<std::wstring>& values, const std::wstring& value) {
        if (value.empty()) {
            return;
        }

        if (std::find(values.begin(), values.end(), value) == values.end()) {
            values.push_back(value);
        }
    }

    bool ParseRegistryFieldValues(const json& node, std::vector<std::wstring>& outValues) {
        if (node.is_string()) {
            AppendRegistryFieldValue(outValues, TrimWhitespace(Utf8ToWStringLocal(node.get<std::string>())));
            return true;
        }

        if (node.is_array()) {
            for (json::const_iterator it = node.begin(); it != node.end(); ++it) {
                if (it->is_string()) {
                    AppendRegistryFieldValue(outValues, TrimWhitespace(Utf8ToWStringLocal(it->get<std::string>())));
                }
            }
            return true;
        }

        return false;
    }

    bool ClassifyRegistryRuleValueMatchType(
        const std::wstring& rawValue,
        ULONG fallbackMatchType,
        bool hasExplicitMatchType,
        ULONG& outMatchType,
        std::wstring& outNormalizedValue) {
        std::wstring value = TrimWhitespace(rawValue);
        if (value.empty()) {
            return false;
        }

        if (hasExplicitMatchType) {
            outMatchType = fallbackMatchType;
            outNormalizedValue = value;
            return true;
        }

        const bool startsWithWildcard = !value.empty() && value.front() == L'*';
        const bool endsWithWildcard = !value.empty() && value.back() == L'*';

        if (!startsWithWildcard && !endsWithWildcard) {
            outMatchType = fallbackMatchType;
            outNormalizedValue = value;
            return true;
        }

        if (startsWithWildcard && endsWithWildcard) {
            if (value.size() <= 2) {
                return false;
            }

            outMatchType = REGISTRY_MATCH_TYPE_CONTAINS;
            outNormalizedValue = value.substr(1, value.size() - 2);
        }
        else if (startsWithWildcard) {
            if (value.size() <= 1) {
                return false;
            }

            outMatchType = REGISTRY_MATCH_TYPE_SUFFIX;
            outNormalizedValue = value.substr(1);
        }
        else {
            if (value.size() <= 1) {
                return false;
            }

            outMatchType = REGISTRY_MATCH_TYPE_PREFIX;
            outNormalizedValue = value.substr(0, value.size() - 1);
        }

        outNormalizedValue = TrimWhitespace(outNormalizedValue);
        return !outNormalizedValue.empty();
    }

    bool ParseRegistryField(
        const json& root,
        const char* fieldName,
        ULONG defaultMatchType,
        RegistryRuleField& outField) {
        if (!root.contains(fieldName)) {
            return true;
        }

        outField.enabled = true;
        outField.matchType = defaultMatchType;
        bool hasExplicitMatchType = false;
        std::vector<std::wstring> rawValues;

        const json& node = root[fieldName];
        if (node.is_object()) {
            if (node.contains("match_type")) {
                if (!node["match_type"].is_string() ||
                    !TryParseRegistryMatchType(node["match_type"].get<std::string>(), outField.matchType)) {
                    return false;
                }
                hasExplicitMatchType = true;
            }

            if (node.contains("values")) {
                if (!ParseRegistryFieldValues(node["values"], rawValues)) {
                    return false;
                }
            }
            else if (node.contains("value")) {
                if (!ParseRegistryFieldValues(node["value"], rawValues)) {
                    return false;
                }
            }
            else {
                return false;
            }
        }
        else if (!ParseRegistryFieldValues(node, rawValues)) {
            return false;
        }

        ULONG classifiedMatchType = outField.matchType;
        for (std::vector<std::wstring>::const_iterator it = rawValues.begin(); it != rawValues.end(); ++it) {
            ULONG valueMatchType = outField.matchType;
            std::wstring normalizedValue;
            if (!ClassifyRegistryRuleValueMatchType(
                *it,
                outField.matchType,
                hasExplicitMatchType,
                valueMatchType,
                normalizedValue)) {
                return false;
            }

            if (!hasExplicitMatchType) {
                if (outField.values.empty()) {
                    classifiedMatchType = valueMatchType;
                }
                else if (classifiedMatchType != valueMatchType) {
                    std::wcerr << L"[RuleManager] Skip registry field " << Utf8ToWStringLocal(fieldName)
                        << L": mixed wildcard match types require explicit match_type." << std::endl;
                    return false;
                }
            }

            AppendRegistryFieldValue(outField.values, normalizedValue);
        }

        outField.matchType = classifiedMatchType;
        if (!IsValidRegistryMatchType(outField.matchType) || outField.values.empty()) {
            return false;
        }

        return true;
    }

    ULONG PromoteCompiledRuleBucket(ULONG currentBucket, ULONG matchType) {
        switch (matchType) {
        case REGISTRY_MATCH_TYPE_EXACT:
        case REGISTRY_MATCH_TYPE_PREFIX:
        case REGISTRY_MATCH_TYPE_SUFFIX:
        case REGISTRY_MATCH_TYPE_CONTAINS:
            return (matchType > currentBucket) ? matchType : currentBucket;
        default:
            return 0;
        }
    }

    bool CountCompiledRulesByMatchType(
        const std::vector<REGISTRY_RULE>& compiledRules,
        RegistryRuleClassStats& outStats) {
        outStats = RegistryRuleClassStats{};

        for (std::vector<REGISTRY_RULE>::const_iterator it = compiledRules.begin();
            it != compiledRules.end();
            ++it) {
            ULONG bucket = REGISTRY_MATCH_TYPE_EXACT;

            if ((it->MatchFlags & REGISTRY_MATCH_FLAG_PROCESS_NAME) != 0) {
                bucket = PromoteCompiledRuleBucket(bucket, it->ProcessNameMatchType);
            }
            if ((it->MatchFlags & REGISTRY_MATCH_FLAG_KEY_PATH) != 0) {
                bucket = PromoteCompiledRuleBucket(bucket, it->KeyPathMatchType);
            }
            if ((it->MatchFlags & REGISTRY_MATCH_FLAG_INFO_CLASS) != 0) {
                bucket = PromoteCompiledRuleBucket(bucket, it->InfoClassMatchType);
            }
            if ((it->MatchFlags & REGISTRY_MATCH_FLAG_VALUE_NAME) != 0) {
                bucket = PromoteCompiledRuleBucket(bucket, it->ValueNameMatchType);
            }
            if ((it->MatchFlags & REGISTRY_MATCH_FLAG_VALUE_DATA) != 0) {
                bucket = PromoteCompiledRuleBucket(bucket, it->ValueDataMatchType);
            }

            if (!IsValidRegistryMatchType(bucket)) {
                return false;
            }

            ++outStats.totalRules;
            switch (bucket) {
            case REGISTRY_MATCH_TYPE_EXACT:
                ++outStats.exactRules;
                break;
            case REGISTRY_MATCH_TYPE_PREFIX:
                ++outStats.prefixRules;
                break;
            case REGISTRY_MATCH_TYPE_SUFFIX:
                ++outStats.suffixRules;
                break;
            case REGISTRY_MATCH_TYPE_CONTAINS:
                ++outStats.containsRules;
                break;
            default:
                return false;
            }
        }

        return true;
    }

    void MergeRegistryRuleClassStats(
        RegistryRuleClassStats& target,
        const RegistryRuleClassStats& delta) {
        target.totalRules += delta.totalRules;
        target.exactRules += delta.exactRules;
        target.prefixRules += delta.prefixRules;
        target.suffixRules += delta.suffixRules;
        target.containsRules += delta.containsRules;
    }

    bool ParseRegistryOperation(const json& root, ULONG& outOperation) {
        outOperation = REGISTRY_OPERATION_SET_VALUE;
        if (!root.contains("operation")) {
            return true;
        }

        if (!root["operation"].is_string()) {
            return false;
        }

        const std::string lowered = ToLowerAscii(root["operation"].get<std::string>());
        if (lowered == "set_value") {
            outOperation = REGISTRY_OPERATION_SET_VALUE;
            return true;
        }
        if (lowered == "create_key") {
            outOperation = REGISTRY_OPERATION_CREATE_KEY;
            return true;
        }
        if (lowered == "delete_value") {
            outOperation = REGISTRY_OPERATION_DELETE_VALUE;
            return true;
        }
        if (lowered == "delete_key") {
            outOperation = REGISTRY_OPERATION_DELETE_KEY;
            return true;
        }
        if (lowered == "rename_key") {
            outOperation = REGISTRY_OPERATION_RENAME_KEY;
            return true;
        }
        if (lowered == "set_information_key") {
            outOperation = REGISTRY_OPERATION_SET_INFORMATION_KEY;
            return true;
        }

        return false;
    }

            bool CopyToFixedBuffer(
        const std::wstring& value,
        WCHAR* buffer,
        size_t bufferLength,
        const wchar_t* fieldName,
        const std::wstring& ruleId) {
        if (value.size() >= bufferLength) {
            std::wcerr << L"[RuleManager] Skip registry rule " << ruleId
                << L": field " << fieldName << L" is too long." << std::endl;
            return false;
        }

        wcsncpy_s(buffer, bufferLength, value.c_str(), _TRUNCATE);
        return true;
    }

    bool ExpandSingleRegistryRule(
        const RegistryRuleDefinition& definition,
        std::vector<REGISTRY_RULE>& outRules) {
        const std::vector<std::wstring> processValues = definition.processNameRule.enabled ?
            definition.processNameRule.values : std::vector<std::wstring>(1, L"");
        const std::vector<std::wstring> keyPathValues = definition.keyPathRule.enabled ?
            definition.keyPathRule.values : std::vector<std::wstring>(1, L"");
        const std::vector<std::wstring> infoClassValues = definition.infoClassRule.enabled ?
            definition.infoClassRule.values : std::vector<std::wstring>(1, L"");
        const std::vector<std::wstring> valueNameValues = definition.valueNameRule.enabled ?
            definition.valueNameRule.values : std::vector<std::wstring>(1, L"");
        const std::vector<std::wstring> valueDataValues = definition.valueDataRule.enabled ?
            definition.valueDataRule.values : std::vector<std::wstring>(1, L"");

        for (std::vector<std::wstring>::const_iterator processIt = processValues.begin();
            processIt != processValues.end();
            ++processIt) {
            for (std::vector<std::wstring>::const_iterator keyIt = keyPathValues.begin();
                keyIt != keyPathValues.end();
                ++keyIt) {
                for (std::vector<std::wstring>::const_iterator infoClassIt = infoClassValues.begin();
                    infoClassIt != infoClassValues.end();
                    ++infoClassIt) {
                    for (std::vector<std::wstring>::const_iterator valueNameIt = valueNameValues.begin();
                        valueNameIt != valueNameValues.end();
                        ++valueNameIt) {
                        for (std::vector<std::wstring>::const_iterator valueDataIt = valueDataValues.begin();
                            valueDataIt != valueDataValues.end();
                            ++valueDataIt) {
                            REGISTRY_RULE compiledRule = {};
                            compiledRule.Operation = definition.operation;
                            compiledRule.Severity = static_cast<ULONG>(definition.severity);

                            if (!CopyToFixedBuffer(definition.id, compiledRule.RuleId, MAX_RULE_ID_LENGTH, L"rule_id", definition.id)) {
                                return false;
                            }

                            if (definition.processNameRule.enabled) {
                                compiledRule.MatchFlags |= REGISTRY_MATCH_FLAG_PROCESS_NAME;
                                compiledRule.ProcessNameMatchType = definition.processNameRule.matchType;
                                if (!CopyToFixedBuffer(*processIt, compiledRule.ProcessName, MAX_RULE_LENGTH, L"process_name", definition.id)) {
                                    return false;
                                }
                            }

                            if (definition.keyPathRule.enabled) {
                                compiledRule.MatchFlags |= REGISTRY_MATCH_FLAG_KEY_PATH;
                                compiledRule.KeyPathMatchType = definition.keyPathRule.matchType;
                                if (!CopyToFixedBuffer(*keyIt, compiledRule.KeyPath, MAX_REG_PATH_LENGTH, L"key_path", definition.id)) {
                                    return false;
                                }
                            }

                            if (definition.infoClassRule.enabled) {
                                compiledRule.MatchFlags |= REGISTRY_MATCH_FLAG_INFO_CLASS;
                                compiledRule.InfoClassMatchType = definition.infoClassRule.matchType;
                                if (!CopyToFixedBuffer(*infoClassIt, compiledRule.InfoClass, MAX_RULE_LENGTH, L"info_class", definition.id)) {
                                    return false;
                                }
                            }

                            if (definition.valueNameRule.enabled) {
                                compiledRule.MatchFlags |= REGISTRY_MATCH_FLAG_VALUE_NAME;
                                compiledRule.ValueNameMatchType = definition.valueNameRule.matchType;
                                if (!CopyToFixedBuffer(*valueNameIt, compiledRule.ValueName, MAX_RULE_LENGTH, L"value_name", definition.id)) {
                                    return false;
                                }
                            }

                            if (definition.valueDataRule.enabled) {
                                compiledRule.MatchFlags |= REGISTRY_MATCH_FLAG_VALUE_DATA;
                                compiledRule.ValueDataMatchType = definition.valueDataRule.matchType;
                                if (!CopyToFixedBuffer(*valueDataIt, compiledRule.ValueData, MAX_RULE_LENGTH, L"value_data", definition.id)) {
                                    return false;
                                }
                            }

                            outRules.push_back(compiledRule);
                        }
                    }
                }
            }
        }

        return !outRules.empty();
    }

        bool ParseSingleRegistryRule(
        const json& item,
        RegistryRuleDefinition& outDefinition,
        std::vector<REGISTRY_RULE>& outCompiledRules) {
        outDefinition.id = Utf8ToWStringLocal(item.value("id", ""));
        outDefinition.threatDesc = Utf8ToWStringLocal(item.value("threat_desc", ""));
        outDefinition.severity = item.value("severity", 0);

        if (outDefinition.id.empty()) {
            return false;
        }

        json body = item;
        if (item.contains("match") && item["match"].is_object()) {
            body = item["match"];
        }
        else if (item.contains("rule")) {
            if (item["rule"].is_object()) {
                body = item["rule"];
            }
            else if (item["rule"].is_string()) {
                body = json::parse(item["rule"].get<std::string>());
            }
        }

        if (!ParseRegistryOperation(item, outDefinition.operation) ||
            !ParseRegistryOperation(body, outDefinition.operation) ||
            !ParseRegistryField(body, "process_name", REGISTRY_MATCH_TYPE_EXACT, outDefinition.processNameRule) ||
            !ParseRegistryField(body, "key_path", REGISTRY_MATCH_TYPE_CONTAINS, outDefinition.keyPathRule) ||
            !ParseRegistryField(body, "info_class", REGISTRY_MATCH_TYPE_EXACT, outDefinition.infoClassRule) ||
            !ParseRegistryField(body, "value_name", REGISTRY_MATCH_TYPE_EXACT, outDefinition.valueNameRule) ||
            !ParseRegistryField(body, "value_data", REGISTRY_MATCH_TYPE_EXACT, outDefinition.valueDataRule)) {
            std::wcerr << L"[RuleManager] Skip registry rule " << outDefinition.id
                << L": invalid registry rule schema." << std::endl;
            return false;
        }

        if (body.contains("new_name")) {
            if (body.contains("value_data")) {
                std::wcerr << L"[RuleManager] Skip registry rule " << outDefinition.id
                    << L": new_name conflicts with value_data." << std::endl;
                return false;
            }

            outDefinition.valueDataRule = RegistryRuleField{};
            if (!ParseRegistryField(body, "new_name", REGISTRY_MATCH_TYPE_EXACT, outDefinition.valueDataRule)) {
                std::wcerr << L"[RuleManager] Skip registry rule " << outDefinition.id
                    << L": invalid new_name schema." << std::endl;
                return false;
            }
        }

        if (!HasAnyEnabledRegistryField(outDefinition)) {
            std::wcerr << L"[RuleManager] Skip registry rule " << outDefinition.id
                << L": no registry match fields were configured." << std::endl;
            return false;
        }

        return ExpandSingleRegistryRule(outDefinition, outCompiledRules);
    }

    bool ParseRegistryRuleArray(
        const json& ruleArray,
        std::vector<RegistryRuleDefinition>& outDefinitions,
        std::vector<REGISTRY_RULE>& outCompiledRules,
        RegistryRuleClassStats& outStats) {
        if (!ruleArray.is_array()) {
            return false;
        }

        RegistryRuleClassStats aggregateStats;
        for (json::const_iterator item = ruleArray.begin(); item != ruleArray.end(); ++item) {
            RegistryRuleDefinition definition;
            std::vector<REGISTRY_RULE> compiledRules;
            if (!ParseSingleRegistryRule(*item, definition, compiledRules)) {
                continue;
            }

            RegistryRuleClassStats compiledStats;
            if (!CountCompiledRulesByMatchType(compiledRules, compiledStats)) {
                std::wcerr << L"[RuleManager] Skip registry rule " << definition.id
                    << L": unsupported compiled match type." << std::endl;
                return false;
            }
            if (aggregateStats.containsRules + compiledStats.containsRules > MAX_REGISTRY_CONTAINS_RULES) {
                std::wcerr << L"[RuleManager] contains match count exceeds limit ("
                    << MAX_REGISTRY_CONTAINS_RULES << L")." << std::endl;
                return false;
            }

            outDefinitions.push_back(definition);
            outCompiledRules.insert(outCompiledRules.end(), compiledRules.begin(), compiledRules.end());
            MergeRegistryRuleClassStats(aggregateStats, compiledStats);
        }

        outStats = aggregateStats;
        return true;
    }


}
RuleManager::RuleManager() {}
RuleManager::~RuleManager() {}

size_t RuleManager::GetRuleCount() const {
    std::lock_guard<std::mutex> lock(m_Lock);
    return m_ActiveConfig.processRules.size();
}

size_t RuleManager::GetProcessAllowRuleCount() const {
    std::lock_guard<std::mutex> lock(m_Lock);
    return m_ActiveConfig.processAllowRules.size();
}

size_t RuleManager::GetRegistryRuleCount() const {
    std::lock_guard<std::mutex> lock(m_Lock);
    return m_ActiveConfig.registryRuleDefinitions.size();
}

size_t RuleManager::GetRegistryAllowRuleCount() const {
    std::lock_guard<std::mutex> lock(m_Lock);
    return m_ActiveConfig.registryAllowRuleDefinitions.size();
}

std::vector<REGISTRY_RULE> RuleManager::GetRegistryRules() const {
    std::lock_guard<std::mutex> lock(m_Lock);
    return m_ActiveConfig.registryRules;
}

std::vector<REGISTRY_RULE> RuleManager::GetRegistryAllowRules() const {
    std::lock_guard<std::mutex> lock(m_Lock);
    return m_ActiveConfig.registryAllowRules;
}

std::wstring RuleManager::GetConfigVersion() const {
    std::lock_guard<std::mutex> lock(m_Lock);
    return m_ActiveConfig.configVersion;
}

std::wstring RuleManager::GetProfileName() const {
    std::lock_guard<std::mutex> lock(m_Lock);
    return m_ActiveConfig.profileName;
}

RuleConfiguration RuleManager::GetRuleConfigurationSnapshot() const {
    std::lock_guard<std::mutex> lock(m_Lock);
    return m_ActiveConfig;
}

bool RuleManager::TryGetRegistryRuleMetadata(
    const std::wstring& ruleId,
    std::wstring& outThreatDesc,
    int& outSeverity) const {
    std::lock_guard<std::mutex> lock(m_Lock);
    for (std::vector<RegistryRuleDefinition>::const_iterator it = m_ActiveConfig.registryRuleDefinitions.begin();
        it != m_ActiveConfig.registryRuleDefinitions.end();
        ++it) {
        if (it->id == ruleId) {
            outThreatDesc = it->threatDesc;
            outSeverity = it->severity;
            return true;
        }
    }

    return false;
}


bool RuleManager::TryLoadRulesFromJson(
    const std::wstring& jsonFilePath,
    RuleConfiguration& outConfig,
    std::wstring* outError) const {
    std::wifstream file(jsonFilePath.c_str());
    if (!file.is_open()) {
        if (outError != nullptr) {
            *outError = L"failed to open rules file";
        }
        return false;
    }

    file.imbue(std::locale(file.getloc(), new std::codecvt_utf8<wchar_t>));

    try {
        std::wstringstream wss;
        wss << file.rdbuf();

        json root = json::parse(wss.str());
        RuleConfiguration loadedConfig;
        loadedConfig.sourcePath = jsonFilePath;

        if (root.is_array()) {
            if (!ParseDetectionRuleArray(root, loadedConfig.processRules)) {
                if (outError != nullptr) {
                    *outError = L"invalid legacy process rule array";
                }
                return false;
            }

            loadedConfig.configVersion = L"legacy-unversioned";
            loadedConfig.profileName = L"legacy";
        }
        else if (root.is_object()) {
            if (root.contains("config_version")) {
                if (!root["config_version"].is_string()) {
                    if (outError != nullptr) {
                        *outError = L"config_version must be a string";
                    }
                    return false;
                }
                loadedConfig.configVersion = Utf8ToWStringLocal(root["config_version"].get<std::string>());
            }

            if (root.contains("profile_name")) {
                if (!root["profile_name"].is_string()) {
                    if (outError != nullptr) {
                        *outError = L"profile_name must be a string";
                    }
                    return false;
                }
                loadedConfig.profileName = Utf8ToWStringLocal(root["profile_name"].get<std::string>());
            }

            if (root.contains("generated_at")) {
                if (!root["generated_at"].is_string()) {
                    if (outError != nullptr) {
                        *outError = L"generated_at must be a string";
                    }
                    return false;
                }
                loadedConfig.generatedAt = Utf8ToWStringLocal(root["generated_at"].get<std::string>());
            }

            if (!ParseProcessVerdictConfig(root, loadedConfig, outError)) {
                return false;
            }

            if (!ParseAutoResponseConfig(root, loadedConfig, outError)) {
                return false;
            }

            if (root.contains("process_rules")) {
                if (!ParseDetectionRuleArray(root["process_rules"], loadedConfig.processRules)) {
                    if (outError != nullptr) {
                        *outError = L"invalid process_rules";
                    }
                    return false;
                }
            }

            if (root.contains("process_allow_rules")) {
                if (!ParseDetectionRuleArray(root["process_allow_rules"], loadedConfig.processAllowRules)) {
                    if (outError != nullptr) {
                        *outError = L"invalid process_allow_rules";
                    }
                    return false;
                }
            }

            if (root.contains("registry_rules")) {
                if (!ParseRegistryRuleArray(
                    root["registry_rules"],
                    loadedConfig.registryRuleDefinitions,
                    loadedConfig.registryRules,
                    loadedConfig.registryRuleClassStats)) {
                    if (outError != nullptr) {
                        *outError = L"invalid registry_rules";
                    }
                    return false;
                }
            }

            if (root.contains("registry_allow_rules")) {
                if (!ParseRegistryRuleArray(
                    root["registry_allow_rules"],
                    loadedConfig.registryAllowRuleDefinitions,
                    loadedConfig.registryAllowRules,
                    loadedConfig.registryAllowRuleClassStats)) {
                    if (outError != nullptr) {
                        *outError = L"invalid registry_allow_rules";
                    }
                    return false;
                }
            }
        }
        else {
            if (outError != nullptr) {
                *outError = L"rules root must be an object or array";
            }
            return false;
        }

        if (loadedConfig.configVersion.empty()) {
            loadedConfig.configVersion = L"unversioned";
        }
        if (loadedConfig.profileName.empty()) {
            loadedConfig.profileName = L"default";
        }














        outConfig = std::move(loadedConfig);
        return true;
    }
    catch (const json::exception& e) {
        std::cerr << "[RuleManager] JSON parse failed: " << e.what() << std::endl;
        if (outError != nullptr) {
            *outError = Utf8ToWStringLocal(e.what());
        }
        return false;
    }
}

void RuleManager::ApplyLoadedRules(RuleConfiguration&& loadedConfig) {
    std::lock_guard<std::mutex> lock(m_Lock);
    m_ActiveConfig = std::move(loadedConfig);
}

bool RuleManager::LoadRulesFromJson(const std::wstring& jsonFilePath) {
    RuleConfiguration loadedConfig;
    if (!TryLoadRulesFromJson(jsonFilePath, loadedConfig, nullptr)) {
        return false;
    }

    ApplyLoadedRules(std::move(loadedConfig));
    return true;
}

bool RuleManager::EvaluateProcessAgainstRules(
    const std::wstring& parentName,
    const std::wstring& childName,
    const std::wstring& cmdLine,
    const std::wstring& parentCmdLine,
    DetectionRule& outMatchedRule) {
    std::lock_guard<std::mutex> lock(m_Lock);
    DetectionRule ignoredAllowRule;
    if (TryMatchDetectionRuleCollection(
        m_ActiveConfig.processAllowRules,
        parentName,
        childName,
        cmdLine,
        parentCmdLine,
        ignoredAllowRule)) {
        return false;
    }

    return TryMatchDetectionRuleCollection(
        m_ActiveConfig.processRules,
        parentName,
        childName,
        cmdLine,
        parentCmdLine,
        outMatchedRule);
}

bool RuleManager::TryMatchProcessAllowRule(
    const std::wstring& parentName,
    const std::wstring& childName,
    const std::wstring& cmdLine,
    const std::wstring& parentCmdLine,
    DetectionRule& outMatchedRule) const {
    std::lock_guard<std::mutex> lock(m_Lock);
    return TryMatchDetectionRuleCollection(
        m_ActiveConfig.processAllowRules,
        parentName,
        childName,
        cmdLine,
        parentCmdLine,
        outMatchedRule);
}

