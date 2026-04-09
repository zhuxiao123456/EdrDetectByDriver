#include "RuleManager.h"

#include <windows.h>

#include <algorithm>
#include <cctype>
#include <codecvt>
#include <cwctype>
#include <fstream>
#include <iostream>
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

    bool ParseDriverBlacklist(
        const json& driverArray,
        std::vector<std::wstring>& outDriverBlacklist) {
        if (!driverArray.is_array()) {
            return false;
        }

        for (json::const_iterator item = driverArray.begin(); item != driverArray.end(); ++item) {
            std::wstring driverName;

            if (item->is_string()) {
                driverName = Utf8ToWStringLocal(item->get<std::string>());
            }
            else if (item->is_object() && item->contains("name") && (*item)["name"].is_string()) {
                driverName = Utf8ToWStringLocal((*item)["name"].get<std::string>());
            }

            driverName = TrimWhitespace(driverName);
            if (driverName.empty()) {
                continue;
            }

            if (std::find(outDriverBlacklist.begin(), outDriverBlacklist.end(), driverName) == outDriverBlacklist.end()) {
                outDriverBlacklist.push_back(driverName);
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

    void AppendRegistryFieldValue(RegistryRuleField& field, const std::string& rawValue) {
        std::wstring value = TrimWhitespace(Utf8ToWStringLocal(rawValue));
        if (value.empty()) {
            return;
        }

        if (std::find(field.values.begin(), field.values.end(), value) == field.values.end()) {
            field.values.push_back(value);
        }
    }

    bool ParseRegistryFieldValues(const json& node, RegistryRuleField& outField) {
        if (node.is_string()) {
            AppendRegistryFieldValue(outField, node.get<std::string>());
            return true;
        }

        if (node.is_array()) {
            for (json::const_iterator it = node.begin(); it != node.end(); ++it) {
                if (it->is_string()) {
                    AppendRegistryFieldValue(outField, it->get<std::string>());
                }
            }
            return true;
        }

        return false;
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

        const json& node = root[fieldName];
        if (node.is_object()) {
            if (node.contains("match_type")) {
                if (!node["match_type"].is_string() ||
                    !TryParseRegistryMatchType(node["match_type"].get<std::string>(), outField.matchType)) {
                    return false;
                }
            }

            if (node.contains("values")) {
                if (!ParseRegistryFieldValues(node["values"], outField)) {
                    return false;
                }
            }
            else if (node.contains("value")) {
                if (!ParseRegistryFieldValues(node["value"], outField)) {
                    return false;
                }
            }
            else {
                return false;
            }
        }
        else if (!ParseRegistryFieldValues(node, outField)) {
            return false;
        }

        if (!IsValidRegistryMatchType(outField.matchType) || outField.values.empty()) {
            return false;
        }

        return true;
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

    bool HasAnyEnabledFileField(const FileRuleDefinition& rule) {
        return rule.processNameRule.enabled ||
            rule.targetPathRule.enabled ||
            rule.extensionRule.enabled;
    }

    bool ParseFileOperation(const json& root, ULONG& outOperation) {
        outOperation = FILE_OPERATION_CREATE_OR_WRITE;
        if (!root.contains("operation")) {
            return true;
        }

        if (!root["operation"].is_string()) {
            return false;
        }

        const std::string lowered = ToLowerAscii(root["operation"].get<std::string>());
        if (lowered == "create") {
            outOperation = FILE_OPERATION_CREATE;
            return true;
        }
        if (lowered == "write") {
            outOperation = FILE_OPERATION_WRITE;
            return true;
        }
        if (lowered == "create_or_write") {
            outOperation = FILE_OPERATION_CREATE_OR_WRITE;
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

    bool ExpandSingleFileRule(
        const FileRuleDefinition& definition,
        std::vector<FILE_RULE>& outRules) {
        const std::vector<std::wstring> processValues = definition.processNameRule.enabled ?
            definition.processNameRule.values : std::vector<std::wstring>(1, L"");
        const std::vector<std::wstring> targetPathValues = definition.targetPathRule.enabled ?
            definition.targetPathRule.values : std::vector<std::wstring>(1, L"");
        const std::vector<std::wstring> extensionValues = definition.extensionRule.enabled ?
            definition.extensionRule.values : std::vector<std::wstring>(1, L"");

        for (std::vector<std::wstring>::const_iterator processIt = processValues.begin();
            processIt != processValues.end();
            ++processIt) {
            for (std::vector<std::wstring>::const_iterator pathIt = targetPathValues.begin();
                pathIt != targetPathValues.end();
                ++pathIt) {
                for (std::vector<std::wstring>::const_iterator extensionIt = extensionValues.begin();
                    extensionIt != extensionValues.end();
                    ++extensionIt) {
                    FILE_RULE compiledRule = {};
                    compiledRule.Operation = definition.operation;
                    compiledRule.Severity = static_cast<ULONG>(definition.severity);

                    if (!CopyToFixedBuffer(definition.id, compiledRule.RuleId, MAX_RULE_ID_LENGTH, L"rule_id", definition.id)) {
                        return false;
                    }

                    if (definition.processNameRule.enabled) {
                        compiledRule.MatchFlags |= FILE_MATCH_FLAG_PROCESS_NAME;
                        compiledRule.ProcessNameMatchType = definition.processNameRule.matchType;
                        if (!CopyToFixedBuffer(*processIt, compiledRule.ProcessName, MAX_RULE_LENGTH, L"process_name", definition.id)) {
                            return false;
                        }
                    }

                    if (definition.targetPathRule.enabled) {
                        compiledRule.MatchFlags |= FILE_MATCH_FLAG_TARGET_PATH;
                        compiledRule.TargetPathMatchType = definition.targetPathRule.matchType;
                        if (!CopyToFixedBuffer(*pathIt, compiledRule.TargetPath, MAX_REG_PATH_LENGTH, L"target_path", definition.id)) {
                            return false;
                        }
                    }

                    if (definition.extensionRule.enabled) {
                        compiledRule.MatchFlags |= FILE_MATCH_FLAG_EXTENSION;
                        compiledRule.ExtensionMatchType = definition.extensionRule.matchType;
                        if (!CopyToFixedBuffer(*extensionIt, compiledRule.Extension, MAX_RULE_LENGTH, L"file_extension", definition.id)) {
                            return false;
                        }
                    }

                    outRules.push_back(compiledRule);
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

    bool ParseSingleFileRule(
        const json& item,
        FileRuleDefinition& outDefinition,
        std::vector<FILE_RULE>& outCompiledRules) {
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

        if (!ParseFileOperation(item, outDefinition.operation) ||
            !ParseFileOperation(body, outDefinition.operation) ||
            !ParseRegistryField(body, "process_name", REGISTRY_MATCH_TYPE_EXACT, outDefinition.processNameRule)) {
            std::wcerr << L"[RuleManager] Skip file rule " << outDefinition.id
                << L": invalid process_name or operation schema." << std::endl;
            return false;
        }

        if (body.contains("target_path")) {
            if (!ParseRegistryField(body, "target_path", REGISTRY_MATCH_TYPE_CONTAINS, outDefinition.targetPathRule)) {
                std::wcerr << L"[RuleManager] Skip file rule " << outDefinition.id
                    << L": invalid target_path schema." << std::endl;
                return false;
            }
        }
        else if (body.contains("path")) {
            if (!ParseRegistryField(body, "path", REGISTRY_MATCH_TYPE_CONTAINS, outDefinition.targetPathRule)) {
                std::wcerr << L"[RuleManager] Skip file rule " << outDefinition.id
                    << L": invalid path schema." << std::endl;
                return false;
            }
        }

        if (body.contains("file_extension")) {
            if (!ParseRegistryField(body, "file_extension", REGISTRY_MATCH_TYPE_SUFFIX, outDefinition.extensionRule)) {
                std::wcerr << L"[RuleManager] Skip file rule " << outDefinition.id
                    << L": invalid file_extension schema." << std::endl;
                return false;
            }
        }
        else if (body.contains("extension")) {
            if (!ParseRegistryField(body, "extension", REGISTRY_MATCH_TYPE_SUFFIX, outDefinition.extensionRule)) {
                std::wcerr << L"[RuleManager] Skip file rule " << outDefinition.id
                    << L": invalid extension schema." << std::endl;
                return false;
            }
        }

        if (!HasAnyEnabledFileField(outDefinition)) {
            std::wcerr << L"[RuleManager] Skip file rule " << outDefinition.id
                << L": no file match fields were configured." << std::endl;
            return false;
        }

        return ExpandSingleFileRule(outDefinition, outCompiledRules);
    }

    bool ParseRegistryRuleArray(
        const json& ruleArray,
        std::vector<RegistryRuleDefinition>& outDefinitions,
        std::vector<REGISTRY_RULE>& outCompiledRules) {
        if (!ruleArray.is_array()) {
            return false;
        }

        for (json::const_iterator item = ruleArray.begin(); item != ruleArray.end(); ++item) {
            RegistryRuleDefinition definition;
            std::vector<REGISTRY_RULE> compiledRules;
            if (!ParseSingleRegistryRule(*item, definition, compiledRules)) {
                continue;
            }

            if (outCompiledRules.size() + compiledRules.size() > MAX_REGISTRY_RULE_COUNT) {
                std::wcerr << L"[RuleManager] registry_rules exceed kernel capacity ("
                    << MAX_REGISTRY_RULE_COUNT << L")." << std::endl;
                return false;
            }

            outDefinitions.push_back(definition);
            outCompiledRules.insert(outCompiledRules.end(), compiledRules.begin(), compiledRules.end());
        }

        return true;
    }

    bool ParseFileRuleArray(
        const json& ruleArray,
        std::vector<FileRuleDefinition>& outDefinitions,
        std::vector<FILE_RULE>& outCompiledRules) {
        if (!ruleArray.is_array()) {
            return false;
        }

        for (json::const_iterator item = ruleArray.begin(); item != ruleArray.end(); ++item) {
            FileRuleDefinition definition;
            std::vector<FILE_RULE> compiledRules;
            if (!ParseSingleFileRule(*item, definition, compiledRules)) {
                continue;
            }

            if (outCompiledRules.size() + compiledRules.size() > MAX_FILE_RULE_COUNT) {
                std::wcerr << L"[RuleManager] file_rules exceed kernel capacity ("
                    << MAX_FILE_RULE_COUNT << L")." << std::endl;
                return false;
            }

            outDefinitions.push_back(definition);
            outCompiledRules.insert(outCompiledRules.end(), compiledRules.begin(), compiledRules.end());
        }

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

size_t RuleManager::GetDriverBlacklistCount() const {
    std::lock_guard<std::mutex> lock(m_Lock);
    return m_ActiveConfig.driverBlacklist.size();
}

size_t RuleManager::GetFileRuleCount() const {
    std::lock_guard<std::mutex> lock(m_Lock);
    return m_ActiveConfig.fileRuleDefinitions.size();
}

std::vector<std::wstring> RuleManager::GetDriverBlacklist() const {
    std::lock_guard<std::mutex> lock(m_Lock);
    return m_ActiveConfig.driverBlacklist;
}

std::vector<FILE_RULE> RuleManager::GetFileRules() const {
    std::lock_guard<std::mutex> lock(m_Lock);
    return m_ActiveConfig.fileRules;
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

bool RuleManager::TryGetFileRuleMetadata(
    const std::wstring& ruleId,
    std::wstring& outThreatDesc,
    int& outSeverity) const {
    std::lock_guard<std::mutex> lock(m_Lock);
    for (std::vector<FileRuleDefinition>::const_iterator it = m_ActiveConfig.fileRuleDefinitions.begin();
        it != m_ActiveConfig.fileRuleDefinitions.end();
        ++it) {
        if (it->id == ruleId) {
            outThreatDesc = it->threatDesc;
            outSeverity = it->severity;
            return true;
        }
    }

    return false;
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

std::wstring RuleManager::Utf8ToWString(const std::string& utf8Str) {
    return Utf8ToWStringLocal(utf8Str);
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

            if (root.contains("driver_blacklist")) {
                if (!ParseDriverBlacklist(root["driver_blacklist"], loadedConfig.driverBlacklist)) {
                    if (outError != nullptr) {
                        *outError = L"invalid driver_blacklist";
                    }
                    return false;
                }
            }

            if (root.contains("file_rules")) {
                if (!ParseFileRuleArray(
                    root["file_rules"],
                    loadedConfig.fileRuleDefinitions,
                    loadedConfig.fileRules)) {
                    if (outError != nullptr) {
                        *outError = L"invalid file_rules";
                    }
                    return false;
                }
            }

            if (root.contains("registry_rules")) {
                if (!ParseRegistryRuleArray(
                    root["registry_rules"],
                    loadedConfig.registryRuleDefinitions,
                    loadedConfig.registryRules)) {
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
                    loadedConfig.registryAllowRules)) {
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
