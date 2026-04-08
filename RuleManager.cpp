#include "RuleManager.h"
#include <windows.h>
#include <fstream>
#include <algorithm>
#include <iostream>
#include <cwctype> // [修复 1]：包含宽字符处理头文件
#include <codecvt> // [新增] 用于 UTF-8 文件流的解码转换
#include <sstream> // [新增] 用于 std::wstringstream
#include <nlohmann/json.hpp>

using json = nlohmann::json;

RuleManager::RuleManager() {}
RuleManager::~RuleManager() {}

size_t RuleManager::GetRuleCount() const {
	return m_Rules.size();
}

std::wstring RuleManager::Utf8ToWString(const std::string& utf8Str) {
	if (utf8Str.empty()) return std::wstring();

	int sizeNeeded = MultiByteToWideChar(CP_UTF8, 0, &utf8Str[0], (int)utf8Str.size(), NULL, 0);
	// [修复 8]：判断 API 调用是否成功，防止返回脏数据
	if (sizeNeeded <= 0) return std::wstring();

	std::wstring wstrTo(sizeNeeded, 0);
	int result = MultiByteToWideChar(CP_UTF8, 0, &utf8Str[0], (int)utf8Str.size(), &wstrTo[0], sizeNeeded);
	if (result == 0) return std::wstring();

	return wstrTo;
}

bool RuleManager::LoadRulesFromJson(const std::wstring& jsonFilePath) {
	// [修复 3]：改用 wifstream，专为 Windows 宽字符路径设计
	std::wifstream file(jsonFilePath.c_str());
	if (!file.is_open()) {
		return false;
	}

	// [修复 3]：注入 UTF-8 解码器。这能完美处理带 BOM 的 UTF-8 文件，并避免系统默认编码干扰
	file.imbue(std::locale(file.getloc(), new std::codecvt_utf8<wchar_t>));

	try {
		// 1. 利用 wstringstream 将宽字符流一次性全部读入内存
		std::wstringstream wss;
		wss << file.rdbuf();

		// 2. 调用 parse 静态方法，nlohmann/json 原生支持解析 std::wstring
		json rootArray = json::parse(wss.str());

		// [修复 4]：移除了所有的 file.close()，完全信任 C++ RAII，让析构函数接管句柄关闭

		for (const auto& item : rootArray) {
			DetectionRule rule;
			// 此时提取出的 item.value() 依然是 UTF-8 编码的 std::string，兼容原逻辑
			rule.id = Utf8ToWString(item.value("id", ""));
			rule.threatDesc = Utf8ToWString(item.value("threat_desc", ""));
			rule.severity = item.value("severity", 0);

			std::string innerRuleStr = item.value("rule", "{}");
			json innerRule = json::parse(innerRuleStr);

			if (innerRule.contains("matchArray")) {
				for (const auto& matchItem : innerRule["matchArray"]) {
					int position = matchItem.value("position", 0);

					if (matchItem.contains("value")) {
						for (const auto& val : matchItem["value"]) {
							std::wstring wVal = Utf8ToWString(val.get<std::string>());

							std::transform(wVal.begin(), wVal.end(), wVal.begin(), [](wchar_t c) {
								return std::towlower(c);
							});

							switch (position) {
							case 1: rule.parentProcessKeywords.push_back(wVal); break;
							case 2: rule.childProcessKeywords.push_back(wVal); break;
							case 3: rule.cmdLineKeywords.push_back(wVal); break;
							case 4: rule.parentCmdLineKeywords.push_back(wVal); break;
							default: break;
							}
						}
					}
				}
			}
			m_Rules.push_back(rule);
		}
		return true;
	}
	catch (const json::exception& e) {
		// [修复 4]：移除了 catch 块中的 file.close()，异常发生退栈时，file 自动安全析构
		return false;
	}
}

// [修复 4]：补充 parentCmdLine 参数
bool RuleManager::EvaluateProcessAgainstRules(const std::wstring& parentName, const std::wstring& childName, const std::wstring& cmdLine, const std::wstring& parentCmdLine, DetectionRule& outMatchedRule) {
	std::wstring lowerParent = parentName;
	std::wstring lowerChild = childName;
	std::wstring lowerCmd = cmdLine;
	std::wstring lowerParentCmd = parentCmdLine; // [修复 4]：处理父进程命令行

	// [修复 2]：统一使用安全 lambda 转换为小写
	auto toLowerSafe = [](wchar_t c) { return (wchar_t)towlower((wint_t)c); };
	std::transform(lowerParent.begin(), lowerParent.end(), lowerParent.begin(), toLowerSafe);
	std::transform(lowerChild.begin(), lowerChild.end(), lowerChild.begin(), toLowerSafe);
	std::transform(lowerCmd.begin(), lowerCmd.end(), lowerCmd.begin(), toLowerSafe);
	std::transform(lowerParentCmd.begin(), lowerParentCmd.end(), lowerParentCmd.begin(), toLowerSafe);

	for (const auto& rule : m_Rules) {
		bool parentHit = rule.parentProcessKeywords.empty();
		bool childHit = rule.childProcessKeywords.empty();
		bool cmdHit = rule.cmdLineKeywords.empty();
		bool parentCmdHit = rule.parentCmdLineKeywords.empty();

		for (const auto& kw : rule.parentProcessKeywords) {
			if (lowerParent.find(kw) != std::wstring::npos) { parentHit = true; break; }
		}
		for (const auto& kw : rule.childProcessKeywords) {
			if (lowerChild.find(kw) != std::wstring::npos) { childHit = true; break; }
		}
		for (const auto& kw : rule.cmdLineKeywords) {
			if (lowerCmd.find(kw) != std::wstring::npos) { cmdHit = true; break; }
		}
		// [修复 5]：真正让 parentCmdLine 参与逻辑匹配
		for (const auto& kw : rule.parentCmdLineKeywords) {
			if (lowerParentCmd.find(kw) != std::wstring::npos) { parentCmdHit = true; break; }
		}

		// AND 逻辑匹配且排除全空规则
		if (parentHit && childHit && cmdHit && parentCmdHit &&
			!(rule.parentProcessKeywords.empty() &&
				rule.childProcessKeywords.empty() &&
				rule.cmdLineKeywords.empty() &&
				rule.parentCmdLineKeywords.empty())) {

			outMatchedRule = rule;
			return true;
		}
	}
	return false;
}