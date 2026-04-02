#pragma once
#include <string>
#include <vector>

// ===========================================================================
// 检测规则结构体
// ===========================================================================
struct DetectionRule {
	std::wstring id;
	std::wstring threatDesc;
	int severity;
	std::vector<std::wstring> parentProcessKeywords; // position: 1
	std::vector<std::wstring> childProcessKeywords;  // position: 2
	std::vector<std::wstring> cmdLineKeywords;       // position: 3
	std::vector<std::wstring> parentCmdLineKeywords; // position: 4
};

// ===========================================================================
// 规则管理与匹配引擎类
// ===========================================================================
class RuleManager {
public:
	RuleManager();
	~RuleManager();

	// 从 JSON 文件加载规则
	bool LoadRulesFromJson(const std::wstring& jsonFilePath);

	// 匹配进程事件是否命中规则
	// [修复 4]：补充 parentCmdLine 参数
	bool EvaluateProcessAgainstRules(
		const std::wstring& parentName,
		const std::wstring& childName,
		const std::wstring& cmdLine,
		const std::wstring& parentCmdLine,
		DetectionRule& outMatchedRule
	);

	// 获取当前加载的规则数量
	size_t GetRuleCount() const;

private:
	std::vector<DetectionRule> m_Rules; // 内部维护的规则库

	// 内部辅助函数：UTF-8 转 std::wstring
	std::wstring Utf8ToWString(const std::string& utf8Str);
};