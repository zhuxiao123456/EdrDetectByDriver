#include <windows.h>
#include <iostream>
#include <thread>
#include <vector>
#include <string>

// 引入我们拆分出来的模块
#include "CommonUtils.h"
#include "DriverUtils.h"
#include "Shared.h"
#include "resource.h"
#include "RuleManager.h"

// ===========================================================================
// 全局变量实例化
// ===========================================================================
RuleManager g_RuleManager; // 实例化全局规则管理器
std::wstring g_ExeDirectory; // [修复] 声明全局变量，供当前文件及 LogMessage 使用

// ===========================================================================
// 独立线程：专门监听内核底层的驱动拦截告警
// ===========================================================================
void DriverEventMonitorThread() {
	// 让子线程自己申请一个全新的、独立的通信句柄
	HANDLE hDriverDevice = CreateFileW(L"\\\\.\\PebMonitor", GENERIC_READ | GENERIC_WRITE,
		0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	if (hDriverDevice == INVALID_HANDLE_VALUE) {
		LogMessage(L"[-] 驱动遥测通道连接失败！");
		return;
	}

	DRIVER_EVENT driverEvent = { 0 };
	DWORD bytesReturned = 0;

	LogMessage(L"[+] 驱动防御遥测通道已开启，正在监听底层拦截事件...");

	while (true) {
		// 使用专属句柄，即使这里阻塞，也不会影响主线程抓进程
		BOOL success = DeviceIoControl(hDriverDevice, IOCTL_GET_DRIVER_EVENT,
			NULL, 0, &driverEvent, sizeof(DRIVER_EVENT), &bytesReturned, NULL);

		if (success && bytesReturned == sizeof(DRIVER_EVENT)) {
			std::wstring blockedDriverPath(driverEvent.ImagePath);
			LogMessage(L"#########################################################");
			LogMessage(L"[!] 战报：成功在 Ring 0 底层拦截高危漏洞驱动加载！");
			LogMessage(L"    └─ 目标驱动: " + blockedDriverPath);
			LogMessage(L"#########################################################");
		}
		else {
			Sleep(100);
		}
	}
	CloseHandle(hDriverDevice);
}

// ===========================================================================
// 主函数
// ===========================================================================
int main() {
	// 为了在控制台正确显示中文
	setlocale(LC_ALL, "");

	// =======================================================================
	// [新增] 快速失败检查：是否为管理员权限
	// =======================================================================
	if (!IsRunAsAdmin()) {
		std::wcout << L"[-] 致命错误：必须以【管理员身份】运行此防御系统！" << std::endl;
		std::wcout << L"    请右键点击 exe，选择“以管理员身份运行”。" << std::endl;
		system("pause");
		return 1;
	}

	// =======================================================================
	// 禁用控制台的“快速编辑模式”和“插入模式”，防止鼠标点击导致线程假死
	// =======================================================================
	HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
	DWORD mode;
	if (GetConsoleMode(hStdin, &mode)) {
		mode &= ~ENABLE_QUICK_EDIT_MODE; // 移除快速编辑模式
		mode &= ~ENABLE_INSERT_MODE;     // 移除插入模式
		SetConsoleMode(hStdin, mode);
	}

	// 1. 初始化全局路径
	g_ExeDirectory = GetExeDirectory();
	std::wstring driverPath = g_ExeDirectory + L"PebMonitor.sys";
	std::wstring rulesPath = g_ExeDirectory + L"rules.json";

	std::wcout << L"[*] 正在初始化 Hostguard 终端防御系统..." << std::endl;
	std::wcout << L"[*] 当前工作目录: " << g_ExeDirectory << std::endl;

	// 2. 加载规则库 (调用封装好的类)
	if (g_RuleManager.LoadRulesFromJson(rulesPath)) {
		wchar_t msg[256];
		swprintf_s(msg, L"[+] 成功加载 %zu 条检测规则。", g_RuleManager.GetRuleCount());
		LogMessage(msg);
	}
	else {
		LogMessage(L"[!] 警告: 未能成功加载 JSON 规则库或文件不存在，将以空规则模式运行。");
	}

	// 3. 判断系统位数，选择释放哪一个驱动
	int resourceId = Is64BitOS() ? IDR_SYS64 : IDR_SYS32;
	std::wcout << L"[*] 探测到操作系统架构: " << (Is64BitOS() ? L"x64" : L"x86") << std::endl;

	// 4. 释放驱动文件 (内部自带错误处理与日志)
	if (DropDriverFromResource(resourceId, driverPath)) {
		std::wcout << L"[+] 驱动文件已成功释放至: " << driverPath << std::endl;
	}
	else {
		std::wcout << L"[-] 释放驱动失败！继续尝试加载已有文件..." << std::endl;
	}

	// 5. 自动加载驱动
	std::wcout << L"[*] 正在向内核注册 PebMonitor 服务..." << std::endl;
	if (LoadKernelDriver(driverPath, L"PebMonitor")) {
		std::wcout << L"[+] 内核驱动加载成功！雷达已上线。" << std::endl;
	}
	else {
		std::wcout << L"[!] 驱动加载失败！请检查：\n  1. 杀毒软件是否拦截？\n  2. 是否关闭了安全启动(Secure Boot)并处于测试模式？" << std::endl;
		system("pause");
		return 1;
	}

	// 6. 连接驱动通信端口
	HANDLE hDevice = CreateFileW(L"\\\\.\\PebMonitor", GENERIC_READ | GENERIC_WRITE,
		0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	if (hDevice == INVALID_HANDLE_VALUE) {
		std::cerr << "[!] 无法连接驱动通信端口。请确保 PebMonitor.sys 已成功加载。" << std::endl;
		system("pause");
		return 1;
	}

	// 7. 更新驱动内置拦截黑名单
	ClearDriverRules(hDevice);
	std::vector<std::wstring> badDrivers = {
		L"vulndriver.sys",
		L"Warsaw_PM.sys",
		L"RTCore64.sys",     // 常见的自带漏洞驱动 (BYOVD)
		L"gdrv.sys"          // 常见的自带漏洞驱动
	};
	for (const auto& driver : badDrivers) {
		if (AddDriverRule(hDevice, driver)) {
			std::wcout << L"[+] 成功下发底层驱动拦截策略: " << driver << std::endl;
		}
	}

	// =======================================================================
	// 启动旁路监听线程
	// =======================================================================
	std::thread driverThread(DriverEventMonitorThread);
	driverThread.detach(); // 分离线程，让它在后台默默运行

	LogMessage(L"[+] detect.exe 主引擎启动完毕，开始实时进程研判...");

	PROCESS_EVENT eventBuffer = { 0 };
	DWORD bytesReturned = 0;

	// =======================================================================
	// 核心主循环
	// =======================================================================
	while (true) {
		BOOL success = DeviceIoControl(hDevice, IOCTL_GET_PROCESS_EVENT,
			NULL, 0, &eventBuffer, sizeof(PROCESS_EVENT), &bytesReturned, NULL);

		if (success && bytesReturned == sizeof(PROCESS_EVENT)) {
			std::wstring parentName = GetProcessNameByPid(eventBuffer.ParentProcessId);
			std::wstring childName = GetProcessNameByPid(eventBuffer.ProcessId);
			std::wstring cmdLine(eventBuffer.CommandLine);

			// [新增修改] 目前内核驱动暂未传递父进程命令行，先传入空字符串，防编译报错与崩溃
			std::wstring parentCmdLine = L"";

			PROCESS_VERDICT verdict = { 0 };
			verdict.ProcessId = eventBuffer.ProcessId;
			verdict.BlockProcess = FALSE;

			DetectionRule matchedRule;
			// [修改] 适配重构后的 4 参数接口：parentName, childName, cmdLine, parentCmdLine
			if (g_RuleManager.EvaluateProcessAgainstRules(parentName, childName, cmdLine, parentCmdLine, matchedRule)) {
				LogMessage(L"[!] ==================================================");
				LogMessage(L"[!] 触发规则 ID: " + matchedRule.id);
				LogMessage(L"[!] 威胁描述: " + matchedRule.threatDesc);
				LogMessage(L"[!] 父进程名: " + parentName);
				LogMessage(L"[!] 子进程名: " + childName);
				LogMessage(L"[!] 命中的命令行: " + cmdLine);
				LogMessage(L"[!] 执行动作: 拦截 (Severity: " + std::to_wstring(matchedRule.severity) + L")");
				LogMessage(L"[!] ==================================================");

				verdict.BlockProcess = TRUE;
			}

			// 发送判决结果回内核
			DeviceIoControl(hDevice, IOCTL_SEND_VERDICT,
				&verdict, sizeof(PROCESS_VERDICT),
				NULL, 0, &bytesReturned, NULL);
		}
		else {
			Sleep(50);
		}
	}

	CloseHandle(hDevice);
	return 0;
}