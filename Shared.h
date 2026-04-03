#pragma once

// ===========================================================================
// 环境适配：自动区分是编译驱动还是编译 EXE
// ===========================================================================
#ifdef _KERNEL_MODE
	// 内核态编译环境
#include <ntifs.h> 
#else
	// 用户态编译环境 (detect.exe)
#include <windows.h>
#include <winioctl.h>
#endif

// ===========================================================================
// 定义控制码 (IOCTL Codes)
// ===========================================================================
// 【核心修复 1】：必须使用与驱动完全相同的设备类型 0x8000
#define PEB_MONITOR_DEVICE 0x8000

#define IOCTL_GET_PROCESS_EVENT  CTL_CODE(PEB_MONITOR_DEVICE, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SEND_VERDICT       CTL_CODE(PEB_MONITOR_DEVICE, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_GET_DRIVER_EVENT   CTL_CODE(PEB_MONITOR_DEVICE, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ADD_DRIVER_RULE    CTL_CODE(PEB_MONITOR_DEVICE, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_CLEAR_DRIVER_RULES CTL_CODE(PEB_MONITOR_DEVICE, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)

// 限制黑名单驱动名称的最大长度 (包含结束符)
#define MAX_RULE_LENGTH 256

// ===========================================================================
// 通信数据结构 (必须与驱动强一致)
// ===========================================================================

// 事件结构体：驱动 -> 用户态
typedef struct _PROCESS_EVENT {
	ULONG ProcessId;
	ULONG ParentProcessId;
	WCHAR CommandLine[1024]; // 提取到的真实启动命令行
} PROCESS_EVENT, *PPROCESS_EVENT;

// 裁决结构体：用户态 -> 驱动
typedef struct _PROCESS_VERDICT {
	ULONG ProcessId;
	BOOLEAN BlockProcess;    // TRUE 为拦截，FALSE 为放行
} PROCESS_VERDICT, *PPROCESS_VERDICT;

// 驱动拦截事件结构体
typedef struct _DRIVER_EVENT {
	WCHAR ImagePath[512];    // 【核心修复 2】：必须是 512，与内核保持绝对一致
} DRIVER_EVENT, *PDRIVER_EVENT;

// 下发规则的结构体
typedef struct _BLACKLIST_RULE {
	WCHAR DriverName[MAX_RULE_LENGTH];
} BLACKLIST_RULE, *PBLACKLIST_RULE;