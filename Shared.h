#pragma once

// ===========================================================================
// 注意：当前这份 Shared.h 是【驱动端专用版】！
// 如果你要把这个文件复制给用户态的 detect.exe 项目使用，
// 请务必将下面的 #include <ntifs.h> 替换为：
// #include <windows.h> 
// #include <winioctl.h>
// ===========================================================================
#include <ntifs.h>

#define MAX_RULE_LENGTH 256

// IOCTL 定义
#define PEB_MONITOR_DEVICE 0x8000
#define IOCTL_GET_PROCESS_EVENT  CTL_CODE(PEB_MONITOR_DEVICE, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SEND_VERDICT       CTL_CODE(PEB_MONITOR_DEVICE, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_GET_DRIVER_EVENT   CTL_CODE(PEB_MONITOR_DEVICE, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ADD_DRIVER_RULE    CTL_CODE(PEB_MONITOR_DEVICE, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_CLEAR_DRIVER_RULES CTL_CODE(PEB_MONITOR_DEVICE, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)

// 进程事件结构
typedef struct _PROCESS_EVENT {
	ULONG ProcessId;
	ULONG ParentProcessId;
	WCHAR CommandLine[1024];
} PROCESS_EVENT, *PPROCESS_EVENT;

// 进程拦截判决
typedef struct _PROCESS_VERDICT {
	ULONG ProcessId;
	BOOLEAN BlockProcess;
} PROCESS_VERDICT, *PPROCESS_VERDICT;

// 驱动拦截事件结构
typedef struct _DRIVER_EVENT {
	WCHAR ImagePath[512];
} DRIVER_EVENT, *PDRIVER_EVENT;

// 黑名单规则结构
typedef struct _BLACKLIST_RULE {
	WCHAR DriverName[MAX_RULE_LENGTH];
} BLACKLIST_RULE, *PBLACKLIST_RULE;