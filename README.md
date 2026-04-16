# edr_hostguard

`edr_detect` 分支当前对应 HostGuard 的“纯进程 + 注册表版”用户态仓库。

## 仓库定位

本仓库包含轻量化 HostGuard 部署模型下的用户态控制端，负责：

- 加载并管理配套内核驱动
- 向驱动下发进程裁决配置与注册表规则配置
- 通过进程通信端口接收进程创建裁决请求
- 从驱动拉取注册表事件与响应动作遥测
- 对已运行进程执行内核辅助终止响应

## 当前防护范围

本分支当前保留：

- 进程创建裁决
- 进程白名单规则
- 注册表拦截规则
- 注册表白名单规则
- 运行状态与遥测查询

本分支当前已移除：

- 驱动黑名单与驱动专项裁决端口
- 驱动加载拦截
- 文件规则与文件拦截
- 基于镜像加载的可疑驱动遥测

## 目录说明

- `HostGuard.cpp`：服务与命令行入口、进程裁决循环、事件处理
- `RuleManager.*`：JSON 规则加载与运行时快照
- `DriverUtils.*`：驱动/服务安装与 IOCTL 辅助函数
- `Common/PebMonitorShared.h`：与内核驱动共享的 ABI 协议头

## 构建说明

推荐环境：

- Visual Studio 2022
- `Legacy2012 | x64` 配置
- 已还原到 `packages/` 目录下的 `nlohmann.json` NuGet 包

输出文件：

- `x64\\Legacy2012\\HostGuard.exe`

## 规则说明

本分支当前只使用进程和注册表相关规则，核心配置段包括：

- `process_rules`
- `process_allow_rules`
- `registry_rules`
- `registry_allow_rules`
- `process_verdict`
- `response`

旧分支中的驱动专项规则和文件规则在这个分支里不再使用。
