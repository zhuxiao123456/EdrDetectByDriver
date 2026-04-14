# edr_driver

`driver_module` 分支当前对应 HostGuard 的“纯进程 + 注册表版”内核驱动仓库。

## 仓库定位

本仓库包含 HostGuard 使用的内核侧防护模块，负责：

- 通过进程通信端口进行同步进程创建裁决
- 在注册表预操作阶段执行拦截与阻断
- 维护注册表事件与响应动作的内核事件队列
- 提供运行状态查询与配置同步能力
- 提供内核辅助进程终止 IOCTL

## 当前防护范围

本分支当前保留：

- 进程创建回调
- 注册表回调
- 用户态进程裁决通信端口
- 注册表事件遥测

本分支当前已移除：

- 驱动专项裁决端口
- 驱动黑名单与 Trie 匹配逻辑
- 驱动加载镜像通知回调
- 文件规则与文件拦截回调

说明：驱动仍然保留 FltMgr 注册，因为当前进程通信端口建立在该路径上；但本分支已经不启用文件操作回调。

## 目录说明

- `PebMonitor.cpp`：驱动入口、全局状态、通信端口生命周期
- `MonitorCallbacks.cpp`：进程与注册表回调逻辑
- `IoctlDispatch.cpp`：设备控制分发与运行状态查询
- `Common/PebMonitorShared.h`：与 HostGuard 共享的 ABI 协议头

## 构建说明

推荐环境：

- Visual Studio 2022 + WDK
- `Legacy2012 | x64`
- 本地无签名验证时使用 `SignMode=Off`

输出文件：

- `x64\\Legacy2012\\DriverModule.sys`

## 集成关系

本分支设计上应与 `edr_hostguard` 仓库的 `edr_detect` 分支配套使用。两侧通过 `Common/PebMonitorShared.h` 共享一套已经收缩后的协议定义，当前仅暴露进程与注册表相关字段。
