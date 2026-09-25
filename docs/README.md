# 文档索引

从 [项目首页](../README.zh-CN.md) 进入。当前行为以使用说明和代码为准；历史验证记录保留当时的命令与测试结果。

## 使用与数据

- [使用指南](user/usage.md)：构建、安装、参数、录制、交互与 JSON 快照。
- [界面说明](user/ui-design.md)：页面、按键、布局与状态提示。
- [数据口径与限制](user/measurement.md)：IP 字节、进程 socket I/O、方向、RTT、重传与缺失计数。

## 实现

- [实现原理](internals/architecture.md)：根目录入口、`internal/app` 主循环、采集与探针、进程关联、NAT 和录制。
- [解析原理](internals/parsing.md)：应用协议、HTTP、TLS、QUIC、代理与域名证据。

## 计划

- [路线图](roadmap.md)：尚未实现的功能，每项写明目标、现状、做法和验收方式，以及参考过的同类工具和取舍。

## 历史记录

- [验证记录](archive/validation.md)：2026-09-23 至 2026-09-25 的本机、虚拟机和 CI 测试记录；旧命令与旧限制只描述记录时的版本。
