# socktrail

**[English](README.md) · 简体中文**

`socktrail` 是 Linux 终端实时流量观察程序。它从所选接口采集报文，并结合 eBPF 事件和内核 socket 表，在同一界面显示连接、进程、IP 流量、应用协议和可见的域名证据。IP 报文字节与进程 socket I/O 分开统计。

目前是原型：本机 Linux 6.8 上做过实机验证；其他几个 5.10 到 7.0 的内核只在虚拟机中验证了探针加载和回环流量。NAT 在本机网络命名空间网关中验收过；容器网络和 arm64 尚未验收。具体范围见 [验证记录](docs/validation.md)。

## 构建与运行

运行需要 Linux，以及支持 BTF、fentry/fexit 和 BPF ring buffer 的内核。从源码构建需要 Go 1.27。仓库包含生成的 eBPF 对象，普通构建不需要 clang。建议用 `CGO_ENABLED=0` 构建静态二进制。

也可以从 [GitHub Releases](https://github.com/jimyag/socktrail/releases) 直接下载未压缩的 Linux amd64、arm64 二进制。以下命令按当前架构下载最新版本、核对 SHA-256，并安装到 `/usr/local/bin`：

```sh
curl -fsSL https://raw.githubusercontent.com/jimyag/socktrail/main/install.sh | sh
```

目标目录不可写时会请求 `sudo`；安装后运行仍需 `sudo`，也可按[无 sudo 运行说明](docs/usage.md#不使用-sudo-运行)设置 file capabilities。

```sh
CGO_ENABLED=0 go build -o socktrail ./cmd/socktrail
sudo ./socktrail
sudo ./socktrail --interface lo
sudo ./socktrail --interface lo --interface br0
./socktrail --version
```

默认自动选择最多 8 张运行中的宿主接口；可以重复指定 `--interface` 或用逗号分隔。按 `1`—`4` 切换 PID、来源 IP、目标 IP、协议页，按 `d` 看域名，`0` 看网卡，`?` 看帮助，`q` 退出。选中连接或 PID 后按 `c` 可录制接下来 15 秒的 PCAPNG；文件可能包含明文应用数据。其他参数、交互和录制边界见 [使用指南](docs/usage.md)。

不想每次使用 `sudo` 时，可给安装后的二进制设置 file capabilities；仅授予网络权限不足以加载 eBPF。命令和限制见[无 sudo 运行说明](docs/usage.md#不使用-sudo-运行)。

## 文档

| 主题 | 内容 |
| --- | --- |
| [使用指南](docs/usage.md) | 构建、参数、界面、进程详情、PCAPNG 录制 |
| [实现原理](docs/architecture.md) | AF_PACKET 环、eBPF、进程关联、NAT、分片与非 IP 帧 |
| [解析原理](docs/parsing.md) | 应用协议、HTTP、TLS、QUIC、代理、DNS 与域名证据 |
| [数据口径与限制](docs/measurement.md) | IP 字节、socket I/O、方向、RTT、重传与丢失 |
| [验证记录](docs/validation.md) | 已验证的内核与场景、性能和剩余缺口 |

设计和实现约定见 [开发说明](docs/development.md)，页面布局见 [界面说明](docs/ui-design.md)。

## 发布

推送 `v*` tag 后，GitHub Actions 先执行检查，再使用 GoReleaser 发布 Linux amd64、arm64 静态二进制和 `checksums.txt` 到 [GitHub Releases](https://github.com/jimyag/socktrail/releases)。`socktrail --version` 输出 tag、构建时间和 Go 版本。发布前可运行 `goreleaser release --snapshot --clean` 验证构建；arm64 目前仅完成编译，尚未做运行验收。
