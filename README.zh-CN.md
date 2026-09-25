# socktrail

**[English](README.md) · 简体中文**

`socktrail` 是 Linux 终端实时流量观察程序。它从所选接口采集报文，并结合 eBPF 事件和内核 socket 表，在同一界面显示连接、进程、IP 流量、应用协议和可见的域名证据。IP 报文字节与进程 socket I/O 分开统计。

目前是原型：本机 Linux 6.8 上做过实机验证；x86-64 上 5.10 到 7.0 的发行版内核（含 CentOS Stream 9、10）和 arm64 上 6.4、6.8 的内核在虚拟机里验证了探针加载和回环流量，CI 另在 amd64 和 arm64 的 runner 上以 root 运行测试。NAT 在本机网络命名空间网关中验收过，Kafka、SQL Server、gRPC 等十余种真实服务的协议识别也核对过；容器网络尚未验收。具体范围见 [验证记录](docs/archive/validation.md)。

## 构建与运行

运行需要 Linux，以及支持 BTF、fentry/fexit 和 BPF ring buffer 的内核：x86-64 需 5.10 及以上，arm64 需 6.4 及以上（arm64 的 fentry 依赖 6.4 才有的 ftrace 直接调用）。从源码构建需要 Go 1.27。仓库包含生成的 eBPF 对象，普通构建不需要 clang。建议用 `CGO_ENABLED=0` 构建静态二进制。

也可以从 [GitHub Releases](https://github.com/jimyag/socktrail/releases) 直接下载未压缩的 Linux amd64、arm64 二进制。以下命令按当前架构下载最新版本、核对 SHA-256，并安装到 `/usr/local/bin`：

```sh
curl -fsSL https://raw.githubusercontent.com/jimyag/socktrail/main/install.sh | sh
```

目标目录不可写时会请求 `sudo`。v0.0.1 之后的版本带构建来源证明，装有 2.49 及以上版本并已登录的 GitHub CLI 时，安装脚本还会用 `gh attestation verify` 确认二进制出自本仓库的发布流程；否则只核对 SHA-256。安装后运行 `sudo socktrail`，也可按[无 sudo 运行说明](docs/user/usage.md#不使用-sudo-运行)设置 file capabilities。

```sh
CGO_ENABLED=0 go build -o socktrail .
sudo ./socktrail
sudo ./socktrail --interface lo
sudo ./socktrail --interface lo --interface br0
sudo ./socktrail --interface br0 --duration 30s --output json
./socktrail --version
```

默认自动选择最多 8 张运行中的宿主接口；可以重复指定 `--interface` 或用逗号分隔，显式指定没有数量上限。按 `1`—`4` 切换 PID、来源 IP、目标 IP、协议页，按 `5` 看进程分组（`g` 在服务、cgroup、进程树、可执行文件名四种分组间切换），按 `d` 看域名，`0` 看网卡，`?` 看帮助，`q` 退出。用 `--process`、`--pid`（含子孙进程）或 `--cgroup` 可以只看指定的进程。本机 TCP 连接的 RTT、拥塞窗口和重传取自内核，与 `ss -ti` 一致。选中连接或 PID 后按 `c` 可录制接下来 15 秒的 PCAPNG，以 `--record-before 10s` 启动时文件还包含按键前 10 秒的帧；文件可能包含明文应用数据。`--duration` 输出限时快照，加 `--output json` 输出 JSON。其他参数、交互和录制边界见 [使用指南](docs/user/usage.md)。

不想每次使用 `sudo` 时，可给安装后的二进制设置 file capabilities；仅授予网络权限不足以加载 eBPF。命令和限制见[无 sudo 运行说明](docs/user/usage.md#不使用-sudo-运行)。

从源码构建可执行 `task` 或 `task build`，安装可执行 `task install`。构建时注入 Git 版本和构建时间；安装任务会把程序放到 `/usr/local/bin/socktrail`，并设置抓包和 eBPF 所需的 file capabilities。以普通用户执行 `task install`，安装步骤会调用 `sudo`；随后可直接运行 `socktrail` 做基础抓包。需要完整的 OpenSSL 进程 SNI、内核 TLS 探针等功能时运行 `sudo socktrail`。录制文件默认保存在 `$XDG_STATE_HOME/socktrail/captures`（通常为 `~/.local/state/socktrail/captures`），需要临时文件时用 `--capture-dir /tmp/...` 指定。

在仓库根目录运行 `go install .` 也可安装到 Go 的二进制目录；这个命令不会设置 Linux file capabilities。

## 文档

从[文档索引](docs/README.md)进入使用指南、界面与数据口径说明、实现原理和历史验证记录。

## 开发与 CI

```sh
go vet ./...
go test -race ./...
CGO_ENABLED=0 go build .
```

GitHub Actions 在推送到 `main` 和 PR 时检查格式、vet 和测试；在 amd64、arm64 两种 runner 上以 root 运行探针、socket 层读取、抓包环和 conntrack 的测试，再用 [test/smoke.sh](test/smoke.sh) 对测试流量做一次 JSON 快照核对；另检查提交的 eBPF 对象与源码一致（按 `go generate ./internal/...` 重新生成后逐字节比较）。[内核矩阵](.github/workflows/kernels.yaml)每周以及探针源码变化时，用 [test/vm/run.sh](test/vm/run.sh) 在 QEMU 里启动 [kernels.txt](test/vm/kernels.txt) 列出的发行版内核，每个内核一个作业、并行运行；本地可直接运行 `test/vm/run.sh amd64` 或 `test/vm/run.sh arm64`，后面可跟内核名只跑其中几个。

## 发布

推送 `v*` tag 后，GitHub Actions 先执行检查，再使用 GoReleaser 发布 Linux amd64、arm64 静态二进制和 `checksums.txt` 到 [GitHub Releases](https://github.com/jimyag/socktrail/releases)，并为它们生成构建来源证明，可用 `gh attestation verify socktrail_linux_amd64 --repo jimyag/socktrail` 核对。`socktrail --version` 输出 tag、构建时间和 Go 版本。发布前可运行 `goreleaser release --snapshot --clean` 验证构建。
