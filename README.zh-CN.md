<h1 align="center">socktrail</h1>

<p align="center">
  <strong>在一个终端中查看 Linux 网络流量、连接、进程和可见域名。</strong>
</p>

<p align="center">
  <a href="https://github.com/jimyag/socktrail/actions/workflows/check.yaml"><img src="https://img.shields.io/github/actions/workflow/status/jimyag/socktrail/check.yaml?branch=main&amp;label=CI" alt="CI 状态"></a>
  <a href="https://github.com/jimyag/socktrail/actions/workflows/kernels.yaml"><img src="https://img.shields.io/github/actions/workflow/status/jimyag/socktrail/kernels.yaml?branch=main&amp;label=Kernel%20matrix" alt="内核矩阵状态"></a>
  <a href="https://github.com/jimyag/socktrail/releases/latest"><img src="https://img.shields.io/github/v/release/jimyag/socktrail?label=Latest%20release" alt="最新发布版本"></a>
</p>

<p align="center">
  <a href="#为什么使用-socktrail">为什么使用 socktrail</a> ·
  <a href="#功能">功能</a> ·
  <a href="#界面截图">界面截图</a> ·
  <a href="#构建与运行">构建与运行</a> ·
  <a href="#文档">文档</a>
</p>

<p align="center">
  <a href="README.md">English</a> · <strong>简体中文</strong>
</p>

---

socktrail 是用于观察实时网络流量的 Linux 终端程序。它从所选接口采集报文，并结合 eBPF socket 探针和内核 socket 表，将本机流量关联到进程。界面显示连接、IP 流量、应用协议，以及从可观察的 HTTP、TLS、QUIC、代理和 DNS 数据中发现的域名。

目前仍是原型。本机 Linux 6.8 上做过实机验证；x86-64 上 5.10 到 7.0 的发行版内核（含 CentOS Stream 9 和 10）以及 arm64 上 6.4、6.8 的内核在虚拟机里验证了探针加载和回环流量；CI 另在 amd64 和 arm64 runner 上以 root 运行测试。NAT 在本机网络命名空间网关中验收过，Kafka、SQL Server、gRPC 等十余种真实服务的协议识别也核对过。容器网络尚未验收。数据口径和已知限制见[验证记录](docs/archive/validation.md)。

## 为什么使用 socktrail

报文、进程和域名证据回答不同的问题。socktrail 把它们放在一个界面中，同时分别统计 IP 报文字节和进程 socket I/O 字节。你可以查看哪个进程拥有连接、流量去了哪里、哪个接口看到了它，以及可见的 Host 或 SNI 能否说明目标域名。

## 功能

- 采集 IPv4、IPv6、ARP 和其他以太网流量。自动选择最多八张接口；显式指定 `--interface` 没有数量上限，也可包含回环和 tun 接口。
- 将 TCP、UDP、ICMP 和其他流量归入连接或会话，显示应用协议提示、连接状态、RTT、拥塞窗口、重传（本机 socket 使用与 `ss -ti` 类似的内核值）、DNS 响应时间和 ICMP 错误。
- 将本机 TCP/UDP socket 关联到进程，并把进程 socket RX/TX 与采集的 IP 字节分开显示。
- 按 systemd 服务或容器、cgroup、进程树、可执行文件名分组；可用 `--process`、`--pid`（含子孙进程）或 `--cgroup` 只看指定进程。
- 有 conntrack 映射时，合并 NAT 地址改写前后观测到的连接。
- 提取可见的 HTTP Host、TLS 和 QUIC SNI、代理目标与 DNS 域名提示。抓包无法看到加密的 HTTP 请求域名和真实的 ECH 内层域名。
- 在终端查看 PID、来源 IP、目标 IP、协议、域名和单网卡视图。
- 按需为选中的连接或 PID 录制之后 15 秒的 PCAPNG，也可包含按键前数秒的帧。
- 输出限时文本快照或 JSON 文档。
- 可选用离线 DB-IP Lite 国家和 ASN 数据补充连接信息。

## 界面截图

以下截图来自隔离的 Linux 网络命名空间，展示 socktrail 处理模拟流量的界面。`10.20.0.0/24` 是演示私网；图中的公网 IP 只在演示命名空间内本地分配，`.demo.example` 域名也是模拟数据。截图不包含个人流量，也没有访问外部网络。

### PID

![PID 页面，显示进程和连接详情](docs/assets/screenshots/pid.png)

### 来源 IP

![来源 IP 页面，显示演示私网地址](docs/assets/screenshots/source-ip.png)

### 目标 IP

![目标 IP 页面，显示演示流量和 GeoIP 数据](docs/assets/screenshots/destination-ip.png)

### 协议

![协议页面，显示 HTTP、TLS、DNS、ICMP 和 ARP 分组](docs/assets/screenshots/protocol.png)

### 进程分组

![按可执行文件名分组的进程页面](docs/assets/screenshots/service.png)

### 域名

![域名页面，显示 HTTP 和 TLS 域名](docs/assets/screenshots/domains.png)

### 网卡

![网卡诊断页面，显示 demo0 和回环接口](docs/assets/screenshots/interfaces.png)

## 构建与运行

运行需要 Linux，以及支持 BTF、fentry 和 BPF ring buffer 的内核：x86-64 需 5.10 及以上，arm64 需 6.4 及以上（arm64 的 fentry 依赖 ftrace 直接调用）。从源码构建需要 Go 1.27。仓库包含生成的 eBPF 对象，普通构建不需要 clang。运行时需要足够的抓包和 eBPF 加载权限，使用 `sudo` 最简单。

[GitHub Releases](https://github.com/jimyag/socktrail/releases) 提供未压缩的 Linux amd64 和 arm64 二进制。下载、校验并把最新版本安装到 `/usr/local/bin`：

```sh
curl -fsSL https://raw.githubusercontent.com/jimyag/socktrail/main/install.sh | sh
```

目标目录不可写时，安装脚本会请求 `sudo`。v0.0.1 之后的版本带构建来源证明；如果已安装并登录 GitHub CLI 2.49 或更新版本，脚本还会验证该证明，否则只校验 SHA-256。安装后可运行 `sudo socktrail`，或按 [file capabilities 设置](docs/user/usage.md#不使用-sudo-运行)运行。

从源码构建时，`task`（或 `task build`）会生成带 Git 版本和构建时间的静态二进制；`task install` 会将其安装到 `/usr/local/bin/socktrail`，并设置抓包和 eBPF 所需的 file capabilities。以普通用户运行 `task install`，它只在安装阶段调用 `sudo`。随后可直接运行 `socktrail` 做基础抓包；如果需要包括 OpenSSL 进程 SNI 和内核 TLS 在内的全部探针，而宿主机限制读取模块 BTF，请运行 `sudo socktrail`。

在仓库根目录运行 `go install .` 可将程序安装到 Go 的二进制目录；此命令不会设置 Linux file capabilities。

```sh
CGO_ENABLED=0 go build -o socktrail .
sudo ./socktrail
sudo ./socktrail --interface lo
sudo ./socktrail --interface lo --interface eth0
sudo ./socktrail --interface eth0 --duration 30s --output json
./socktrail --download-geoip-db
./socktrail --version
```

不指定 `--interface` 时，socktrail 最多选择八张运行中的接口：先选物理网卡，再选回环、隧道和宿主网桥。容器 veth、Docker 网桥和虚拟机 tap 需要显式指定 `--interface`；它接受重复参数、逗号分隔的名称，以及 `'veth*,br-*,vnet*'` 等 glob 模式。显式选择不受网卡数量限制。可用 `ip -br link` 查找接口名称。

显式选择超过八张接口时，程序会列出匹配项并请求确认。默认在内存上限为 512 MiB 的 systemd scope 中运行。非交互运行可加 `--yes`，用 `--memory-limit=1GiB` 调整上限，或用 `--memory-limit=none` 关闭限制。如果无法使用 systemd，受限模式会在抓包前报错。

不使用 `sudo` 时，需要为二进制设置 Linux file capabilities。只有网络权限不足以加载 eBPF 探针；详见[权限设置及限制](docs/user/usage.md#不使用-sudo-运行)。

按 `1`—`4` 切换 PID、来源 IP、目标 IP 和协议视图；`5` 打开进程分组页，按 `b` 在服务、cgroup、进程树和可执行文件名之间切换；`d` 看域名；`0` 看网卡诊断；`?` 看帮助；`q` 退出。按 `g` 显示或隐藏连接两端的 GeoIP；缺少数据库时，可在界面中确认下载。选中连接或 PID 后按 `c` 开始或停止 PCAPNG 录制；以 `--record-before 10s` 启动可包含按键前十秒的帧。录制文件默认保存在 `$XDG_STATE_HOME/socktrail/captures`（通常为 `~/.local/state/socktrail/captures`），可能包含明文应用数据；临时文件可用 `--capture-dir /tmp/...` 指定目录。

以普通用户运行 `socktrail --download-geoip-db`，可将可选的 [DB-IP Lite](https://db-ip.com/db/lite.php) 国家和 ASN 数据库安装到 `$XDG_DATA_HOME/socktrail/geoip`（通常为 `~/.local/share/socktrail/geoip`）。抓包不会自动联网，没有数据库也能使用；在 TUI 中按 `g` 可明确选择下载。启用后，连接表为来源和目标公网 IP 分别显示国旗、ASN 和组织简称；选中连接的详情和 JSON 快照保留完整名称。`--geoip-dir` 可选择其他数据库目录。DB-IP Lite 使用 CC BY 4.0 许可。

## 文档

[文档索引](docs/README.md)汇集中文使用指南、实现说明和历史验证记录。另见 [English README](README.md)。

## 开发

```sh
go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.14.0 run ./...
go test -race ./...
CGO_ENABLED=0 go build .
```

GitHub Actions 还会在推送到 `main` 和提交 PR 时检查 Go 格式，在 amd64、arm64 runner 上以 root 运行探针和抓包测试，用 `test/smoke.sh` 对测试流量生成快照，并确认提交的 eBPF 对象与源码一致。[内核矩阵](.github/workflows/kernels.yaml)每周以及探针变化时，使用 `test/vm/run.sh` 在 QEMU 中逐一启动 `test/vm/kernels.txt` 列出的发行版内核；本地可运行 `test/vm/run.sh amd64` 或 `test/vm/run.sh arm64`，后面也可指定内核名称。

## 发布

推送 `v*` tag 后，GitHub Actions 会先执行检查，再用 GoReleaser 将 Linux amd64、arm64 静态二进制和 `checksums.txt` 发布到 [GitHub Releases](https://github.com/jimyag/socktrail/releases)，并为构建生成来源证明。可用 `gh attestation verify socktrail_linux_amd64 --repo jimyag/socktrail` 校验下载的二进制。`socktrail --version` 输出 tag、构建时间和 Go 版本。发布前可运行 `goreleaser release --snapshot --clean` 在本地验证构建。
