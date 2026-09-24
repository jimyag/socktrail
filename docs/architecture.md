# 实现原理

从 [中文首页](../README.zh-CN.md) 进入。这里说明数据从采集到页面的路径；已验证场景见 [验证记录](validation.md)。

```text
AF_PACKET/TPACKET_V3 → 报文解码 ─────┐
eBPF socket 与进程事件 ──────────────┼→ 连接与进程关联 → 整机聚合 → 终端页面
/proc socket 表、conntrack 映射 ─────┘
```

主入口在 [main_linux.go](../cmd/socktrail/main_linux.go)，抓包环在 [socket_linux.go](../internal/capture/socket_linux.go)，报文解码在 [packet.go](../internal/capture/packet.go)。图省略了各接口独立采集、异步查询和录制分支。

## 采集与关联概览

每张接口各有一个 AF_PACKET socket。内核把帧写入 TPACKET_V3 环，读取方按块交给主循环；[报文解码器](../internal/capture/packet.go)识别链路层、IP、传输层和分片。主循环按连接键维护流，再把应用协议和域名证据附到流上。录制 PCAPNG 时才切换为保留完整帧。

本机进程归属来自 eBPF 的 connect、accept 和 socket I/O 事件；启动前已存在或错过探针挂载时机的 socket，再从内核 socket 表补全。NAT 查询把改写前后的元组关联起来。整机视图合并跨接口观测，详情保留证据来源；[数据口径](measurement.md)说明为什么这些字节不能直接相加。

## 运行条件与兼容性

运行需 root 或相应的 `CAP_BPF`、`CAP_PERFMON`、`CAP_NET_RAW`、`CAP_NET_ADMIN` 权限；5.10 内核设置 eBPF memlock 限额还需要 `CAP_SYS_RESOURCE`。file capabilities 的安装命令和 `/proc`、OpenSSL 探针限制见[使用指南](usage.md#不使用-sudo-运行)。内核要支持 fentry/fexit 和 BPF ring buffer，并带 BTF（`CONFIG_DEBUG_INFO_BTF=y`，存在 `/sys/kernel/btf/vmlinux`）。

x86-64 上已在 Debian 11 的 5.10、Ubuntu 的 5.11、5.13、5.15（22.04）、6.8（24.04）、6.17、7.0 内核里实测三个探针都能加载。

5.4 及更早的内核没有 fentry；Ubuntu 的 5.8 内核没有 BTF，都无法运行。

内核接口的版本差异由程序自己处理：recvmsg 在 5.19 去掉了 nonblock 参数，探针按内核 BTF 里的参数个数加载对应版本；5.12 之前 tracing 程序不能取 socket cookie，socket 层读取改用 socket 的内核地址区分连接。

基础 PID/抓包能力缺失时程序报错。

### OpenSSL SNI 探针

OpenSSL 用户态探针默认尝试启用；不可用时继续抓包，但顶部标出 `OPENSSL-PROBE-UNAVAILABLE`，`!` 状态页显示原因与事件数。

它目前针对 x86_64 上动态链接的系统 OpenSSL 3/1.1，读取 `SSL_ctrl`/`SSL_get_servername` 暴露的 SNI，并通过 `SSL_set_fd`、`BIO_new_socket` 或 `SSL_connect` 期间的同线程 TCP 发送关联 socket；后者已用 curl 8.5 的自定义 BIO 路径在 OpenSSL 3.0.13 上实测。

同线程路径是时间窗口关联：如果握手回调同时向其他 TCP socket 发送数据，可能产生错误关联；跨线程发送则可能漏报。

并非每次握手都会产生额外域名：正常捕获到 ClientHello 时，报文解析通常已有相同 SNI。

Go TLS、静态链接库、其他 TLS 库、未覆盖的自定义 BIO 调用路径、真实 ECH 的内层名和 HTTP/2/3 加密的请求域名不在当前覆盖范围。

可用 `--openssl-probe=false` 关闭。

### socket 前缀探针

socket 层前缀读取同样默认开启，不可用时顶部标出 `SOCKET-SNIFF-UNAVAILABLE`，`!` 状态页显示读取的数据块、内核丢失和队列丢弃数，可用 `--socket-sniff=false` 关闭。

### NAT 依赖与探针生成

NAT 映射要求内核已加载 `nf_nat` 和 `nf_conntrack_netlink`（或编译进内核）；没有加载时程序不去加载模块，`!` 状态页说明原因，其余功能照常。

重新生成探针对象才需要 clang、libbpf 头文件及 `go generate ./internal/probe ./internal/tlsprobe ./internal/sockstream`。

## AF_PACKET 环形缓冲

抓包用 AF_PACKET 的 TPACKET_V3 环形缓冲：内核把报文写进与程序共享的内存块，块写满或 100 ms 到期才唤醒一次读取方，解析直接读环里的数据，不再逐包系统调用和复制。每张接口 4 MiB，计入进程 RSS。每帧只保留前 16 KiB 加 256 B 头部余量（录制期间保留完整帧），这正是解析器会读的范围；被截掉的只是 TSO/GRO 大帧后面的负载，不算截断。在本机两张 veth 间的 20 Gbps TCP 和每秒约 10 万个 64 B UDP 报文下，采集用 0.3 和 0.13 个核，没有丢包，详见验证记录。

## 进程与 socket 关联

[eBPF 探针](../internal/probe/ebpf_linux.go)把本机 socket 操作送到主循环，事件包含协议、端点、PID、进程启动标识、角色与应用字节数。[collector.event](../cmd/socktrail/main_linux.go)先按 PID 和启动标识累计 socket I/O，再尝试用端点关联已观测的流。暂时没有流的 I/O 最多等待 2 秒；仍无法匹配的字节计入未关联统计。TCP 的 connect/accept 角色与实际执行 send/recv 的 PID 分开记录，避免把共享 socket 的 I/O 算给连接建立者。

## ICMP 与非 IP 帧

ICMP/ICMPv6 的 Echo 按两端地址和 identifier 合成一条流，显示请求/应答数、最近序号和 RTT，ping 洪泛不会把流表撑满；其他消息按两端地址和 type/code 成流，显示类型名，邻居发现和重定向显示目标地址，“需要分片”显示 MTU。错误报文解出所引用原始报文的协议和端点，对应的 TCP/UDP 流在状态列标出错误名，例如 UDP 发往关闭端口后显示 `port-unreachable`。本机进程发出的 Echo 请求，无论走原始 socket 还是 ping socket，都按对端地址和 identifier 关联到发送进程；入站 Echo 由内核应答，内核生成的错误报文也没有进程。

## 链路层与隧道接口

没有 IP 头的帧同样计入：ARP 显示请求/应答数和各 IP 宣告的 MAC 地址；PPPoE 会话里的 IPv4/IPv6 解开后按普通流统计；其他帧按 EtherType 分组，802.3 长度帧归为 `802.3 LLC`，这类流没有 IP 端点，显示为 `-`。tun 类接口没有链路层头，按帧里的 IP 报文直接解析；录制 PCAPNG 时给这类帧补一个空以太网头，保持文件只有一种链路类型。

## IP 分片归属

IPv4/IPv6 分片：后续分片按（源地址、目的地址、协议、分片 ID）归入首片所在的流，包括大包 ping 的 ICMP Echo；首片没抓到时，后续分片单独成流。关联表最多 4096 项，30 秒过期。

## NAT 映射

查询和元组解析见 [conntrack_linux.go](../internal/conntrack/conntrack_linux.go)。

NAT 映射：新的 TCP/UDP 流出现时，在单独的 goroutine 里向 conntrack 查一次这个元组（先按报文方向，查不到再反向，改写后的一侧对应应答方向），只保留确实被改写过的条目，按两个元组都能找到；多播不查。不订阅 conntrack 事件，因为那会让内核为整机每条连接生成事件。查询队列满时跳过（状态页计数），连接只是不关联。条目随关联的流一起续期，空闲 5 分钟后删除，最多 65,536 条。本机进程的 socket 用的是它那一侧的元组，关联后该进程的角色和 socket I/O 会挂到抓到的另一侧报文上。

## 内核 socket 表补全进程

读取和进程关联见 [procnet_linux.go](../cmd/socktrail/procnet_linux.go)。

内核 socket 表（`/proc/net/tcp`、`tcp6`、`udp`、`udp6` 与 `/proc/<pid>/fd`，即 ss/netstat 的数据源）是进程归属的补充来源。存在两端都没有 PID 的 TCP/UDP 连接时，程序每 10 秒最多在后台读一次（扫描所有进程的文件描述符在本机约 6,400 个描述符时要 30 ms，描述符越多越久，不能卡住主循环），读完再应用；它给启动前已建立、或 connect/accept 早于探针挂载的连接补上进程，并按上文规则确定中途开始的 TCP 连接方向。启动时先读一份，用来判断哪些连接早于抓包。只覆盖当前网络命名空间；在两次读取之间开始又结束的连接，这里拿不到。
