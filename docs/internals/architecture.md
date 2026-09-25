# 实现原理

从 [中文首页](../../README.zh-CN.md) 进入。这里说明数据从采集到页面的路径和实现时遵守的约定；已验证场景见 [验证记录](../archive/validation.md)。

```text
AF_PACKET/TPACKET_V3 → 报文解码 ─────┐
eBPF socket 与进程事件 ──────────────┼→ 连接与进程关联 → 整机聚合 → 终端页面 / 快照
/proc socket 表、conntrack 映射 ─────┘
```

主入口在 [main_linux.go](../../main_linux.go)，采集主循环在 [app_linux.go](../../internal/app/app_linux.go)，抓包环在 [socket_linux.go](../../internal/capture/socket_linux.go)，报文解码在 [packet.go](../../internal/capture/packet.go)。图省略了各接口独立采集、异步查询和录制分支。

## 设计约定

- 三种数字分开：报文的 IP 字节来自采集点，进程的 socket I/O 来自 `sendmsg`/`recvmsg` 的返回值，域名证据是连接级的名字或请求计数。它们口径不同，界面和快照都不把它们相加，也不互相核对成相等。[数据口径](../user/measurement.md)逐项说明。
- 不确定就显示未知：连接方向只由 SYN、connect/accept、客户端首个报文或内核 socket 表确定，不按端口猜；PID 关联不上显示未知，多个候选显示歧义；证据冲突时保留报文里的名字并标出冲突。
- 进程身份是 PID 加进程启动时间，进程名只是标签。PID 被复用后，新旧进程分别统计，历史不被覆盖。
- 连接键是地址族、协议、两端地址和端口；同一五元组上的新 SYN 开始新的一代。
- 所有索引都有容量、过期时间和淘汰计数；丢包、截断、事件丢失、解析失败都在界面上可见，不把缺口当成零流量。
- 不读 TLS 明文，不保存请求正文。报文和 socket 层只读握手、请求头这类用于命名的前段，解析后丢弃；只有用户按 `c` 录制时才把原始帧写入文件。
- 热路径逐包不做系统调用、不分配内存；需要保留的数据自行复制，因为报文负载直接引用抓包环。

## 采集与关联概览

每张接口各有一个 AF_PACKET socket。内核把帧写入 TPACKET_V3 环，读取方按块交给主循环；[报文解码器](../../internal/capture/packet.go)识别链路层、IP、传输层和分片。主循环按连接键维护流，再把应用协议和域名证据附到流上。

本机进程归属来自 eBPF 的 connect、accept 和 socket I/O 事件；启动前已存在或错过探针挂载时机的 socket，再从内核 socket 表补全。NAT 查询把改写前后的元组关联起来。整机视图合并跨接口观测，详情保留证据来源。

## 运行条件与兼容性

运行需 root 或相应的 `CAP_BPF`、`CAP_PERFMON`、`CAP_NET_RAW`、`CAP_NET_ADMIN` 权限；5.10 内核设置 eBPF memlock 限额还需要 `CAP_SYS_RESOURCE`。file capabilities 的安装命令和 `/proc`、OpenSSL 探针限制见[使用指南](../user/usage.md#不使用-sudo-运行)。内核要支持 fentry/fexit 和 BPF ring buffer，并带 BTF（`CONFIG_DEBUG_INFO_BTF=y`，存在 `/sys/kernel/btf/vmlinux`）。

- x86-64：5.10 起可用。已在 Debian 11 的 5.10，Ubuntu 的 5.11、5.13、5.15、6.8、6.17、7.0，以及 CentOS Stream 9（5.14）和 10（6.12）的内核里实测。5.4 及更早的内核没有 fentry；Ubuntu 的 5.8 内核没有 BTF。
- arm64：6.4 起可用。arm64 通过 ftrace 直接调用挂 fentry/fexit，6.4 才支持；更早的内核上挂载报 `not supported`，程序提示需要 6.4。Debian 12 的 6.1、Ubuntu 22.04 的 5.15 和 6.2 因此不能运行。已在 mainline 6.4 和 Ubuntu 6.8 的 arm64 内核里实测。

内核接口的差异按内核自己的 BTF 处理，不按版本号猜：

- recvmsg 系列在 5.19 去掉了 nonblock 参数，每个 recvmsg 程序都有旧签名的 `_old` 版本，加载器按 `tcp_recvmsg` 的参数个数保留其一；内核 TLS 的 `tls_sw_recvmsg` 同样按 tls 模块的 BTF 选择。
- accept 在内核有 `__inet_accept`（6.8 起）时挂它的 fentry，否则挂 `inet_csk_accept` 的 fexit：后者在 6.10 改了签名，而且挂载时已经阻塞在 `accept()` 里的调用返回时不经过它。
- `iov_iter` 在 5.14 之前没有 `iter_type`，用 CO-RE 回退读旧的 `type` 位集合。
- 5.12 之前 tracing 程序不能调用 `bpf_get_socket_cookie`，加载器用一个极小的探测程序判断，不可用时 socket 层读取以 socket 的内核地址作键，并在 `inet_sock_destruct` 时清掉该地址的预算（`sk_free` 不行，发送路径每次释放写内存引用都会调用它）。
- 进程启动时间读 `start_boottime`（5.5 之前为 `real_start_time`），与 `/proc` 同一基准。
- 老版本校验器不接受栈上未初始化的结构填充字节，写入 map 的结构都显式补齐；socket 层读取的分块循环把游标放在 map 内存里，否则 5.15 的校验器会因路径组合过多拒绝加载。
- 某个函数在内核或模块 BTF 里不存在时，只删掉挂它的程序，例如 6.5 起没有的 `generic_splice_sendpage`，以及没加载 tls 模块时的内核 TLS 程序。

基础 PID 探针或抓包不可用时程序报错退出；OpenSSL 探针、socket 层读取和 NAT 映射不可用时继续运行，顶部和 `!` 状态页给出原因。

## PID 探针

[pid.bpf.c](../../internal/probe/pid.bpf.c) 挂在 TCP connect/accept/send/receive、UDP send/receive，以及原始 socket 和 ping socket 发出的 ICMP Echo 请求上，每个事件带协议、端点、PID、进程启动时间、角色和应用字节数，还有父进程（PID 和启动时间）和 cgroup v2 ID：在事件发生时读取，进程随后退出也不丢。TCP 事件另带 socket 此刻的平滑 RTT 及偏差、拥塞窗口、已发送数据段和累计重传，与 `ss -ti` 同源。

出站 TCP 建连结果另由 `inet_sock_set_state` 跟踪：进入 SYN_SENT 时在有界 LRU map 保存发起进程和时间，`tcp_v4_connect`/`tcp_v6_connect` 返回时补上当时才分配好的本地临时端口；转为 ESTABLISHED 或 CLOSE 时输出结果与耗时并删除 map 项。CLOSE 的 `sk_err=0` 归为应用主动放弃。结果复用 128 B 的 PID ring 事件。跟踪点加载或挂载失败只关闭这项探针，状态页与 JSON 显示原因，其他 socket 事件继续采集。

- `sendfile` 和写往 socket 的 splice 在 6.5 起都经过 `tcp_sendmsg`；之前的内核里 splice 写 socket 走 `generic_splice_sendpage`，另挂它的 fexit。读 socket 的 splice 走 `tcp_splice_read`，各内核都有。
- socket 开启内核 TLS 后，协议操作换成 tls 模块的实现，读写不再经过 `tcp_sendmsg`/`tcp_recvmsg`。程序另挂 `tls_sw_sendmsg`、`tls_device_sendmsg`、`tls_sw_recvmsg` 和 `tls_sw_splice_read` 的 fexit；cilium/ebpf 能挂到已加载模块里的函数。`tls_*_sendpage` 不挂，它们的字节已由 `generic_splice_sendpage` 计入。
- 重传挂 `tcp_retransmit_skb`（返回 0 才算）和 `tcp_send_loss_probe` 的 fexit：尾部丢失探测直接调用 `__tcp_retransmit_skb`，不挂它会少计。事件带 `tcp_sock` 里的累计 `total_retrans`，也就是 `ss -ti` 显示的值；这两个 hook 在软中断和定时器里运行，网络命名空间取自 socket 而不是当前任务。

事件经 4 MiB 的 ring buffer 送到用户态。每次提交都唤醒读取方，比处理事件本身还贵：每秒十几万次 socket 调用时，读取协程和主循环的反复唤醒占了 socktrail 六成的 CPU。所以程序只在 ring 里积压超过 512 KiB 时才唤醒读取方，读取方另外每 100 ms 读一次，事件因此最多晚 100 ms 到达；读取方按块交给主循环，每批最多 1,024 个事件，主循环跟不上时整批丢弃并计数。事件按生成的结构布局直接从 ring 读出，不经 `encoding/binary` 的反射。

## OpenSSL SNI 探针

OpenSSL 用户态探针默认尝试启用；不可用时继续抓包，但顶部标出 `OPENSSL-PROBE-UNAVAILABLE`，`!` 状态页显示原因与事件数。可用 `--openssl-probe=false` 关闭。

它针对 amd64 和 arm64 上动态链接的系统 OpenSSL 3/1.1，读取 `SSL_ctrl`/`SSL_get_servername` 暴露的 SNI，并通过 `SSL_set_fd`、`BIO_new_socket` 或 `SSL_connect` 期间的同线程 TCP 发送关联 socket；后者已用 curl 8.5 的自定义 BIO 路径在 OpenSSL 3.0.13 上实测。uprobe 按架构读参数寄存器，bpf2go 为两种架构各生成一份对象；其他架构上探针报告不支持。

同线程路径是时间窗口关联：如果握手回调同时向其他 TCP socket 发送数据，可能产生错误关联；跨线程发送则可能漏报。并非每次握手都会产生额外域名：正常捕获到 ClientHello 时，报文解析通常已有相同 SNI。Go TLS、静态链接库、其他 TLS 库、未覆盖的自定义 BIO 调用路径、真实 ECH 的内层名和 HTTP/2/3 加密的请求域名不在覆盖范围。

## socket 层前缀读取

[sockstream](../../internal/sockstream/sockstream.bpf.c) 在 `tcp_sendmsg`、`tcp_recvmsg` 上挂 fentry/fexit：fentry 记下调用方缓冲区的位置，fexit 按实际收发的字节数从该缓冲区复制，每个 socket 每个方向最多前 16 KiB。UDP 只复制发出的 QUIC 长包头数据报。不可用时顶部标出 `SOCKET-SNIFF-UNAVAILABLE`，可用 `--socket-sniff=false` 关闭。它补的是报文拿不到客户端字节的情况，解析规则见[解析原理](parsing.md#socket-层前缀读取)。

## AF_PACKET 环

抓包用 TPACKET_V3 环：内核把报文按长度紧凑写进与程序共享的 256 KiB 块，块写满或 100 ms 到期才唤醒一次读取方；读取方把一整块解码成一批交给主循环，报文负载直接引用环内存，主循环处理完这一批再把块还给内核，批的切片按接口复用。所以负载切片只在处理期间有效，保留数据的地方都要复制；现有解析器、DNS 缓存、QUIC 重组都只保存副本。

经典 BPF 过滤器把每帧截到 16 KiB 加 256 B，正好是解析器会读的范围：往环里拷帧发生在转发报文的软中断里，64 KiB 的 GSO 帧整帧拷贝在 veth 实验里让转发吞吐降了约 15%。录制 PCAPNG 时换成保留完整帧（最长 64 KiB），停止读取时过滤器改成全部丢弃，否则退出阶段填满的环会被内核记成丢包。

单接口的环为 16 MiB，两接口时各 8 MiB，三接口时各 5 MiB，四张及以上时每张各 4 MiB；总内存随接口数增长。默认自动选最多 8 张，显式指定可以超过 8 张，启动确认与内存限制见[使用指南](../user/usage.md#页面与接口选择)。一个截到 16 KiB 的 GSO 帧占环里 16.6 KB，一块只放得下 15 个；每秒 60 万个这样的帧时，4 MiB 的环只能缓冲不到 0.5 ms，实测丢了约 1%，16 MiB 时几乎不丢，而主循环此时只用了不到一个核。小报文则一块能放约 2,000 个。环计入进程 RSS。

主循环的停顿直接决定丢包，所以扫描所有进程 fd 的 socket 表读取（本机约 30 ms）放在后台 goroutine，读完才回到主循环应用。多队列网卡上也只有一个主循环：实测它的处理能力不是瓶颈，没有用 `PACKET_FANOUT` 拆分（数据见[验证记录](../archive/validation.md)）。

## 进程与 socket 关联

[collector.event](../../internal/app/app_linux.go) 先按 PID 和启动标识累计 socket I/O，再尝试用端点关联已观测的流。暂时没有流的 I/O 最多等待 2 秒；仍无法匹配的字节计入未关联统计。TCP 的 connect/accept 角色与实际执行 send/recv 的 PID 分开记录，避免把共享 socket 的 I/O 算给连接建立者；fd 传给别的进程后，各进程写的字节分别计入各自的 PID。

抓包和 eBPF 两个通道没有固定的处理顺序：抓包环的块最多攒 100 ms，事件最多晚 100 ms。accept 事件先于入站 SYN 被处理时，没有旧流、且角色是 2 秒内记录的就采用；否则按旧连接的角色丢掉。事件晚于报文时，一条短连接可能已经关闭，关闭后 2 秒内它仍接收自己的 connect、accept 和 I/O 事件；同一元组上的新连接要在这 2 秒内带着新 SYN 出现才会混淆。

## 进程树与服务

[processes_linux.go](../../internal/app/processes_linux.go) 按 PID 加启动时间记录每个出现过的进程的父进程和 cgroup，所有接口共用。父进程和 cgroup ID 来自事件；cgroup 路径在进程第一次出现时从 `/proc/<pid>/cgroup` 读取，并按 cgroup ID 记下，同一 cgroup 里之后的进程即使已经退出也能取到路径。进程的祖先大多不碰网络（shell、脚本），第一次见到一个进程时，趁它们还在，从 `/proc` 把祖先补齐。进程 10 分钟没有事件后删除，但保留仍在使用的进程的祖先。

服务取 cgroup 路径里最内层的 `.service` 或 `.scope` 目录：systemd 服务、`docker-<id>.scope` 这样的容器、会话和终端的 scope；没有这类目录时整个路径就是服务。进程树以一个进程在同一服务里最远的祖先为根，所以 nginx 的 worker 归到主进程下，终端里的命令归到 shell 下，而不会一直追到 systemd。只有 cgroup v1 的主机取 systemd 层级的路径。进程分组页还可按完整 cgroup 路径或可执行文件名分组；后者读取 `/proc/<pid>/exe` 的最后一段，无法读取时回退到内核任务名。

容器显示名在服务键确定后按容器 ID 查本地文件：Docker 读取 `config.v2.json` 的名称和 Compose 标签，支持 `/etc/docker/daemon.json` 的 `data-root`；containerd/CRI 读取 `/var/log/containers` 的 kubelet 日志链接来得到容器、Pod 和 namespace。最多缓存 4096 个 ID，找不到的 30 秒后重试；不可读时显示短 ID。这个查找只补名称，不改变 cgroup 服务键或跨网络命名空间的 PID 范围。

`--process`、`--pid`、`--cgroup`、`--container` 只影响显示：报文要先和进程对上才知道属于谁，所以抓包和事件照常全量处理，界面、快照和 JSON 在输出时按进程过滤，每次输出缓存每个进程的判断结果。

## 内核 socket 表补全进程

读取和进程关联见 [procnet_linux.go](../../internal/app/procnet_linux.go)。内核 socket 表（`/proc/net/tcp`、`tcp6`、`udp`、`udp6` 与 `/proc/<pid>/fd`，即 ss/netstat 的数据源）是进程归属的补充来源。存在两端都没有 PID 的 TCP/UDP 连接时，程序每 10 秒最多在后台读一次，读完再应用；它给启动前已建立、或 connect/accept 早于探针挂载的连接补上进程，并确定中途开始的 TCP 连接方向。启动时先读一份，用来判断哪些连接早于抓包。只覆盖当前网络命名空间；在两次读取之间开始又结束的连接，这里拿不到。

交互界面和 JSON 快照还使用同一份 socket inventory 展示监听端口：TCP 的队列与 backlog 优先由 sock_diag netlink 读取，失败时沿用 `/proc/net` 的监听条目；UDP 取未连接 socket，inode 到进程沿用 `/proc/<pid>/fd`。交互运行时每 5 秒后台刷新一次，accept 次数由已有探针事件累计，入站失败按原有尝试表的目标端口聚合；没有新增逐包探针。全局 ListenOverflows、ListenDrops 取 `/proc/net/netstat` 的 TcpExt 增量。

## NAT 映射

查询和元组解析见 [conntrack_linux.go](../../internal/conntrack/conntrack_linux.go)。

新的 TCP/UDP 流出现时，在单独的 goroutine 里向 conntrack 发一个 ctnetlink `IPCTNL_MSG_CT_GET` 按元组查一次：先按报文方向，查不到再反向，因为 conntrack 只按原始方向和应答方向的元组建索引，改写后的一侧对应应答方向。只保留确实被改写过的条目，按两个元组都能找到；多播不查。不订阅 conntrack 事件，因为那会让内核为整机每条连接生成事件，而抓到的连接往往只是一小部分；也不挂逐包触发的 `nf_nat_manip_pkt`。查询队列满时跳过（状态页计数），连接只是不关联。条目随关联的流一起续期，空闲 5 分钟后删除，最多 65,536 条。

本机进程的 socket 用它那一侧的元组，所以 PID 事件到来时若本侧没有流、条目的另一侧有，就把事件的端点换成另一侧；条目晚于事件到达时，把已记录在 socket 元组下的角色和待匹配 I/O 挪到抓到的流上。程序只在 `nf_nat` 和 `nf_conntrack_netlink` 已加载时启用，查询不会触发内核自动加载模块。查询不带 conntrack zone，zone 非 0 的条目查不到。

## ICMP 与非 IP 帧

ICMP/ICMPv6 的 Echo 按两端地址和 identifier 合成一条流，显示请求/应答数、最近序号和 RTT，ping 洪泛不会把流表撑满；其他消息按两端地址和 type/code 成流，显示类型名，邻居发现和重定向显示目标地址，“需要分片”显示 MTU。错误报文解出所引用原始报文的协议和端点，对应的 TCP/UDP 流在状态列标出错误名。本机进程发出的 Echo 请求，无论走原始 socket 还是 ping socket，都按对端地址和 identifier 关联到发送进程；入站 Echo 由内核应答，内核生成的错误报文也没有进程。

没有 IP 头的帧同样计入：ARP 显示请求/应答数和各 IP 宣告的 MAC 地址；PPPoE 会话里的 IPv4/IPv6 解开后按普通流统计；其他帧按 EtherType 分组，802.3 长度帧归为 `802.3 LLC`。tun 类接口没有链路层头，按帧里的 IP 报文直接解析；录制 PCAPNG 时给这类帧补一个空以太网头，保持文件只有一种链路类型。

IPv4/IPv6 分片：后续分片按（源地址、目的地址、协议、分片 ID）归入首片所在的流；首片没抓到时，后续分片单独成流。关联表最多 4096 项，30 秒过期。

## 流表与内存

每个接口的流表最多 2 万条。流表满时先淘汰一次性的流：已关闭的 TCP、没有得到 SYN-ACK 的 SYN、单向不超过两个报文的 UDP，按最后活动时间最旧的 10% 批量淘汰，避免扫描期间每个新流都排序一次。入站尝试按来源汇总，在流被淘汰或过期时计入。

只有少数流用到的状态按需分配：DNS 和 ICMP 状态、HTTP/2 解析器、重组的待排序片段、HTTP Host 计数和服务端的乱序片段。整机视图每秒重建一次，只在有数据时才分配 socket I/O 和 OpenSSL 进程的映射。`hostViewState` 在跨接口合并时维护稳定 ID；关闭的连接等待 2 秒后、其余连接从视图消失时，把最后一份合并记录放入 5000 条的环形内存历史。它按 ID 比较连接名称、状态和参与进程；变化结果同时供 LOG 页和 NDJSON 使用，最近 5000 次变化保存在内存环中。ID 留在视图映射中，不放进每条接口流的结构体。历史版本的每流堆占用实测值见[验证记录](../archive/validation.md)，不作为当前容量估算。

## 录制与快照输出

录制 PCAPNG 用格式规范里的 SHB、IDB、EPB 和注释选项实现最小写入器，不依赖 tshark。`--record-before` 开启后，主循环把每个帧复制进一个按时间和 32 MiB 上限淘汰的队列，按 `c` 时先把其中属于所选连接或 PID 的帧写进文件；为此抓包环一直按 SnapLength 复制帧，默认关闭。`--output json` 把快照的同一组数据按固定字段输出，字段见[使用指南](../user/usage.md#json-快照)。

## 参考

- [Linux Packet MMAP 文档](https://www.kernel.org/doc/html/latest/networking/packet_mmap.html)：AF_PACKET 环形缓冲与 TPACKET_V3。
- [pktz](https://github.com/immanuwell/pktz/tree/e580e7e3339635e3e6cd9a11e174f38ccc3ccb09)：用 TCP send/read 路径计数和 `/proc` 的 inode 关联进程，给了进程关联和淘汰问题的提示；它的 PID 键没有进程启动时间，计数口径也不同，没有复用代码。
- [RFC 792](https://www.rfc-editor.org/rfc/rfc792.html)、[RFC 4443](https://www.rfc-editor.org/rfc/rfc4443.html)（ICMP）、[RFC 9112](https://www.rfc-editor.org/rfc/rfc9112.html)（HTTP/1.1 消息边界）、[RFC 8446](https://www.rfc-editor.org/rfc/rfc8446.html)（TLS 握手）。
