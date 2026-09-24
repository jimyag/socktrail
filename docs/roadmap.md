# 后续计划

从 [中文首页](../README.zh-CN.md) 进入。这里列出已确认、尚未实现的事项，每项写明现状与证据、做法和验收方式，供后续逐项实现；已完成的内容和实测数据见 [验证记录](validation.md)。状态截至 2026-09-24。

| 事项 | 优先级 | 规模 |
| --- | --- | --- |
| [arm64 发布](#arm64-发布) | 高 | 中 |
| [CI 跑 root 测试](#ci-跑-root-测试) | 高 | 小 |
| [BPF 对象与源码一致性检查](#bpf-对象与源码一致性检查) | 中 | 小 |
| [内核矩阵进 CI](#内核矩阵进-ci) | 中 | 中 |
| [INCOMPLETE 写明原因](#incomplete-写明原因) | 中 | 小 |
| [内核重传计数](#内核重传计数) | 中 | 中 |
| [DNS 时延](#dns-时延) | 中 | 小 |
| [kTLS 的 socket 字节](#ktls-的-socket-字节) | 中 | 中 |
| [每条流的内存](#每条流的内存) | 中 | 中 |
| [真实服务验收新协议标签](#真实服务验收新协议标签) | 中 | 小 |
| [其他验收缺口](#其他验收缺口) | 中 | 各不相同 |
| [JSON 快照](#json-快照) | 低 | 中 |
| [预触发录制](#预触发录制) | 低 | 中 |
| [h2c 升级与 TLS 服务端乱序](#h2c-升级与-tls-服务端乱序) | 低 | 小 |
| [GC 目标](#gc-目标) | 低 | 小 |
| [多队列抓包](#多队列抓包) | 低 | 大 |
| [发布来源证明](#发布来源证明) | 低 | 小 |
| [文档合并](#文档合并) | 低 | 小 |

## 发布

### arm64 发布

现状：goreleaser 和 `install.sh` 都发布 arm64 二进制，但它从未在 arm64 上运行过，已知有两处问题：

- OpenSSL 探针以 `-D__TARGET_ARCH_x86` 和 `-I/usr/include/x86_64-linux-gnu` 编译（[gen.go](../internal/tlsprobe/gen.go)），uprobe 用 `PT_REGS_PARM*` 按 x86 的 `pt_regs` 布局读参数；arm64 上读到的是别的寄存器，SSL 指针和 fd 都是错的。
- arm64 的 BPF trampoline 从 Linux 6.0 才有，fentry/fexit 在更老的内核上无法挂载，例如 Ubuntu 22.04 arm64 的 5.15，PID 探针加载不了。

PID 探针和 socket 层读取只用 fentry/fexit 的参数数组，按 CO-RE 重定位结构体，理论上与架构无关，但同样没有实测。

做法：

1. OpenSSL 探针用 bpf2go 的 `-target amd64,arm64` 按架构生成两套对象（bpf2go 会为每个目标定义对应的 `__TARGET_ARCH_*`），去掉写死的 x86 宏和头文件路径。
2. 仿照现有的 x86 虚拟机流程，用 QEMU aarch64（没有 KVM 时用 TCG，较慢）或 arm64 机器，启动 Debian 12（6.1）和 Ubuntu 24.04（6.8）的 arm64 内核，跑各包的 root 测试和一次回环快照。
3. 验证之前，要么先从 `.goreleaser.yml` 和 `install.sh` 里去掉 arm64，要么在 README 标明 arm64 需要 6.0 以上内核、OpenSSL 探针不可用。

验收：arm64 上 probe、sockstream、capture、conntrack、tlsprobe 的 root 测试通过；OpenSSL 探针报告的 PID、五元组与连接一致。

### 发布来源证明

现状：`install.sh` 用 `checksums.txt` 校验 SHA-256，但它和二进制来自同一个 release，只能发现传输损坏，不能证明来源。

做法：release workflow 加 `actions/attest-build-provenance` 生成构建证明；安装脚本在有 `gh` 时执行 `gh attestation verify`，没有时照旧只校验 SHA-256。

## CI

### CI 跑 root 测试

现状：[check.yaml](../.github/workflows/check.yaml) 只跑不需要权限的测试。探针加载、校验器兼容、抓包环、conntrack 查询都只有 root 测试覆盖，目前靠手工在本机和虚拟机里跑。

做法：GitHub 托管的 `ubuntu-latest` 有免密 sudo 和带 BTF 的内核。先 `go test -c` 出 probe、sockstream、capture、conntrack、tlsprobe、cmd 的测试二进制，再用 `sudo` 运行。conntrack 的 DNAT 测试需要 `apt install nftables`；cmd 的测试要在包目录下运行，因为它按相对路径读 fixture。

验收：故意让一个探针程序无法通过校验器，CI 失败。

### BPF 对象与源码一致性检查

现状：仓库提交了 bpf2go 生成的 `.o` 和 `.go`，没有检查它们与 `.bpf.c` 源码一致；改了源码忘记重新生成，普通测试照样能过。

做法：CI 装 clang-18、llvm-18（`llvm-strip-18`）和 libbpf 头文件，运行 `go generate ./internal/...`，再 `git diff --exit-code`。先确认同版本 clang 两次生成的对象逐字节一致。

### 内核矩阵进 CI

现状：5.10 至 7.0 的虚拟机验证靠本机手工进行：下载发行版内核包，用静态 Go init 做 initramfs，在 QEMU/KVM 里跑 root 测试和回环快照，每个内核约 15 秒。脚本不在仓库里。

做法：

1. 把内核下载、initramfs 生成和 init 程序整理进仓库，例如放到 `test/vm/`。
2. 写一个手动触发或定时运行的 workflow，按内核版本矩阵执行。GitHub 的 Linux runner 可以用 udev 规则放开 `/dev/kvm`，需要先实测确认可用。
3. 缓存下载的内核包。

验收：每个内核的测试数、快照流数和丢包数写进 job summary，任一内核失败则 workflow 失败。

## 功能

### INCOMPLETE 写明原因

现状：只要丢包、截断、流索引淘汰、PID 索引淘汰、PID 事件丢失、未索引的 socket I/O 这几项计数中任一项非零，或当前有一条连接解析失败，顶部就标 `INCOMPLETE`，具体原因要按 `!` 才能看到。1 小时长稳结束时出现了这个标记，但进程退出后已无法得知是哪一项。

做法：顶部标记后附上非零的项和数量，例如 `INCOMPLETE drop=12 parse=1`；快照报告的状态行也列出同样的分项。

### 内核重传计数

现状：`RETX` 是从抓到的报文里推断的，只统计本采集点看到的重复 SYN 和序号重叠，丢包、乱序或多接口合并都会影响结果。

做法：挂 `tcp:tcp_retransmit_skb` tracepoint（4.15 起就有，只在发生重传时触发），按 socket cookie（没有 cookie 的内核用 socket 地址）计数，经 ring buffer 或周期读取的 map 交给用户态。本机 socket 的连接改显示内核计数，转发流量仍用抓包推断，界面标明来源。

验收：用 `tc qdisc add dev <veth> root netem loss 5%` 制造丢包，内核计数与 `ss -ti` 的 `retrans` 一致。

### DNS 时延

现状：DNS 流只有查询名、类型、应答码和失败次数，没有时延。

做法：`dnsState` 记下最近几个未应答查询的事务 ID 和抓包时间（环里的时间戳是内核时间），应答到来时算出 RTT，保留最近一次和最小值。每条流只多几十字节，不需要跨流状态。

验收：用 `tc netem delay 50ms` 给实验网络命名空间加时延，显示的 RTT 约为 50 ms。

### kTLS 的 socket 字节

现状：PID 的 socket 字节来自 `tcp_sendmsg`/`tcp_recvmsg` 等函数的返回值。socket 开启内核 TLS 后，协议操作换成 TLS 的实现，写入走 `tls_sw_sendmsg`（硬件卸载时为 `tls_device_sendmsg`），读取走 `tls_sw_recvmsg`，推测不再经过已挂的函数，nginx 开启 kTLS 后 PID 字节会少计。

做法：先在本机用 `openssl s_server -ktls` 或开启 kTLS 的 nginx 确认实际调用路径和少计的情况，再给这几个函数加 fexit，思路与 `generic_splice_sendpage` 一样：按内核 BTF 判断函数是否存在，没有就不加载。

### JSON 快照

现状：快照只有文本输出，脚本处理和前后对比都要解析表格。

做法：加 `--output json`，输出一个固定结构的 JSON 文档，包括接口统计、连接、域名汇总和 PID socket I/O，字段名写进文档并保持向后兼容。文本仍是默认输出。

### 预触发录制

现状：按 `c` 只录之后 15 秒的报文，问题出现时再按往往已经错过。

做法：每个接口保留一个有上限的环形缓冲，存最近 N 秒的帧（按抓包长度截断），例如总量不超过 32 MiB；按 `c` 时先写出缓冲里属于所选连接或 PID 的帧，再继续录后续报文。默认关闭，用参数开启，因为它会一直复制帧。

### h2c 升级与 TLS 服务端乱序

- 经 HTTP/1.1 `Upgrade: h2c` 升级的连接：客户端在服务端回 101 之后才发 HTTP/2 前言，现在的 HTTP/1.1 解析器会在前言处出错。需要让客户端方向解析器知道升级成功，再切换到 HTTP/2 解析。
- TLS 服务端解析只接受按序报文，服务端开头几个报文乱序时拿不到版本和证书名。可以为服务端方向复用客户端流的有界重组，缓冲上限保持 64 KiB。

## 资源

### 每条流的内存

现状：1 小时长稳测试中，自动选中 8 个接口时，GC 后的存活堆稳定在 44 至 49 MB，对应约 3,300 条整机合并后的流，每条流在 10 KB 量级。例如每条 TCP 流一建立就分配域名解析器的待重组 map 和 Host 计数 map，多数流用不到它们。

做法：先写一个构造 N 条流的基准测试并取 heap profile，找出占比最高的分配，再改成按需分配。

验收：同样的基准下每条流的内存明显下降，长稳测试的 RSS 相应减少。

### GC 目标

现状：RSS 约为存活堆的两倍加上固定部分（每个接口 4 MiB 的抓包环、约 18 MiB 的 eBPF map），这是 Go 默认 GC 目标下的正常表现。

做法：评估 `debug.SetMemoryLimit` 或降低 GC 目标，在长稳场景里对比 RSS 与 CPU，只在 CPU 代价可以接受时采用。

### 多队列抓包

现状：每个接口一个读取协程，所有报文都在一个主循环里处理。veth 上每秒约 10 万个包时采集只用 0.13 个核，余量很大；物理网卡上百万级 pps 还没测。

做法：只有物理网卡实测出现瓶颈时才考虑。可以用 `PACKET_FANOUT` 按流哈希把一个接口分到多个环，并按接口或流哈希拆分采集器的状态，改动很大。

## 验收

### 真实服务验收新协议标签

现状：Kafka、AMQP、NATS、ZooKeeper、Memcached、SQL Server、Oracle TNS、Cassandra、LDAP、Kerberos、NFS/RPC 的识别只有构造报文的单元测试；明文 HTTP/2 只用 curl 的 prior knowledge 请求验证过。

做法：本机有 docker，用 `--network host` 起真实服务，让流量走 lo，再用各自的客户端发请求，核对 `APP` 标签。候选镜像有 Kafka、RabbitMQ、NATS、ZooKeeper、Memcached、SQL Server、Cassandra、OpenLDAP；Kerberos 用 krb5-kdc，NFS 用主机的 nfs-kernel-server。gRPC 另用 grpc-go 的示例服务，跑一条带多次请求的长连接。

### 其他验收缺口

- 物理网卡上的高负载、多队列和 GSO/GRO，以及 12 小时以上的长稳运行。
- RHEL 系内核：大量回移特性，BTF、fentry 的可用性要实测。
- conntrack zone 非 0 的条目：查询没带 zone，查不到。
- 桥接转发，以及非当前网络命名空间里的流量。
- 强制复现 PID 数值复用；fd 传递、多个写者共用一个 socket。

## 文档

### 文档合并

现状：新旧文档并存，内容重叠。[architecture.md](architecture.md) 与 [development.md](development.md) 都讲实现；[parsing.md](parsing.md) 与两篇 HTTPS 文档都讲解析；[usage.md](usage.md) 与 [ui-design.md](ui-design.md) 都讲界面。[implementation-plan.md](implementation-plan.md) 和 [protocol-capture-plan.md](protocol-capture-plan.md) 是早期只有十几行的计划，内容已被验证记录和本文取代。

做法：把 development.md 中仍然有效的设计约定并入 architecture.md，两篇 HTTPS 文档保留为调研记录或并入 parsing.md，删除两篇早期计划，并同步更新各处链接。
