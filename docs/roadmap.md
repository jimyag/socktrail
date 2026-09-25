# 路线图

从 [文档索引](README.md) 进入。这里列出计划功能及实施进度，每项写明目标、现状、做法和验收方式，供实现者（人或 AI）直接动手。开始任何一项之前，先读完[通用约定](#通用约定)。

## 总览

| 编号 | 事项 | 优先级 | 规模 | 依赖 |
| --- | --- | --- | --- | --- |
| 0 | [收回连接记录的内存规格](#0-收回连接记录的内存规格) | 高 | 小 | 无 |
| 1 | [保留已结束的连接](#1-保留已结束的连接) | 高 | 小 | 无 |
| 2 | [出站失败诊断](#2-出站失败诊断) | 高 | 中 | 1、16 |
| 3 | [容器网络验收与跨命名空间采集](#3-容器网络验收与跨命名空间采集) | 高 | A 小、B 大 | B 依赖 A 的结论 |
| 4 | [容器与 Pod 名称](#4-容器与-pod-名称) | 中 | 小 | 无，和 3 一起验收 |
| 5 | [TCP 瓶颈判断](#5-tcp-瓶颈判断) | 中 | 中 | 无 |
| 6 | [内核丢包原因](#6-内核丢包原因) | 中 | 中 | 无 |
| 7 | [监听端口页](#7-监听端口页) | 中 | 小 | 无 |
| 8 | [结构化过滤](#8-结构化过滤) | 中 | 小 | 无 |
| 9 | [环境变量中的凭据遮蔽](#9-环境变量中的凭据遮蔽) | 中 | 小 | 无 |
| 10 | [DNS 查询记录](#10-dns-查询记录) | 中 | 小 | 无 |
| 11 | [诊断结论](#11-诊断结论) | 低 | 小 | 2、5、6 |
| 12 | [流量趋势](#12-流量趋势) | 低 | 中 | 无 |
| 13 | [进程来源链与按用户分组](#13-进程来源链与按用户分组) | 低 | 小 | 无 |
| 14 | [读回 PCAPNG](#14-读回-pcapng) | 低 | 中 | 无 |
| 15 | [显式触发的主动探测](#15-显式触发的主动探测) | 低 | 中 | 无 |
| 16 | [变化计算、实时 JSON 输出与 LOG 页](#16-变化计算实时-json-输出与-log-页) | 高 | 中 | 1 |
| 17 | [域名覆盖：补齐缺口，标明原因](#17-域名覆盖补齐缺口标明原因) | 高 | 中 | 第 3 部分依赖 10 |

进度（2026-09-25）：0、1、2、3、7、8、9、10、16 已实现并验证（1 的一小时历史流测试已通过；3B 的跨命名空间抓包、PID、NAT、socket 表与 kind Pod 已在实机验证；7 的 sock_diag 队列、真实 HTTP 监听与 accept、PTY 页面和 root 冒烟测试已通过；8 已通过单元测试和 root 冒烟测试）；4 的 Docker 名称和 `--container` 已在实机验证，Pod 名称和 namespace 已在 kind 的真实 kubelet 元数据上验收；17 的协议升级 TLS、PROXY v2 AUTHORITY、按进程 DNS 关联和加密 DNS 标记已实现并验证。其余条目尚未开始。

建议顺序：
1. 先做 0，它只调整字段顺序。
2. 再做 1 和 16：保留已结束的连接、变化计算、实时输出和 LOG 页。后面几项的展示都要经过它们。
3. 接着做 17 的第 1、2、4 部分，然后做 10 和 17 的第 3 部分。
4. 然后做 2。
5. 接着做 3A 和 4。
6. 5、6、7、8、9 彼此独立，可以穿插着做。
7. 11 等 2、5、6 完成后再做；12 到 15 按需。

新页面的按键：`6 LOG`（第 16 项，用 `b` 切换分组，第 2 项的失败汇总是其中一种分组）、`7 PORTS`（第 7 项）。现在已占用的按键有 `1`–`5`、`0`、`a`、`i`、`d`、`g`、`b`、`c`、`s`、`/`、`?`、`!`、`q`、`Tab`、`Enter`、`Esc`、方向键、`h/j/k/l` 和翻页键；新增按键前先查 `handleKey`，并同步顶栏的 `topPages`、`pageEntries` 和鼠标点击表。

## 通用约定

### 数据模型

所有功能都遵守同一个分层：底层采集的数据只有一份，页面分组、汇总、关联和"事件"都是在它上面计算出来的，界面、文本报告、JSON 快照和实时 JSON 输出只是同一份计算结果的不同展示形式。

- 采集层：数据都挂在现有结构上。
  - 连接是 `flow`（`app_linux.go`）：报文计数，两端进程（`Client`、`Server`），各进程的 socket 收发（`IO`），域名证据（`WireDomain`、`SocketDomain`、`QUICDomain`、`ProcessDomain`、`DNSDomain`，由 `chooseDomain` 选出 `Domain`，证据类型是 `domain.Evidence`），TCP 健康（`Health`，类型为 `tcpHealth`），状态（`TCPState`、`Closed`、`ICMPError`），各协议的状态（`DNS`、`ICMP`、`ARP`、`SSH`），NAT 和网卡（`Interfaces`）。
  - 进程在 `processTable`（`processes_linux.go`）里，进程的 socket 收发在 `collector.pidIO`。
  - DNS 提示在 `domain.DNSCache`，入站尝试在 `collector.attempts`。
  - 多网卡合并：`hostCollector` 每秒生成合并后的连接，`hostViewState` 给每条连接一个跨帧稳定的 ID，并在 `displayed` 里保存最后显示的副本。
- 计算层：页面分组是 `terminalUI.rows`（产出 `uiRow`，服务页用 `b` 切换分组方式），汇总有 `serviceTotals`、`domainSummary` 等，排序是 `sortFlows`、`sortGroups`。同一个计算只写一次，界面、文本报告和 JSON 共用。
- 展示层：界面（`ui.go`、`ui_layout.go`），文本报告（`printReport`），JSON（`reportJSON` 生成 `jsonSnapshot`，每条连接是一个 `jsonFlow`）。

新功能怎么接入：
- 不为某个新功能单独设计记录结构，也不为某一种输出单独采集。数据加在已有结构上：
  - 连接相关的加到 `flow` 或它的子结构上，例如建连结果加进 `tcpHealth`，DNS 查询加进 `dnsState`，没有名字的原因扩展 `domain.Evidence` 已有的字段和 `Group` 分组。
  - JSON 相应扩展 `jsonFlow`、`jsonSnapshot` 的字段。
  - 新页面是 `rows` 里的一种新分组，或者已有页面的一种 `b` 分组方式。
- 已有字段不合用时，直接重构已有的字段和函数，不要另起一套平行的。例如把 `reportJSON` 里在循环中构造 `jsonFlow` 的代码提成函数，快照和实时输出共用。重构时 JSON 已有字段的含义保持不变。
- "事件"也是计算结果：每秒比较同一条连接前后两次的状态，算出新出现、名字变化、状态变化、结束（第 16 项）。界面的 LOG 页和实时 JSON 输出用的是同一份计算结果。

### 实现细节

代码位置：
- 主循环、报表和 JSON：`internal/app/app_linux.go`、`report_json_linux.go`。
- 界面：`internal/app/ui.go`，布局 `ui_layout.go`，排序 `ui_sort.go`，样式 `ui_style.go`。
- 合并视图：`host_view_linux.go`。`hostViewState.update` 给跨网卡的同一连接分配跨帧稳定的 ID。
- 进程表、服务和过滤：`processes_linux.go`。
- 探针：`internal/probe/pid.bpf.c`、`types.go`、`ebpf_linux.go`。改了 C 代码要运行 `go generate ./internal/probe`，重新生成 `bpf_bpfel`、`bpf_bpfeb` 的 `.go` 和 `.o` 并一起提交；CI 会检查生成物是否最新。

内核：
- 要求 amd64 5.10 及以上、arm64 6.4 及以上。
- 新的 BPF 程序在挂载点、字段或跟踪点参数缺失时必须能降级：可选程序单独加载，失败时跳过，并在状态页 `!` 和 JSON 的 `probes` 里写明原因，做法和现有的 OpenSSL、socket 读取探针一样。
- 改动探针后要跑 `test/vm/run.sh` 覆盖 `test/vm/kernels.txt` 里的全部内核；CI 的 Kernels 工作流也会跑。

主循环和性能：
- 抓包、PID 事件、按键和界面都在同一个 goroutine 里。周期性工作放进现有的每秒 tick，不要另开 goroutine 读写 collector；需要后台执行的任务（下载、探测）通过 channel 把结果送回主循环。
- 探针的 `struct event` 现在是 128 B，经 ring buffer 批量唤醒。新数据优先用新的操作类型或只在需要的事件里填，不要让所有 socket 事件都变大；大量同类事件（如丢包）在内核里聚合计数，不要逐条上报。
- 每条连接的存活堆用 `go test -run '^$' -bench BenchmarkFlowMemory ./internal/app` 测，加字段前后都要对比。
- `flow` 结构体的大小用 `go run golang.org/x/tools/go/analysis/passes/fieldalignment/cmd/fieldalignment@latest ./internal/app/` 检查，它会给出当前大小、最优大小和对应的分配规格。第 0 项完成后应不超过 768 B；新字段放进已有的对齐空隙，或者用按需分配的指针，不要越过这个规格。

输出格式：
- JSON 快照的 `version` 是 1，只增字段，不改已有字段的含义。
- 实时输出每行是一条连接的 `jsonFlow`，和快照 `flows[]` 的元素是同一个结构，由同一个函数生成（第 16 项）。

界面：
- 颜色只用 `ui_style.go` 里的样式（主题 16 色，支持 `NO_COLOR`）。
- 表格列按内容定宽，写法参照 `connectionLayout`。
- 每一列都能点击排序，要在 `sortFlows` 或 `sortGroups` 里加对应分支，并在 `selectColumn` 里设定默认升降序。

边界：
- 不读取 TLS 明文。域名只从 DNS、TLS 和 QUIC 握手（包括 STARTTLS 等协议升级之后的握手）、明文 HTTP 和代理握手里取。
- socktrail 只产生域名和连接数据，不对域名做判断或拦截，这些留给下游程序。
- 不修改网络：不下发防火墙规则，不断开连接。
- 主动发包只在用户显式触发后进行（第 15 项）。

文档和验证：
- 用户可见的改动同步 `docs/user/usage.md`、`ui-design.md`、`measurement.md`；实现原理的改动同步 `docs/internals/architecture.md`。
- 验证手段：
  - 单元测试：伪造 `/proc` 用 `processes_linux_test.go` 里的 `fakeProc`。
  - 探针 root 测试：`sudo go test ./internal/probe`。
  - 冒烟测试：`sudo test/smoke.sh <二进制>`。
  - lint：`golangci-lint run`。
  - 界面用 PTY 渲染检查。
- 提交信息沿用 `type(scope): summary` 格式，并加 `-s` 签名。

## 0. 收回连接记录的内存规格

现状：
- `flow` 结构体现在是 776 B，超过了 768 B，Go 按 896 B 的规格分配，每条连接多占 128 B。
- 原因是记录网卡的字段换成了 `interfaceSet`（一个 uint64 加一个 map，共 16 B），按 8 字节对齐，放不进原来 `Preexisting` 后面的对齐空隙。
- fieldalignment 给出的最优大小是 760 B，正好落在 768 B 规格里。

做法：只调整 `flow` 的字段顺序，不改任何语义。把分散的 bool 字段（`Preexisting`、`DomainConflict`，以及 `FinA`、`FinB`、`Closed` 等）排在一起，消除它们各自后面的对齐空隙。按 fieldalignment 的建议排列即可，排完保留原有的字段注释。

验收：
- fieldalignment 对 `flow` 不再报告浪费；结构体本身需不超过 760 B，给含指针对象的 8 B 分配头留出空间。
- `BenchmarkFlowMemory` 前后对比，B/flow 下降约 128。
- 新增一个测试，断言 `unsafe.Sizeof(flow{}) <= 760`，防止以后再越过这个规格。

## 1. 保留已结束的连接

目标：连接结束后，仍能查到它完整的记录，包括时间、两端、进程、域名和结束原因。第 16 项的 LOG 页和实时输出、第 2 项的失败汇总都从这里取已结束的连接。

现状：
- 连接过期由 `collector.expire` 负责：已关闭的连接在最后一个报文后保留 1 分钟，未关闭的连接空闲 5 分钟后过期；满额时 `evict` 淘汰最久未活动的连接。过期后只剩累计字节。
- 合并视图的 `hostViewState` 已经给每条连接分配稳定 ID，并在 `displayed` 里保存最后一次显示的副本；ID 消失时，这份副本就被丢掉了。

做法：不新建记录结构，扩展现有的。
- `flow` 增加一个字段 `End`（结束原因），用 uint8 枚举，放进 bool 字段旁的对齐空隙，不增加结构体大小。结束时间就用已有的 `Last`（最后一个报文的时间），不另加字段。
  - `fin`、`reset`：来自现有的 `TCPState` 和 `Closed`。
  - `failed`：来自第 2 项记在 `tcpHealth` 上的建连结果。
  - `idle`、`evicted`：连接的 ID 在 `hostViewState.update` 里消失时，看最后一份副本，距最后一个报文超过空闲时限的是 `idle`，否则是 `evicted`。
- 什么时候算结束：TCP 连接已关闭，并且距最后一个报文超过 `lateEventWindow`（2 秒，等晚到的 PID 事件）；或者连接的 ID 消失。
- `hostViewState` 增加一个有上限的环形缓冲，默认 5000 条，按结束时间保存已结束连接的最后副本，也就是 `displayed` 里的同一个 `*flow`。每条连接只进入一次。
- 这一项只保存数据，展示在第 16 项。
- JSON：`jsonFlow` 增加 `id`（稳定 ID）和 `end`，结束时间看已有的 `last_seen`。快照的 `flows[]` 含义不变，仍是当前还在表里的连接。

验收：
- 单元测试：
  - 关闭后 2 秒内不算结束；2 秒后算结束，并且只进入历史一次。
  - 同一连接出现在两块网卡上时，历史里只有一份，`interfaces` 两块都列出。
  - 过期的连接结束原因为 `idle`。
  - 环形缓冲超出上限时丢弃最早的。
- 连续运行 1 小时：缓冲不超过上限，RSS 保持平稳。

## 2. 出站失败诊断

目标：按进程和目标汇总失败的出站连接（被拒、超时、不可达、应用自己放弃），保留最近几次失败的时间，让用户一眼看出"谁连不上谁、为什么"。同时记录成功连接的建连时延。

现状：
- 抓包侧能看到 SYN 无应答、RST 和 ICMP 错误（STATE 列）。但 attempts 只按来源统计入站尝试，没有出站失败的汇总。
- 探针只在 `tcp_v4_connect`、`tcp_v6_connect` 返回时记录 PID。非阻塞 connect 当场只返回 EINPROGRESS，失败发生在之后，现在拿不到失败原因。

内核依据（已在本机 6.8 的 BTF 核实，5.10 起可用）：
- `tp_btf/inet_sock_set_state` 跟踪点，参数为 `(sk, oldstate, newstate)`：
  - SYN_SENT → ESTABLISHED：建连成功，两次状态变化的时间差就是建连时延，口径与 bcc 的 tcpconnlat 相同。
  - SYN_SENT → CLOSE：建连失败。此时内核已经写好 `sk->sk_err`：
    - `ECONNREFUSED`：收到 RST，由 tcp_reset 写入。
    - `ETIMEDOUT`：SYN 重传用尽，由 tcp_write_err 写入。
    - `EHOSTUNREACH`、`ENETUNREACH` 等：收到 ICMP 不可达，由 tcp_v4_err、tcp_v6_err 写入。
    - `sk_err` 为 0：应用在内核放弃之前自己关闭了 socket。很多应用的连接超时比内核默认约 127 秒的 SYN 重试短，这种情况很常见，单独归为 `aborted`。
- 不选其他挂载点的原因：`tcp_write_err` 在 6.8 上被内联，不在 BTF 里；`tcp_reset` 的参数个数随版本变化（本机 6.8 为 `sk, skb`）；`tcp_done` 虽然可用，但不如跟踪点稳定。
- UDP 没有连接状态。已连接的 UDP socket 收到端口不可达时，内核写入 `ECONNREFUSED`，但要到下一次收发才报告给应用。所以 UDP 的失败先靠抓包侧的 ICMP 错误和 DNS 应答码（NXDOMAIN、SERVFAIL、REFUSED、无应答）表达。

做法：
- 探针：新增 `SEC("tp_btf/inet_sock_set_state")` 程序，只处理 TCP，以及和现有探针同一网络命名空间的 socket。
  - newstate 为 SYN_SENT 时，把发起者写入 `BPF_MAP_TYPE_LRU_HASH` 类型的 map `connecting`，键是 sk 指针，值包括 tgid、start_ns、comm、cgroup_id 和时间戳，max_entries 可取 16384。这次状态变化发生在 connect 系统调用里，current 就是发起进程。
  - oldstate 为 SYN_SENT、newstate 为 ESTABLISHED 或 CLOSE 时，从 map 取回发起者，输出操作码为 `OP_CONNECT_RESULT` 的事件，内容包括四元组、结果（0 或 errno）、建连时延和发起者信息，然后删除 map 项。这次变化可能发生在软中断或定时器里，所以进程信息只能从 map 取，不能用 current。
  - 事件复用 `struct event`，新增 `result` 和 `latency_us` 两个 `__u32`，注意总大小。
- 用户态：数据全部记在现有结构上。
  - `probe.Event` 增加 `Result`、`ConnectLatency`。
  - `tcpHealth` 增加 `ConnectResult`（int32 的 errno，0 表示成功）和 `ConnectLatency`（uint32 微秒），合计 8 B。collector 按 `keyFor(local, remote, 6)` 把它们记到对应 flow 的 `Health` 上。
  - 探针报告了结果、但没有抓到报文的连接（例如 SYN 没经过任何采集接口），照样建一条 `flow`：没有报文，网卡为空。这样它和其他连接走同一条展示路径。只在第一个采集器里建，和现有"与网卡无关的数据以第一个采集器为准"（`hostCollector` 取 `base.pidIO`）的做法一致。
  - 建连失败的连接，第 1 项的结束原因记为 `failed`。
- 失败汇总不新建结构，它是第 16 项 LOG 页的一种 `b` 分组，按"失败原因、进程、目标"分组。
  - 数据来自还在表里的连接，加上第 1 项保存的已结束连接。
  - 次数、首次和最近时间由组内的连接算出；底栏的连接表逐条列出每一次失败，各自带时间。
- 界面：
  - 失败连接的 STATE 列显示 `syn, refused`、`syn, timeout` 等，做法是扩展现有 `flowState` 拼接 ICMP 错误的方式。
  - 连接详情在 RTT、RETX 旁边显示建连结果和时延，例如 `CONNECT refused 0.3ms`。
- JSON：
  - `jsonFlow` 在现有的 RTT、重传字段旁边增加 `connect_result`（errno 名称）和 `connect_latency_us`。
  - 快照增加 `failures[]`，由和 LOG 页失败分组相同的分组函数生成。每组包含原因、进程、目标、次数、首次和最近时间，以及组内连接的 `id`。
- 第二步：在 `3 DST` 页按目标汇总建连时延的 p50 和 p95，同样从 `ConnectLatency` 计算。

降级：跟踪点挂载失败时（极少数裁剪过的内核），仍用抓包侧的 SYN 无应答、RST 和 ICMP 错误推断失败，并在状态页标明"内核结果不可用"。

验收：
- 探针 root 测试：
  - 连本机未监听的端口，得到 ECONNREFUSED 和一个很短的时延。
  - 在测试网络命名空间里用 nftables 丢弃 SYN，对 socket 设置 `TCP_SYNCNT=1` 缩短重试，约 3 秒后得到 ETIMEDOUT。
  - 非阻塞 connect 后 100 ms 内关闭 socket，得到 `aborted`。
  - 连通的连接得到成功结果和时延。
- 界面和快照：curl 连本机未监听端口 3 次、连被丢弃的地址 2 次。LOG 页的失败分组应出现 `curl → 127.0.0.1:<port> refused ×3` 和 `curl → <地址> timeout ×2`，最近时间正确；快照的 `failures[]` 和它一致。
- 内核矩阵全部通过。

## 3. 容器网络验收与跨命名空间采集

目标：先弄清现有能力在容器网络下的表现并写进文档，再决定并实现跨网络命名空间采集（`--netns`）。

现状：
- 探针按线程所在的网络命名空间过滤，`pid.bpf.c` 的 `settings.netns` 等于 socktrail 自己的命名空间。
- socket 表只读本命名空间的 `/proc/net`，conntrack 查询也只在本命名空间。
- 结果是容器里的进程完全不可见；经过网桥或 veth 的报文能抓到，但没有进程。
- 自动选网卡时优先物理口，容器的子链路要用 `--interface` 显式指定。

### 阶段 A：验收现有能力（小）

- 环境：本机 Docker（已有多个 bridge 网络）、一个 host 网络容器；可选在虚拟机里起一个 kind 或 k3d 集群。
- 场景和预期：
  1. bridge 容器访问外网：Docker 网关接口和宿主出口都能看到建连尝试，conntrack 把 NAT 前后合并成一条，方向为 `forwarded`，没有 PID。
  2. host 网络容器：进程完整，服务显示为 `docker-<id>.scope`。
  3. 同一网桥上的两个容器互访：本机实测宿主侧 veth 可见，`docker0` 本身看不到桥内转发帧；没有 PID。
  4. 用 `--interface vethXXX` 显式指定：只看到这一个容器的流量。
- 产出：
  - 更新 README 里"容器网络尚未验收"的说明和 `docs/user/measurement.md` 的限制。
  - 写明哪些缺口必须靠 `--netns` 解决。

### 阶段 B：`--netns`（大）

- 参数：`--netns <路径|名字|pid:PID|container:ID>`，可以重复；默认只采集当前命名空间。
  - 统一解析成 `/proc/<pid>/ns/net` 或 `/run/netns/<name>` 的文件描述符，用它的 inode 作为命名空间 ID。
  - `container:ID` 依赖第 4 项的解析结果找到容器的 PID。
- 抓包：
  - 对每个命名空间，先 `runtime.LockOSThread`，再 `setns(fd, CLONE_NEWNET)`，在其中创建 AF_PACKET（TPACKET_V3）socket 和 conntrack netlink socket，最后切回原命名空间。socket 创建后始终属于创建时所在的命名空间。
  - `internal/capture` 和 `internal/conntrack` 各需要一个"在指定命名空间打开"的入口。
  - 接口的 ifindex 要在目标命名空间里解析。
- 命名：不同命名空间的接口可能重名，界面和 JSON 用 `<命名空间名>:<接口>` 表示；`captureInterfaces` 的每一项都带上命名空间。
- 探针：`settings.netns` 改成以命名空间 inode 为键的 BPF hash map。事件本身已经带有 netns，用户态据此把事件送到对应命名空间的采集器。
- socket 表：每个命名空间在切换后的线程读 `/proc/thread-self/net/tcp{,6}` 和 `udp{,6}`；PID 反查仍走宿主 `/proc`。
- 每接口采集器只接收一个命名空间的事件；整机聚合键加上命名空间 inode，避免相同私网地址合并，同时保持 `flow` 在 768 B 分配级别以内。
- 参考 ptcpdump 的 `--netns` 和容器过滤实现。

验收：
- 两个容器用相同的私有地址发起连接，在宿主上用 `--netns` 分别显示各自的进程，不混淆。
- 容器命名空间内的 NAT 仍能合并。
- CPU 和内存与只采集单个命名空间时在同一量级。

2026-09-25 验证：参考 ptcpdump 的 [NetNs.Do](https://github.com/mozillazg/ptcpdump/blob/main/internal/types/netns.go) 与按 netns 区分设备的实现。两个独立 netns 都配置 `172.17.0.2`，分别以 `172.17.0.2:50000 → 172.17.0.2:18081` 建连；两份报告保留不同的 client/server PID 和命名空间接口。目标 netns 内 `18082 → 18081` 的 DNAT 被 conntrack 识别。kind CoreDNS 与宿主同时采集时，`listeners[].netns` 区分 CoreDNS 与宿主的 53 端口，Pod 的 `kube-system` 元数据可见；修正了 `/proc/net` 会串到宿主视图的问题。5 秒空闲采集对比：单 netns user/sys 0.58/0.91 s、峰值 RSS 76 MiB；双 netns 0.58/1.05 s、83 MiB。`go test ./...`、root 冒烟，以及 5.10/6.8 amd64、6.4 arm64 虚拟机检查通过。

## 4. 容器与 Pod 名称

目标：服务页和进程详情显示容器名、compose 服务名、Pod 名和它的 namespace，而不是 `docker-<12 位 ID>.scope`。

现状：`serviceOf` 从 cgroup 路径取最内层的 `.service` 或 `.scope`，并把其中的容器 ID 截到 12 位。

做法：
- 在 `serviceOf` 之后加一层 `containerName(id)` 解析，只读本地文件，不连接任何 daemon：
  - Docker：读 `/var/lib/docker/containers/<id>/config.v2.json`，取 `Name`（去掉开头的 `/`），以及 `Config.Labels` 里的 `com.docker.compose.project`、`com.docker.compose.service`。如果 `/etc/docker/daemon.json` 设置了 `data-root`，就改用那个目录。
  - containerd 和 CRI（Kubernetes）：cgroup 路径形如 `.../kubepods-<qos>-pod<uid>.slice/cri-containerd-<id>.scope`（systemd 驱动）或 `/kubepods/<qos>/pod<uid>/<id>`（cgroupfs 驱动）。kubelet 会为每个容器创建软链接 `/var/log/containers/<pod>_<namespace>_<container>-<id>.log`，扫描这个目录就能建立 id 到（namespace、pod、容器名）的映射，之后按目录的 mtime 增量刷新。
  - Podman（`libpod-<id>.scope`）：先只显示短 ID，留到以后。
- 缓存：id 到名称的映射最多 4096 项；解析不到的 30 秒后重试；目录不可读时静默回退到短 ID。
- 显示：
  - 服务页的行名形如 `nginx (docker)`、`web-7d9f (pod default/web)`。
  - 进程详情在 CGROUP 行之后加 CONTAINER 行。
  - JSON 的 `jsonProcess` 增加 `container` 对象：name、runtime、pod、namespace。
- 第二步：加 `--container <名字|ID>`，作为 `--cgroup` 的便捷写法。

验收：
- 本机 Docker 上的容器显示为容器名。
- 虚拟机里的 kind 集群显示 Pod 名和 namespace。
- 数据目录不可读时显示短 ID，不报错。

2026-09-25 实测：kind 节点内 CoreDNS 的 cgroup 同时含外层 Docker scope 与内层 `cri-containerd-…scope`。修正容器身份为最内层后，使用 `--netns pid:<CoreDNS 宿主 PID>` 采集的 JSON 显示 `container.name=coredns`、`pod=coredns-589f44dc88-4f8jn`、`namespace=kube-system`。kind 节点容器的 PID 命名空间和宿主不同；仍需从宿主运行 socktrail 并让节点 kubelet 的 `/var/log/containers` 对运行环境可见，才能同时读取宿主 PID 与节点日志名。

## 5. TCP 瓶颈判断

目标：对本机的每条 TCP 连接回答"慢在哪一侧"：网络、对端接收窗口、本端发送缓冲，还是应用自己没有数据可发。

现状：探针在 socket 事件的 TCP 分支（`pid.bpf.c` 的 `output()`）读取 srtt、mdev、cwnd、data_segs_out、total_retrans；界面的 TCP 行和 JSON 的 `kernel_tcp` 显示这些值。

内核依据（本机 BTF 已核实字段存在，4.10 起都有）：
- `tcp_sock` 里的相关字段：
  - `chrono_stat[3]`：按 jiffies 累计的 busy、rwnd_limited、sndbuf_limited 时间。
  - `chrono_start`，以及 2 位位域 `chrono_type`：当前正在计时的类别和开始时间。
  - `rate_delivered`、`rate_interval_us`、`mss_cache`，以及 1 位位域 `rate_app_limited`。
  - `snd_wnd`。
- `ss -ti` 显示的 busy、rwnd_limited、sndbuf_limited、delivery_rate 就是内核 `tcp_get_info` 用这些字段算出来的。

做法：
- 探针：在 `output()` 的 TCP 分支多读上面这些字段。
  - 位域用 `BPF_CORE_READ_BITFIELD_PROBED` 读取，要在内核矩阵上验证 cilium/ebpf 对位域重定位的处理。
  - 同时用 `bpf_jiffies64()` 取当前 jiffies。用户态把正在计时的那一段（当前值减去 `chrono_start`）加到 `chrono_type` 对应的类别上，算法与内核的 `tcp_get_info_chrono_stats` 一致。
  - 控制开销：这些字段只在 send 和 recv 事件里填，并用一个以 sk 为键的时间戳 map，限制每个 socket 每秒最多填一次。
- 用户态：
  - `probe.TCPInfo` 增加 `Busy`、`RwndLimited`、`SndbufLimited`（单位 jiffies）、`DeliveryRate` 和 `AppLimited`。
  - 先重构 `tcpHealth.Kernel`：它现在是内联的 `[2]probe.TCPInfo`，占 64 B，`TCPInfo` 加字段后会把 `flow` 撑过 768 B。改成按需分配的 `*[2]probe.TCPInfo`，只有本机 socket 的连接才分配；这样 `flow` 还会腾出约 56 B，第 2、6 项的新字段都放得下。
  - DeliveryRate 按 `rate_delivered × mss_cache × 1e6 / rate_interval_us` 计算，单位字节每秒。
  - 算比例不需要知道 HZ。要显示时长时，用两次事件的 jiffies 和 ktime 差值估算 HZ，也可以读 `/boot/config-$(uname -r)` 里的 `CONFIG_HZ`。
- 判定规则写在 `tcp_health.go`，阈值集中定义为常量，并写进文档：
  - `rwnd_limited / busy ≥ 20%`：受对端接收窗口限制，通常是对端应用读得慢或窗口太小。
  - `sndbuf_limited / busy ≥ 20%`：受本端发送缓冲限制，需要调 `SO_SNDBUF` 或 `tcp_wmem`。
  - app_limited 且 busy 时间短：应用没有数据可发，瓶颈在应用。
  - 其余情况，如果重传率高或 RTT 抖动大：判为网络。
- 界面：在连接详情的 TCP 行之后加 LIMIT 行，例如 `rwnd 63% of 12.4s busy, delivery 38 Mbit/s → peer window`。conns 表不加列，避免变得更宽。
- JSON 的 `kernel_tcp` 增加 `busy_ms`、`rwnd_limited_ms`、`sndbuf_limited_ms`、`delivery_rate_bps`、`app_limited` 和判定结果 `limit`。

验收：
- 探针 root 测试：
  - 接收端不读数据（或把 `SO_RCVBUF` 设得很小），发送端持续写：判定为 rwnd。
  - 发送端把 `SO_SNDBUF` 设得很小：判定为 sndbuf。
  - 空闲连接不给出判定。
- 与 `ss -ti` 对照：同一连接的 rwnd_limited、sndbuf_limited、delivery_rate 在同一量级（两边采样时间不同，允许有偏差）。
- 内核矩阵全部通过，重点确认 5.10 和 arm64 6.4 上的位域读取正确。

## 6. 内核丢包原因

参考 pwru、nettrace 的 `--drop` 和 dropwatch。

目标：把内核丢弃的报文按原因归到连接和进程上，回答"包到了本机，却被谁丢了"，例如防火墙、端口没有 socket、校验和错误、接收缓冲已满。

内核依据：
- 跟踪点 `skb:kfree_skb`，以 `tp_btf` 方式挂载时参数为 `(skb, location, reason)`。
- `enum skb_drop_reason` 从 5.17 开始提供。本机 6.8 上约有 100 个原因，例如 `NETFILTER_DROP`、`NO_SOCKET`、`TCP_CSUM`、`SOCKET_RCVBUFF`、`OTHERHOST`。
- 5.10 到 5.16 只有 `location`，即内核函数地址。
- 正常释放走 `consume_skb`，不经过这个跟踪点；但原因为 `NOT_SPECIFIED` 的丢包仍然很多，需要单独归类。

做法：
- 探针：新增 `SEC("tp_btf/kfree_skb")` 程序。
  - 从 skb 读网络头（`skb->head + skb->network_header`，用 CO-RE 读取），只解析 IPv4 和 IPv6 上 TCP、UDP、ICMP 的五元组。
  - 用 per-CPU hash map 按（五元组、原因或位置）聚合计数，用户态每秒读取一次并清零。不要逐包上报，否则丢包风暴时会淹没 ring buffer。
  - 按跟踪点的参数个数，或用 `bpf_core_type_exists` 判断有没有 reason；没有时只记 location。
- 默认关闭，用 `--drops` 开启：kfree_skb 在高 pps 下调用频繁，是否默认开启要等压测结果再定。
- 用户态：
  - 原因编号转名字：从内核 BTF 里读 `enum skb_drop_reason` 的枚举名，不要硬编码，因为各版本的编号不同。
  - location 用 `/proc/kallsyms` 解析成函数名。
- 归属：按五元组找到 flow（包括合并视图里的），计入这条连接的丢包统计。统计放在 `flow` 上一个按需分配的指针里（8 B，第 5 项重构 `Kernel` 之后放得下），没有丢包的连接不分配。找不到 flow 的丢包按原因计入全局汇总。
- 界面：
  - 连接详情加 DROPS 行，例如 `DROPS NETFILTER_DROP×12 NO_SOCKET×3`。
  - 状态页列出全局的丢包原因排行。
- JSON：flow 增加 `drops`（原因到次数的映射），快照增加 `drops[]` 汇总。

验收：
- 用 nftables 在 OUTPUT 链丢弃某个端口，然后 curl 这个端口：连接显示 NETFILTER_DROP 计数；第 2 项同时把它记为 timeout。
- 向本机未监听的 UDP 端口发包：6.x 内核上显示 NO_SOCKET。
- 5.10 虚拟机上显示 location 对应的函数名，不崩溃。

## 7. 监听端口页

参考 `ss -lnt`、bcc 的 solisten 和 tcpsynbl。

目标：列出本机暴露了哪些端口、属于哪个进程、谁在连、accept 队列有没有溢出。

现状：`procnet_linux.go` 读 `/proc/net` 时已经识别 LISTEN（状态 0A）和未连接的 UDP，但只用于 inode 到进程的映射。入站失败的尝试（被拒、无应答）按来源 IP 汇总在 SRC 页。

做法：
- 数据来源：
  - 用 sock_diag netlink（`inet_diag_req_v2`，idiag_states 只取 LISTEN）读取监听 socket。每项带 `idiag_rqueue`（当前 accept 队列长度）和 `idiag_wqueue`（backlog 上限），和 `ss -lnt` 的 Recv-Q、Send-Q 一致。netlink 的写法参考现有的 `internal/conntrack`。
  - 如果 sock_diag 不可用，就退回 `/proc/net/tcp{,6}`：LISTEN 行的 rx_queue 就是当前 accept 队列长度，但拿不到上限。
  - UDP 取远端地址为 0 的 socket。
  - inode 到进程用现有映射。
  - 全局溢出读 `/proc/net/netstat` 里 TcpExt 的 ListenOverflows 和 ListenDrops，取每秒的差值。
  - 每 5 秒刷新一次即可。
  - 读到的监听 socket 放在 collector 上，和现有的 socket 表（`procnet_linux.go`）一起刷新；不单独建一套采集。
- 聚合：页面是 `rows` 里的一种分组，以（协议、端口、绑定地址）为一行，行里的连接就是 Server 端是这个端口的 flow。统计以下内容：
  - 当前活动的入站连接数：Server 端是这个端口的 flow。
  - 启动以来接受的连接数：accept 事件计数。
  - 前 3 个来源。
  - 对这个端口的被拒和无应答尝试：把现有 attempts 再按目标端口汇总一次。
  - 没有监听、但被连接尝试的端口单独列在最后。
- 界面：新增 `7 PORTS` 页。
  - 列：PROTO、BIND、PORT、PROCESS、SERVICE、ACTIVE、ACCEPTED、QUEUE（当前/上限）、REFUSED、UNANSWERED、TOP SOURCES。
  - BIND 为 `0.0.0.0` 或 `::` 时用黄色，表示对外暴露；QUEUE 达到 80% 时用红色。
  - 选中一行后，底栏列出连到这个端口的连接。
- JSON 快照增加 `listeners[]`。

验收：
- 起 `python3 -m http.server 8000`，再起一个只绑 `127.0.0.1` 的服务：页面上各有一行，绑定地址正确。
- 起一个 backlog 为 1 且不 accept 的服务，用并发 curl 打满：QUEUE 显示已满，ListenOverflows 有增量。

## 8. 结构化过滤

目标：`/` 过滤支持键值条件，在连接多的机器上快速定位。

现状：`ui.go` 的 `rowMatches` 把行名和每条连接的一串文本转成小写做子串匹配。

做法：
- 语法：
  - 空格分隔的多个条件取交集，写成 `key:value`，value 支持通配符 `*`。
  - 不带键的词沿用现有的子串匹配。
  - 前缀 `!` 表示取反。
- 支持的键：
  - `port`（任一端）、`sport`、`dport`、`ip`（单个地址或 CIDR）。
  - `proto`（tcp、udp、icmp 等）、`app`、`state`、`dir`、`iface`。
  - `proc`（进程名，包括 I/O PID 里的进程）、`pid`、`svc`（服务名）。
  - `host`（域名证据）、`asn`、`cc`（国家代码）。
  - `fail`（有失败记录，依赖第 2 项）。
- 实现：新文件 `internal/app/filter.go`。
  - `parseFilter(string)` 返回 `[]condition`，每个 condition 是 `func(*flow, *collector) bool`。
  - `rowMatches` 改为：行名匹配，或者行内至少有一条连接满足全部条件。
  - 带键的条件生效时，底栏 conns 只显示满足条件的连接。
  - 解析出错时在状态栏提示，不清空已输入的内容。
- 第二步：加 `--filter`，让快照和实时输出用同一套语法。

验收：
- 单元测试覆盖每个键、CIDR、取反和多条件组合。
- 在界面输入 `port:443 dir:outbound proc:curl`，只剩下对应的连接。

## 9. 环境变量中的凭据遮蔽

目标：进程详情默认不直接显示凭据。

现状：process 标签完整显示 `/proc/<pid>/environ`。实测中会显示 API key 和 token，文档里只提醒了"可能包含凭据"。

做法：
- 键名匹配 `(?i)(token|secret|passw|pwd|key|credential|auth|cookie|session|private)` 的环境变量，值默认显示为 `••••(长度)`。
- 按 `E` 切换为显示原文，状态栏同时提示当前状态。
- 启动参数 `--show-env-secrets` 默认关闭。

验收：
- 单元测试覆盖遮蔽规则。
- 在 PTY 里检查，默认状态下没有原始值泄露。

## 10. DNS 查询记录

参考 DnsTrace 和 pktz 的 DNS 面板。

目标：每条 DNS 连接保留最近几次查询和结果，这样按进程就能看到它查询过哪些域名、结果如何、花了多久。它也是第 17 项按进程关联 DNS 的数据来源：只要应用经本机 resolver 解析，DNS 查询就是最早、最全的域名来源，ECH 和 QUIC 连接也不例外。

现状：
- DNS 连接上的 `dnsState`（`appdetail.go`）只保留最近一个问题、应答码、次数和 RTT。
- 应答里的地址由 `domain.DNSAnswers` 解析出来，但只存进了全局的 `DNSCache`。
- 进程查询本机 resolver（例如 127.0.0.53）时，lo 上的报文属于发起进程的 socket，探针的 `udp_sendmsg` 事件能把这条 DNS 连接归到这个进程。

做法：
- 扩展 `dnsState`：增加一个有上限（例如 8 条）的最近查询列表，每条记名字、类型、应答码、应答里的前几个地址、RTT 和时间。地址复用 `DNSAnswers` 的解析结果，和 `DNSCache.Observe` 共用对同一个报文的解析，不要解析两次。
- JSON：现在 DNS 信息是拼进 `detail` 字符串的。重构为 `jsonFlow` 里结构化的 `dns` 字段，沿用 `dnsState` 已有的字段（查询数、应答数、失败数、名字、类型、应答码、RTT），再加上最近查询列表；`detail` 保持不变以兼容。
- 界面：
  - 连接详情列出最近几次查询。
  - 按进程看 DNS 历史，就是 PID 页里这个进程的 DNS 连接，可以配合第 8 项的 `app:DNS` 过滤；不新增页面。
- 限制：查询经本机 stub resolver 时，lo 必须在采集接口里（自动选择时默认包含），否则查询只能归到 resolver 进程（例如 systemd-resolved）。文档写明。

验收：
- curl 解析 example.com：这次查询出现在 curl 的 DNS 连接上，而不是 systemd-resolved 的。
- NXDOMAIN 能被记录下来。
- 列表不超过上限。

## 11. 诊断结论

参考 nettrace 的诊断模式。

目标：把分散的证据合成一句结论，显示在连接详情里，例如：
- `SYN 重传 3 次无应答，丢包原因 NETFILTER_DROP → 本机防火墙拦截`
- `对端 RST → 目标端口未监听`
- `rwnd 受限 63% → 对端读得慢`

做法：
- 在 `tcp_health.go` 旁边新增一个规则表，每条规则由条件（引用第 2、5、6 项的字段）、结论和建议组成。
- 界面在连接详情加 DIAGNOSIS 行，JSON 增加 `diagnosis`。
- 规则按"有证据才下结论"来写，证据不足时不显示这一行。

验收：用第 2、5、6 项验收时构造的场景，每个都给出正确的结论；正常连接不显示诊断。

## 12. 流量趋势

参考 pktz 的 5 分钟曲线。

目标：主表每行显示近 30 秒的迷你曲线，一眼看出突发。

做法：
- 为主表显示过的行，按行的 identity 保存最近 60 秒每秒的 RX+TX，用 60 个 uint32 组成的环形缓冲。
- 最多保留 500 个 key，5 分钟没有显示过的 key 删除。
- 主表增加 TREND 列，用 `▁▂▃▄▅▆▇█` 画出 30 秒曲线。
- 第二步：选中行后在底栏画 5 分钟曲线。
- 注意：块字符属于东亚宽度有歧义的字符，在把歧义字符显示为双宽的终端里会错位，和现有的 `└`、`↑` 相同，文档里写明。

验收：环形缓冲的单元测试通过；在 PTY 里目视检查曲线和数据一致。

## 13. 进程来源链与按用户分组

参考 witr。

做法：
- 进程详情增加 ANCESTRY 行：从进程表的父链一直取到 PID 1，写成 `curl ← bash ← sshd ← systemd` 的形式。cgroup 变化的地方标出 systemd 单元或容器的边界。数据已经在 `processTable.meta` 和 `addAncestors` 里。
- 服务页的 `b` 分组增加一种 `user`：从 `/proc/<pid>/status` 的 Uid 解析用户名，结果缓存。

验收：用 `fakeProc` 构造多层进程，单元测试覆盖来源链和按用户分组。

## 14. 读回 PCAPNG

参考 ptcpdump 的 `-r` 和 termshark。

目标：离线分析 socktrail 自己录制的文件，便于分享和事后复盘。

做法：
- 增加 `--read <file.pcapng>`。
- 在 `internal/pcapng` 里增加读取器，按 EPB 的时间戳把帧送进和实时采集相同的 `collector.packet` 路径。支持按原速或尽快回放两种方式。
- 录制时每帧的注释里已经写了 interface、方向、app、origin 和 target 的 pid、start_ns、process、domain（见 `capture_session.go`）。读回时解析这些注释，恢复 flow 的 Client 和 Server。
- 离线模式不加载探针，不读 `/proc`；界面和 JSON 与实时采集一致，状态页标明数据来自文件。

验收：录制一段 curl 流量后读回，连接、域名和进程名都和录制时一致。

## 15. 显式触发的主动探测

参考 tcping 和 NextTrace（MTR 模式）。

目标：对选中连接的目标，在界面里直接验证连通性和路径，不必切换工具。

做法：
- 连接详情里按 `t`：对目标地址和端口做 5 次 TCP 建连探测（非阻塞 connect，超时 2 秒，间隔 1 秒），显示每次的建连时延或失败原因。
- 第二步，按 `T`：对目标地址做 MTR 式的逐跳探测，可用 UDP、ICMP 或 TCP 探测包，需要 raw socket 和 root 权限。每跳显示 RTT、丢包率和 ASN，ASN 复用 GeoIP 数据。
- 探测在独立的 goroutine 里执行，结果经 channel 送回主循环。只在按键后发包，探测期间状态栏显示正在探测。

验收：对本机未监听的端口得到 refused；对可达的服务得到建连时延；MTR 能对本机网关和一个公网目标逐跳显示。

## 16. 变化计算、实时 JSON 输出与 LOG 页

目标：
- 每秒算出哪些连接发生了变化。同一份结果，在界面的 LOG 页展示，也以 JSON 逐行实时输出。
- 两个方向的域名都在其中：本机进程访问了哪个域名；外部客户端用哪个域名访问了本机的哪个地址，由哪个进程提供服务。本机地址不分公网和内网。
- socktrail 只输出数据，不对域名做判断。

现状：域名证据挂在每条连接上，只能在界面、文本报告和一次性的 JSON 快照里看到，没有实时输出，也没有"刚才发生了什么"的视图。

做法：
- 变化计算，在计算层实现一次：
  - 每秒 tick 构建合并视图之后，按稳定 ID 把每条连接和上一次比较。比较的都是 `flow` 上现有的字段：
    - 新出现的连接。
    - 名字变化：`Domain` 证据的 `Group()`、`Label()` 变了，或者 `Hosts` 里出现新的 Host（HTTP/1.1 长连接、h2c）。
    - 状态变化：`TCPState`、`ICMPError`，以及第 2 项的建连结果。
    - 进程变化：`Client`、`Server` 或 `IO` 里的进程集合变了。
    - 结束：按第 1 项的规则判定。
  - 每条连接上次参与比较的这些值，压成一个小的比较键，按 ID 存在 `hostViewState` 里。它只用来比较，不是新的记录类型。
  - 新连接和名字变化要等 `lateEventWindow`（2 秒）过去才算，保证进程字段已经到齐；文档写明最多延迟 2 秒。
  - 计算结果是"本次有变化的连接 ID，以及变了哪些字段"。
- 实时 JSON 输出：`--output ndjson`，不开界面。
  - 每条有变化的连接输出一行，内容就是这条连接的 `jsonFlow`，和快照 `flows[]` 的元素是同一个结构、由同一个函数生成；另加 `changes` 字段，列出变化的字段名，例如 `["new"]`、`["name"]`、`["state","end"]`。
  - 先把 `report_json_linux.go` 里在循环中构造 `jsonFlow` 的代码提成函数，快照和实时输出共用。
  - 还在进行、但没有变化的连接，每隔 `--refresh`（默认 60 秒）输出一次最新的计数，`changes` 为 `["refresh"]`。
  - `--duration` 为 0 时一直运行到 Ctrl-C；`--process`、`--pid`、`--cgroup` 的范围照样生效。
  - 第二步加 `--log-file <path>`：界面运行时同时写文件，权限 0600，按大小滚动。
- 界面：新增 `6 LOG` 页。它是 `rows` 里的一种分组，和其他页面一样由主表和底栏组成。
  - 主表的行按 `b` 切换分组方式：按变化类型（新连接、拿到名字、以 fin 结束、以 reset 结束、失败……）；按进程；按失败原因、进程和目标（第 2 项）。
  - 行里的连接来自最近的变化和第 1 项的历史；底栏沿用现有的连接表和连接详情。
- `jsonFlow` 在现有字段基础上补充，不另起结构：
  - `id`：第 1 项已经加上。
  - 本机地址：入站时 `target` 就是被访问的本机地址，出站时 `source` 是本机地址，`direction` 说明方向。文档写明这一点，不新增字段。
  - 名字的来源继续用 `evidence.kind`；第 17 项新增的来源作为它的新取值。
  - `io`：在这条连接上有收发的进程及各自的字节数，复用现有的 `jsonProcessIO`。它是界面 I/O PID 列的 JSON 形式，现在 JSON 里还没有。
- 快照：`domains[]` 增加 `local_addresses`（入站时被访问的本机地址）和按方向的连接数；界面的域名页相应增加 LOCAL 列，超过两个地址时显示为 `+N`。

验收：
- 单元测试：
  - 新连接、名字变化、HTTP/1.1 上出现新 Host、进程到达、连接结束，各产生一次变化；没有变化时不产生。
  - 两块网卡都抓到的连接只算一次。
  - 快照和实时输出的 `jsonFlow` 由同一个函数生成，字段一致。
- 入站：本机起一个 HTTPS 服务（`openssl s_server` 或 nginx），从另一个网络命名空间用 `curl --resolve` 把两个域名分别指向本机的两个地址（内网地址也可以），然后访问。应得到两行 `changes` 含 `name` 的输出：`target` 分别是被访问的地址，`server` 是服务进程，`evidence.sni` 是对应的域名。
- 出站：本机 curl 分别访问外部的 HTTPS 和明文 HTTP 服务，`client` 为 curl，名字分别来自 `evidence.sni` 和 `evidence.hosts`。
- LOG 页：在 PTY 里检查三种分组，底栏和连接详情正常显示。

## 17. 域名覆盖：补齐缺口，标明原因

目标：两个方向上让尽可能多的连接拿到域名；拿不到的，写明原因，让下游能区分"本来就没有域名"和"有域名但看不到"。

现状（已对照代码核实）：
- 已有的来源：
  - TLS ClientHello 和 QUIC Initial 里的 SNI。
  - 明文 HTTP 的 Host、h2c 的 :authority。
  - CONNECT、SOCKS 代理的目标。
  - TLS 1.2 及以下、没有 SNI 时的证书名。
  - OpenSSL 探针读到的 SNI。
  - DNS 应答提示：`domain.DNSAnswers` 解析出应答里的名字和地址，存进全局的 `DNSCache`，形成从 IP 到域名的提示。
- 缺口：
  1. 先明文、后升级为 TLS 的协议。客户端开头的字节既不是 TLS 也不是 HTTP 时，`sniffStream` 把连接标成 `other`，`parser.finished` 随即返回真，之后的 ClientHello 就不再解析。受影响的有 SMTP、IMAP、POP3、FTP、XMPP、LDAP、NNTP 的 STARTTLS，PostgreSQL 的 SSLRequest（libpq 从 14 版起默认发送 SNI），以及 MySQL 的 SSL 请求。两个方向都受影响。
  2. PROXY 协议 v2。`proxyV2Header` 跳过了全部 TLV，没有读 `PP2_TYPE_AUTHORITY`（0x02）。负载均衡终止或重新发起 TLS 之后转发过来的入站连接，客户端原来用的域名就在这个 TLV 里。
  3. 全局 DNS 提示在 CDN 上有歧义：同一个 IP 对应很多域名，`DNSCache.Names` 只能给出一串候选。ECH 连接在线上只有外层的公开名，这时 DNS 是唯一的来源。
  4. 确实看不到的情况：应用自带的 DoH、DoT、DoQ；直接用 IP 访问；socktrail 启动前已建立的连接；HTTP/2 连接复用（同一条 TLS 连接上访问多个域名时，只能看到第一个 SNI）。

做法：
1. 协议升级后的 TLS：
   - 在 `sniffStream` 里识别这些协议客户端的开头：
     - SMTP、LMTP 的 `EHLO`、`HELO`、`LHLO`。
     - IMAP 的带标签命令，POP3 的 `CAPA`、`USER`、`STLS`，FTP 的 `AUTH TLS`、`USER`。
     - XMPP 的 `<stream:stream`，LDAP 的 BER 序列。
     - PostgreSQL 的 SSLRequest（长度 8、代码 80877103）和 GSSENCRequest。
     - MySQL 客户端的第一个包：序号为 1、带 CLIENT_SSL 标志的 32 字节 SSL 请求。
   - 识别出来后进入 upgrade 状态：继续读客户端字节，但只找升级点。升级点是这几种之一：
     - `STARTTLS`、`STLS`、`AUTH TLS` 命令。
     - XMPP 的 `<starttls`。
     - LDAP StartTLS 扩展操作，OID 为 `1.3.6.1.4.1.1466.20037`。
     - PostgreSQL、MySQL 的 SSL 请求本身。
   - 升级点之后的下一段客户端字节如果是 TLS 记录，就交给现有的 TLS 解析器，证据里记下 `upgrade`，例如 `smtp-starttls`、`postgres-ssl`。超过 16 KiB 或 30 秒还没有升级，就像现在一样标成 `other`。
   - 只匹配命令关键字，不保存升级前的明文内容，升级前的明文也不进入证据。
   - 如果 `internal/appproto` 已经识别出 SMTP、PostgreSQL 等协议，就用它的结果决定是否进入 upgrade 状态，避免两处各做一遍识别。
2. PROXY 协议 v2 的 AUTHORITY：`proxyV2Header` 按"类型、两字节长度、值"的格式逐个解析 TLV，读出 `PP2_TYPE_AUTHORITY`（0x02）。
   - 结果记在 `domain.Evidence` 上：新增字段 `ProxyAuthority`，和已有的 `ProxyClient` 并列，两者都来自 PROXY 头。
   - 没有 SNI 和 Host 时，`Group` 用它命名。
   - 其余 TLV 照旧跳过；长度越界时安全失败。
3. 按进程、按时间的 DNS 关联（依赖第 10 项）：
   - 数据来自第 10 项记在各 DNS 连接 `dnsState` 上的最近查询，以及这条 DNS 连接的客户端进程。
   - 每秒 tick 在计算层建立"进程最近解析"索引，只用于这一次计算，不保存：进程 identity → 地址 → 名字，保留 5 分钟和记录 TTL 中较短的一个。进程经本机的 stub resolver（例如 127.0.0.53）查询时，lo 上那条 DNS 连接的客户端就是真正发起解析的进程。
   - 出站连接如果没有 SNI 和 Host、带 ECH、或者只有带歧义的全局提示，就用发起进程的索引查远端地址。
   - 命中时写进这条连接现有的 `DNSDomain` 证据，`evidence.kind` 新增取值 `dns_process`，表明是按进程关联得到的；`chooseDomain` 把它排在全局 DNS 提示之前。命中多个名字时取时间最近的一个，其余作为候选写进证据。
   - 这要求 lo 在采集接口里（自动选择时默认包含），文档写明。
4. 标明看不到的原因：扩展 `domain.Evidence` 已有的原因字段，不另设一套。
   - 已有的原因：`NoSNI`、`ECH`、`NoHandshake`、`ParseError`，以及连接上的 `Preexisting`。域名页已经按这些原因，用 `Group` 给没有名字的连接分组。
   - 新增加密 DNS：`domain.Evidence` 增加一个字段（例如 `EncryptedDNS`，取值 DoT、DoQ、DoH）。
     - DoT 是 TCP 853 端口，DoQ 是 UDP 853 端口。
     - DoH：SNI 或 DNS 提示命中内置的公共 DoH 服务名单，且端口为 443。名单例如 dns.google、cloudflare-dns.com、dns.quad9.net，可以用 `--doh-list` 扩充。
     - 按进程汇总。
   - ECH：沿用已有的 `ECH` 字段，名字是外层的公开名；有 `dns_process` 的结果时一并给出。
   - 直接用 IP 访问：由已有字段判断，包括 `NoSNI`、Host 是 IP 字面量、没有任何证据三种情况；在 `Group` 里归为同一组，不新增字段。
   - 启动前已建立的连接：沿用连接上已有的 `Preexisting`。
   - HTTP/2 连接复用看不到后续的域名，只在文档里写明。
   - 这些原因同时进入界面（域名页已有的"没有名字的按原因分组"）、JSON 的 `evidence` 和第 16 项的实时输出。
- 文档：更新 `docs/internals/parsing.md` 里域名来源和缺口的说明，并在 `docs/user/measurement.md` 写明各个来源的可信程度。

验收：
- 单元测试：
  - SMTP STARTTLS、IMAP STARTTLS、POP3 STLS、PostgreSQL SSLRequest、MySQL SSL 请求之后的 ClientHello 都能解析出 SNI，证据带 `upgrade`。没有升级的 SMTP 会话仍然标为 `other`。升级前的明文不进入证据。
  - PROXY v2 带 AUTHORITY TLV 时能取到主机名；TLV 长度越界时安全失败。
  - DNS 关联：同一进程先把 a.example.com 解析成 X，随后连接 X，这条连接以 `dns_process` 命名为 a.example.com；另一个进程的解析结果不会被借用；超过时间窗口后不再命中。
- 本机实测：
  - `psql "host=<域名> sslmode=require"` 连接 PostgreSQL（libpq 14 及以上）：连接名为该域名，来源 `sni`，upgrade 为 `postgres-ssl`。
  - `openssl s_client -starttls smtp -connect <主机>:25 -servername <域名>`：连接名为该域名。
  - `curl --doh-url https://dns.google/dns-query https://example.com`：到 dns.google 的连接标为 `encrypted_dns`，进程为 curl。
- 两个方向都要验证：从另一个网络命名空间访问本机内网地址上的 STARTTLS 服务，入站连接同样拿到域名。

## 参考工具与取舍

以下工具来自维护者 star 过的网络排查项目，按和 socktrail 的相关程度排列。

| 工具 | 相关功能 | 取舍 |
| --- | --- | --- |
| [rustnet](https://github.com/domcyrus/rustnet) | 按进程的连接 TUI、DPI、过滤、带注释的 PCAPNG 导出、降权和沙箱 | 大部分已有；过滤见第 8 项。降权会让进程详情读不到其他进程的 `/proc`，暂不做 |
| [ptcpdump](https://github.com/mozillazg/ptcpdump) | 进程、容器、Pod 感知的抓包，`--netns`，带元数据的 pcapng，`-r` 读回，pcap-filter 语法 | 第 3、4、14 项；pcap-filter 需要引入 libpcap 或 BPF 编译器，暂不做 |
| [pktz](https://github.com/immanuwell/pktz) | 按进程的流量 TUI、5 分钟曲线、NDJSON 日志、Prometheus、按进程的 DNS 历史、GeoIP、演示模式 | 第 10、12、16 项；Prometheus 指标和演示模式不做 |
| [pwru](https://github.com/cilium/pwru)、[nettrace](https://github.com/OpenCloudOS/nettrace) | skb 在内核里的路径、丢包原因、诊断模式 | 第 6、11 项；逐函数的 skb 路径跟踪属于内核排障专用工具，不做 |
| [bcc](https://github.com/iovisor/bcc) | tcpconnlat、tcplife、tcpsynbl、solisten、gethostlatency | 第 1、2、7、10、16 项 |
| [DnsTrace](https://github.com/furkanonder/DnsTrace) | 按进程的 DNS 查询 | 第 10 项 |
| [witr](https://github.com/pranshuparmar/witr) | 进程、端口的来源链 | 第 13 项 |
| [tcping](https://github.com/pouriyajamshidi/tcping)、[NextTrace](https://github.com/nxtrace/NTrace-core)、[nettools](https://github.com/baidu/nettools) | TCP 探测、MTR、链路质量探测 | 第 15 项，只做显式触发；长期拨测不做 |
| [kyanos](https://github.com/hengyoush/kyanos) | L7 请求时延、内核各阶段耗时、TLS 解密。域名只来自解密后 HTTP/1.x 请求的 Host 头，不解析 SNI | 不读明文，不做。域名方面，SNI、协议升级后的 SNI 和按进程关联的 DNS 能覆盖按域名访问的连接（第 17 项）。明文协议的请求时延要成对匹配请求和应答，等第 1、2 项稳定后再评估 |
| [oryx](https://github.com/pythops/oryx) | eBPF 抓包 TUI、防火墙 | 防火墙会修改网络，不做 |
| [pktstat-bpf](https://github.com/dkorunic/pktstat-bpf) | TC、XDP 挂载，高 pps 统计 | 高 pps 压测时参考它的 per-CPU 计数设计；暂不做 |
| [termshark](https://github.com/gcla/termshark) | 报文列表和逐层解码 | 用录制的 PCAPNG 交给 Wireshark 或 termshark，不做 |
| [kubeshark](https://github.com/kubeshark/kubeshark) | 集群级 L4/L7 观测。官方文档说明：对外访问的域名取自线上 ClientHello 的 SNI，不需要解密；解密只用于集群内按 ClusterIP 访问、不带 SNI 的东西向流量；另外计算 JA3、JA3S 指纹 | SNI 已有；集群内东西向流量不是单机工具的目标，不做 |
| [coroot](https://github.com/coroot/coroot)、[pixie](https://github.com/pixie-io/pixie) | 集群级服务拓扑、APM | 面向集群的持续观测，不是单机终端工具的目标，不做 |
