# socktrail 开发说明

状态：已有可运行原型，并在当前 Linux 6.8 主机完成部分场景验证。本文主要是设计和验收约定；其中“应”“须”“需验证”的内容不等于已实现。已验证事实与剩余差距见 [验证记录](validation.md)，实际运行能力见 [README](../README.md)。

## 目标与使用边界

`socktrail` 是独立的 Linux 终端程序，直接观察内核事件和网络报文，显示宿主机网络命名空间中被选接口上的 ICMP、TCP、UDP 流量、可见的 HTTP/TLS 信息与可确认的本机进程。借鉴 pktz 的进程关联思路，但不依赖或复用它的代码，也不读取应用日志或配置。支持 `sudo socktrail` 自动选择运行中的宿主接口，也支持 `sudo socktrail --interface <name>` 显式选择；启动前检查接口、采集权限及所需内核能力，失败时给出具体原因。

接口决定报文采集覆盖范围；自动模式选择正在运行的宿主接口，显式指定可用于排查遗漏。当前最多同时采集 8 个接口。TUI 默认显示整机 PID socket 收发量和跨接口连接证据；同五元组、同连接代次的观测合成一条，IP 字节只取单个采集点，不累加接口。`0` 可进入逐网卡诊断。NAT 改写后的不同五元组、桥接转发和未经过本机 socket 的报文仍无法保证形成精确整机 IP 总量，也不得冒充本机进程流量。

## 两个统计模块与展示平面

两个统计模块分别产出可验证的指标，由同一展示平面关联。初版可在一个进程中用独立模块和有界事件队列实现，避免多进程同步与重放复杂度；这不妨碍以后拆成独立进程。模块边界按数据口径划分，不直接拼接已有程序。

| 组件 | 输入与职责 | 输出及计数归属 |
| --- | --- | --- |
| 基础流量与进程模块 | 选定接口的报文，以及 socket/进程生命周期和 I/O 事件；识别 ICMP、TCP、UDP，关联网络命名空间、端点、PID 和进程启动时间 | 唯一的界面 IP 层报文字节、包数、速率、流生命周期；如保留 socket 读写字节，只作为单独标注的应用 I/O 指标 |
| 协议证据模块 | 消费基础模块转发的有界 TCP 负载片段和连接生命周期事件，维护双向重组状态 | 带观测 ID 的 HTTP/1.1 Host 汇总次数；TLS ClientHello SNI、ALPN 和解析状态；不另产一份报文字节总量 |
| 展示平面 | 消费两模块的带时间戳快照或增量事件，按统一观测 ID 关联并维护有限期索引 | 按 PID、来源 IP、目标 IP 和协议切换的主表、底部详情面板及合并的 HTTP/HTTPS 域名页；只读取既有计数，不自行抓包或把两种字节相加 |

基础模块为每个观测对象分配稳定观测 ID，记录网络命名空间、接口、地址族、协议、端点和连接代次。协议模块用该 ID 回传证据；负载解析不能以 PID 关联成功为前提，因此未知 PID 的 HTTP Host 和 TLS SNI 也进入域名统计。展示平面按 ID 与事件时间连接，晚到或缺失的 PID/域名保持未知，并展示采集丢失和队列淘汰。TCP 连接、UDP 观测会话与 ICMP 报文使用不同对象类型，不强行套用同一生命周期。若协议模块落后、超限或崩溃，基础流量仍可统计，界面要显示协议统计不完整；若基础模块失败，整项采集停止并报错。采集原型先验证跨模块观测 ID 与计数守恒，再开发展示平面。

## 数据模型和计量点

TCP 连接与 UDP 观测会话至少显示 `direction`、`local_ip:port`、`remote_ip:port`、`src_ip:port`、`dst_ip:port`、`protocol`、`pid`、`process`、`first_seen`、`last_seen`、`rx_bytes`、`tx_bytes`、`rx_bps`、`tx_bps`、`domain`、`domain_source`。ICMP 报文共享时间、地址、方向、进程和流量字段，但端口显示“不适用”，另列 `icmp_type`、`icmp_code`；Echo 可显示 identifier、sequence。TCP/UDP/ICMP 是网络协议分类；识别出的 HTTP/1.1 或 TLS 另放 `application_protocol`。IPv4 和 IPv6 地址分别保存，不将 IPv4 映射地址意外并入 IPv6。

- `local` / `remote` 相对于被归属的本机 socket；`rx` / `tx` 相对于本机。`direction` 的 `inbound` / `outbound` 指连接发起方向。TCP 优先用观测到的 SYN（不带 ACK）确定发起方，也可用已验证的 connect/accept 事件补足。中途开始的连接可用两类证据：发出 ClientHello 或 HTTP 请求行的一端是客户端；本机连接查内核 socket 表，本地端口有监听 socket，或本地地址不属于本机（透明代理接受的连接）时为入站，否则为出站。没有证据或证据冲突时为 `unknown`，不得根据端口号猜测。UDP 没有连接建立握手，默认 `unknown`；若用首包或 socket 事件推断方向，须标明 `inferred`，不能伪装成 TCP 已确认方向。
- `src` / `dst` 是连接发起方与接收方，不能用每个报文的源/目的地址填充。无法确定发起方时这两个字段为未知，原始报文端点仍保存在内部记录；`local` / `remote` 在可确定本机端点时继续显示。
- `pid` / `process` 表示对本机 socket 执行网络 I/O 的进程及其身份。身份至少包含 PID 和进程启动时间；进程名仅是标签。事件、socket 与 PID 的归属可能分别代表建立者、接受者、读写者，必须记录归属依据和置信状态。共享 socket、进程交接或多个本机进程使用同一 socket 时，保存多个已证实的参与者，界面标明角色；不能强行选一个 PID。进程退出后保留当时身份，不用后来复用的 PID 覆盖历史。
- loopback 两端都在本机时，一个流可能有客户端和服务端两个 PID。入站服务场景展示服务进程，出站场景展示客户端进程；聚合字节只计一份，并在详情展示两个本机参与者。原型必须先证实这种关联方式可行。
- 连接键包含网络命名空间、地址族、传输协议、双端地址端口和连接代次。TCP 可利用 socket 身份及生命周期事件区分相同五元组的再次使用；UDP 使用有界空闲超时形成观测会话，并标明这是观测会话而非协议连接。ICMP 按报文事件统计；Echo 请求/响应只有在地址、类型、identifier、sequence 与时间窗口匹配时才配对，错误报文保留其引用的原始报文头但不强制归入一个连接。socket 标识不得只依赖可复用的内核指针；需配合创建/销毁事件或代次。所有索引有容量、过期和淘汰计数。

整机 IP、协议和域名页的观测字节从每条逻辑流的**一个报文采集点**产生；同五元组、同 TCP 代次的多接口观测不相加。它是可见流量样本，不是精确整机 IP 总量；NAT、代理或隧道改写地址后仍可能重复或漏计。逐网卡诊断页保留各接口原始计数。PID 页另显示当前网络命名空间内已观察到的 TCP/UDP socket I/O 返回字节，明确标为应用字节，不受接口选择限制，也不与 IP 字节混加。IP 计数按捕获报文的 IP 层长度，含 IP 与上层协议头、负载及实际观测到的重传；不含以太网头、FCS。`lo` 只保留一次发送副本。解析只复制有界负载，计数字节取原始报文长度。

连接单调计数器按两次采样的差量和实际间隔计算 bps；采样时不得把旧累计值再次累加。丢包、重组超限、超时、索引淘汰、PID 未关联数以及接口状态变化应在界面可见。采集被中断时标记时间缺口，不把缺口期零流量当成确定事实。

## 协议覆盖与字段边界

“几乎所有的信息”在这里指可见的报文元数据和经验证的进程关联，不代表可以解密内容或恢复未捕获的数据。每个字段都应携带 `observed`、`inferred`、`unknown` 或 `not_applicable` 状态；UI 不用空字符串掩盖差别。

| 类型 | 初版统计与可见字段 | 归属与限制 |
| --- | --- | --- |
| IPv4/IPv6 | 地址、IP 层长度、包数、协议、方向、时间；IPv6 扩展头和 IPv4/IPv6 分片状态 | 后续分片按分片 ID 有界关联到首片的流（4096 项、30 秒）；首片丢失时单独成流；不可解析上层头时仍计入 IP/协议总量 |
| 非 IP 帧、tun 链路 | ARP 请求/应答与 IP→MAC；PPPoE 会话内的 IP；其他帧按 EtherType、802.3 长度帧归为 LLC；tun 类接口（无链路层头）的 IP 报文 | 只统计帧数与链路层负载字节，没有进程归属 |
| TCP | 双端端口、SYN/FIN/RST 等标志、连接阶段、报文和字节、速率；有足够证据时统计重传候选 | 重传判定须考虑序列区间、乱序和抓包缺口；不能把候选数称为内核真实重传数 |
| UDP | 双端端口、数据报数、字节、速率、观测会话 | 无握手；UDP socket 可未连接，目的端点须从单次发送事件或报文确认 |
| ICMPv4/ICMPv6 | type/code 及名称、Echo 按 identifier 成流并配对 RTT、错误报文所引述的原始协议与端点（标到对应 TCP/UDP 流的状态）、邻居发现/重定向目标、分片需要的 MTU、包数和字节 | 无端口、无 TCP 式连接；本机发出的 Echo 请求按对端和 identifier 关联发送进程，内核应答的 Echo、内核生成的错误、ICMPv6 邻居发现本来就没有进程 |
| 明文 HTTP/1.1 | 完整请求头中的 Host 及按 Host 汇总的请求数 | 只保留聚合计数和解析状态，不展示或保存逐条请求、路径、请求头或正文 |
| TLS over TCP / HTTPS | ClientHello 可见 SNI、客户端提供的 ALPN、ECH 标记、握手观测次数；经 CONNECT/SOCKS4/SOCKS5 隧道时另记代理目标，PROXY protocol 头跳过并记下原始客户端 | SNI 是连接级目标提示，不是 HTTPS 请求数或 Host；TLS 1.3 的部分握手及证书信息不可见，真实 ECH 隐藏内层名称 |
| QUIC v1/v2、其他 IP 协议 | IP/协议包数和字节；QUIC 客户端 Initial 完整且认证成功时读取可见 SNI | 不用端口号推断应用协议或域名；其他 QUIC 版本、ECH 内层名与 HTTP/3 请求域名仍未知 |

DNS 查询名只能作为单独的 DNS 证据。一个查询可返回多个地址，一个地址也可承载多个站点，不能用 DNS 查询名反填 HTTP Host 或 TLS SNI。当前实现把 DNS 应答用作标为 `DNS` 的名称提示，只给没有 Host/SNI/代理目标/进程 SNI 的连接使用。多播、广播、ICMP 控制报文及无法关联进程的流量可在协议/IP 视图查看，并明确显示未知 PID。

## 域名证据与归属

保存 `http_host`、`tcp_tls_sni`、`quic_tls_sni`、`proxy_target`、`openssl_process_sni`、`dns_hint` 六种独立来源，同时给连接详情提供 `domain` 和 `domain_source`。TCP 的 Host/SNI/代理目标解析自客户端字节，这些字节取自所选接口的报文，或在 `tcp_sendmsg`/`tcp_recvmsg` 读取的 socket 层副本（每个 socket 每个方向前 16 KiB）。报文给出名字时优先用报文，因为它能数完所有 HTTP 请求。选择顺序是客户端字节中的 Host/SNI/代理目标、进程 SNI、DNS 提示；带 ECH 扩展的线上 SNI 让位于进程 SNI。多接口合并时按同样顺序挑证据。域名做大小写与末尾点规范化；反向 DNS 只能是地址提示，不能填入实际访问域名。入站 Host/SNI 是被访问服务的名称，不代表客户端来源域名。进程侧 SNI 必须先验证 socket 五元组与网络命名空间，不能只凭 PID 将域名广播到该进程所有连接。

明文 HTTP/1.1 只在完整请求头后为该 Host 增加一次聚合计数，不保存逐条请求。必须按请求循环解析，同一 TCP 连接可有多个请求和 Host；重传、乱序或重复采集不能重复增加请求数。解析器需要能越过请求体，至少处理 `Content-Length` 和 chunked 编码，才能可靠识别后续请求；消息边界不明、升级协议或超限时停止该方向的请求解析并记录原因；抓包只复制了前缀的请求体按长度跳过。HTTP `CONNECT` 的目标 authority 与 SOCKS4/4a、SOCKS5 请求的地址记为代理目标，不当作普通请求域名，也不计请求数；之后的隧道字节重新识别协议，其中的 ClientHello 或明文请求照常解析。

TLS over TCP 解析客户端 ClientHello 的可见 SNI，作为连接级目标域名；一个握手只产生一次 SNI 证据，不产生 HTTP 请求数。ClientHello 可以跨 TCP 段或 TLS record，须按长度字段逐层解析。QUIC v1/v2 对客户端 Initial 做认证、解保护和有界 CRYPTO offset 重组，再复用 ClientHello 解析。HTTPS 请求 Host、HTTP/2/3 `:authority` 位于加密应用数据中，纯旁路采集无法读取；不能凭 SNI 生成请求数。无 SNI、解析失败或只见握手之后的数据时，按原因显示未命名分组。带 ECH 扩展的 ClientHello 按线上 SNI 分组并标 `[ECH]`：浏览器默认发送 GREASE ECH，此时线上 SNI 就是真实域名；真实 ECH 时它是服务商公共名，内层名旁路不可见。ClientHello 解析完成后该方向停止重组，之后的抓包缺口不计为解析失败。默认 OpenSSL 用户态探针仅在已支持调用路径提供可关联 socket 的进程 SNI；它不是通用解密器。

TCP 两个方向分别维护有界重组状态，以序列号处理跨包、乱序和重传。必须先验证报文截断、IP 分片、TCP 序列号回绕、连接中途加入、缺段、FIN/RST、超时及内存上限的行为。解析 HTTP 请求只检查请求方向；若方向无法确认，不猜测 Host。TLS 只保留握手识别所需的前段数据；HTTP 按请求逐个释放已消费数据。原始正文不写入日志或磁盘。

域名页中的流量分组是互斥分区：一条进入此页的连接，其字节只属于一个分组。明文 HTTP 只观察到一个不同 Host 时归入该 Host；多个不同 Host 时归入“多域名/无法按请求拆分”；TCP/QUIC SNI 归入各自的 SNI 组，带 ECH 扩展的另加标记；代理目标只在隧道内没有 SNI/Host 时成组；OpenSSL 进程 SNI 只在报文证据未知或带 ECH 时补充；DNS 提示只用于前面都没有名字的连接。如果进程 SNI 与不带 ECH 的报文 Host/SNI 冲突，保留报文名称并在详情标记冲突。已识别 TLS/QUIC 但没有目标名的连接按原因分组：握手未捕获、无 SNI、解析失败、尚未完成。不同 Host 的请求数可分别计数，但这些请求数与连接字节是不同指标。UDP、ICMP 和未识别为 HTTP/TLS/QUIC 的 TCP 仍保留在主表及连接详情；域名页同时显示页内流量和全部 IP 流量。

## 统计与终端界面

界面采用 pktz 式主表和底部详情面板；主表按 PID、来源 IP、目标 IP 或协议切换，底栏切换曲线、连接/报文和进程信息。HTTP 与 HTTPS 共用一个域名页，显示 Host/SNI 证据和连接流量，包含已知及未知 PID；明文 HTTP 只显示 Host 汇总次数，不展示逐条请求。TLS 连接以 `TLS` 标识，不仅凭 SNI 断定为 HTTPS。具体布局见 [终端界面草图](ui-design.md)。来源/目标 IP 按已确认的连接发起方/接收方分组；ICMP 等无连接协议按报文地址分组，并标明与连接发起方的语义不同。方向未知时归入“未知发起方”，仍允许按 `local` / `remote` IP 搜索。各分组分别显示 TCP 连接数、UDP 会话数、ICMP 报文数，以及累计字节和当前速率；不将三种对象数量相加称为“连接数”。支持按字节或速率排序，按 IP、域名、协议或 PID 过滤，并可展开到详情。

PID 分组使用 PID 加启动时间，不把复用后的进程合并。进入 PID 后查看其关联的连接、会话或报文，以及连接上的 Host/SNI 证据和流量。没有可见 HTTP 请求证据的 TLS 连接只展示连接和 SNI，不能伪造请求数。Host 汇总次数不分摊连接的 IP 层字节；同一个连接有多个 Host 时，字节进入“多域名”组。

当前 PID 页按执行 `sendmsg`/`recvmsg` 的进程和启动时间统计**应用 socket I/O 字节**。多个本机参与者可分别看到自己的读写量；连接详情仍可显示同一连接，但这些应用字节不与 IP 报文字节核对求和。PID 不明的连接继续在 IP/协议/域名视图及详情显示。未覆盖的 socket 路径、丢失的事件和无法匹配的连接明细必须显式记录；“已关联连接”不等于其所有字节都能归给该 PID。

帮助与快捷键在界面内可见。详情展示原始端点、方向证据、进程归属依据、Host/SNI、请求数、计数口径及解析失败原因。退出时关闭抓包描述符、卸载内核挂载的采集程序并释放有界缓存。

## 实施顺序与停止条件

1. **采集原型**：先在目标 Linux 上选定报文采集点和 socket/进程事件点，再决定库与 eBPF hook。分别由两个 PID 发起出站连接，另运行入站服务；覆盖 IPv4/IPv6、TCP/UDP、ICMPv4/ICMPv6、`lo` 与指定物理接口。检查连接两端进程身份、方向、PID 复用及观测丢失。用 Echo 和内核生成的 ICMP 错误验证“有 PID”与“未知 PID”都能正确呈现。若 TCP/UDP 归属误判或大量丢失，修正采集方案后再进入 TUI。
2. **计数与生命周期**：实现逐接口 IP 层长度累计、连接代次、速率和资源上限。对照受控报文及独立抓包工具，记录 offload 设置与抓包丢失；证明重传只按实际被捕获的报文计入，loopback 和多网卡场景没有悄悄合并成虚假的整机总量。
3. **协议解析**：加入 ICMP type/code 与 Echo 配对、有界 TCP 重组、HTTP/1.1 请求边界与 TLS ClientHello 解析。覆盖跨包、乱序、重传、无 Host/SNI、多 Host、ECH 外层名及解析失败；失败保持未知。
4. **聚合与 TUI**：落实互斥域名字节分组、来源/目标/PID/协议视图、排序、过滤、详情与状态指标。验证主表各分组的总字节与基础模块的观测总量一致；域名页只与已识别 HTTP Host、TCP/QUIC SNI 或已关联进程 SNI 的连接总量核对，同时列出未进入该页的流量。
5. **交付**：补充实际构建/运行命令、最低内核能力、权限、依赖版本、定向测试和实机验证记录。未经另行授权，不提交、推送、部署或常驻运行。

任何阶段若关键采集点无法稳定提供承诺的 PID、方向或字节口径，应暂停后续阶段，记录可复现样本和替代方案；不能在界面中静默显示错误或缺失的统计。

## 验收记录模板

目标机验证时逐项记录内核版本、网络命名空间、接口/ifindex、offload 状态、采集点、测试命令、预期与实测、丢包/淘汰计数。至少覆盖：两个并发出站 PID；进程退出及 PID 复用；从客户端和服务端 PID 查看各自关联的 Host 汇总及连接流量，且全局只计一次；入站 HTTP Host 与服务 PID；双向 TLS SNI；未知 PID 的 SNI 流量；TLS 流无可见请求时不生成请求数；跨段和乱序 ClientHello/HTTP 请求头；重传；无 Host/SNI 与 ECH；同连接多 Host；UDP；IPv4/IPv6 Echo；ICMP 错误与未知 PID；IPv6；loopback；接口切换；退出后的资源清理。只完成单元测试不能标记实机验证通过。

## 参考实现与待验证判断

- pktz 源码快照 [`e580e7e`](https://github.com/immanuwell/pktz/tree/e580e7e3339635e3e6cd9a11e174f38ccc3ccb09)：其 [eBPF 计数](https://github.com/immanuwell/pktz/blob/e580e7e3339635e3e6cd9a11e174f38ccc3ccb09/bpf/pktz.c)使用 TCP send/read 等 socket 路径，[/proc 关联](https://github.com/immanuwell/pktz/blob/e580e7e3339635e3e6cd9a11e174f38ccc3ccb09/internal/collector/procnet.go)扫描 inode 和进程 fd。它可提示 PID 关联与淘汰问题，但计数口径不同，且其 PID 键没有进程启动时间；不复制实现。
- Linux [Packet MMAP 文档](https://www.kernel.org/doc/html/latest/networking/packet_mmap.html)描述了 AF_PACKET 环形缓冲和抓包状态；具体驱动与 offload 对计数的影响仍需目标机实测。
- [RFC 792](https://www.rfc-editor.org/rfc/rfc792.html)与 [RFC 4443](https://www.rfc-editor.org/rfc/rfc4443.html)定义 ICMPv4/ICMPv6 的类型和代码；[RFC 9112](https://www.rfc-editor.org/rfc/rfc9112.html)定义 HTTP/1.1 消息边界；[RFC 8446](https://www.rfc-editor.org/rfc/rfc8446.html)定义 TLS 握手结构。

当前原型已经选择 AF_PACKET 与内嵌 CO-RE eBPF fentry/fexit 探针，覆盖 TCP connect/accept/send/receive、UDP send/receive，以及原始 socket 和 ping socket 发出的 ICMP Echo 请求。accept 在内核有 `__inet_accept`（Linux 6.8 起）时挂它的 fentry，否则挂 `inet_csk_accept` 的 fexit，两者只加载一个：后者在 6.10 改了签名，而且挂载时已经阻塞在 `accept()` 里的调用返回时不经过它。内核 socket 表（`/proc/net` 与 `/proc/<pid>/fd`）为两端都没有 PID 的连接补充进程和中途方向。

跨内核的差异按内核自己的 BTF 处理，不按版本号猜：recvmsg 系列在 5.19 去掉了 nonblock 参数，每个 recvmsg 程序都有旧签名的 `_old` 版本，加载器按 `tcp_recvmsg` 的参数个数保留其一；`iov_iter` 在 5.14 之前没有 `iter_type`，用 CO-RE 回退读旧的 `type` 位集合；5.12 之前 tracing 程序不能调用 `bpf_get_socket_cookie`，加载器用一个极小的探测程序判断，不可用时 socket 层读取以 socket 的内核地址作键，并在 `inet_sock_destruct` 时清掉该地址的预算（`sk_free` 不行，发送路径每次释放写内存引用都会调用它）。进程启动时间读 `start_boottime`（5.5 之前为 `real_start_time`），与 `/proc` 同一基准。老版本校验器不接受栈上未初始化的结构填充字节，写入 map 的结构都显式补齐；socket 层读取的分块循环把游标放在 map 内存里，否则 5.15 的校验器会因路径组合过多拒绝加载。x86-64 上已在 5.10、5.11、5.13、5.15、6.8、6.17、7.0 内核验证；需要 BTF、fentry（5.5）和 ring buffer（5.8）。

Inbound 服务 PID（含启动前已阻塞在 `accept()` 的服务和双栈监听）、两个并发客户端 PID、`fork` 后共享 TCP socket 的接受者与 I/O 执行者、普通 TCP 双端 socket I/O、UDP 未连接 socket、IPv4/IPv6、loopback、同时观察 `lo`/`br0`、tun 接口、从独立网络命名空间发起的入站 ICMP/ARP/分片/TCP/UDP/QUIC、本机 ping 进程、2,500 条短连接样本和一分钟的关闭流回收已实测；真实 PID 数值复用、其他共享方式、NAT、容器网络、极限负载、arm64 仍需验证或实现。上文超出原型能力的规则继续作为目标，不能视为当前能力。
