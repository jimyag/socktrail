# 与 RustNet 的协议识别对照

对照对象是 [RustNet 当前 main 分支的 README](https://github.com/domcyrus/rustnet)。该 README 明确提示部分功能尚未进入 v1.6.0 发布版；本表不把开发分支的声明当作本机实测。socktrail 仅借鉴功能范围，不复用 RustNet 源码。

| 能力 | socktrail 当前状态 | 边界 |
| --- | --- | --- |
| HTTP/1.1、HTTP/2（h2c）、TLS | 已有有界 TCP 重组；Host、明文 HTTP/2 的 `:authority`（HPACK 解码，按请求计数，gRPC 单独标注，含经 `Upgrade: h2c` 升级的连接）与 ClientHello SNI 分别记录，带 ECH 扩展的标 `[ECH]`；识别 HTTP CONNECT、SOCKS4/4a、SOCKS5 代理目标并解析隧道内握手；跳过 PROXY protocol v1/v2 头并记下原始客户端；读服务端 ServerHello 的版本和 ALPN，无 SNI 的 TLS 1.2 连接用证书名命名，握手失败时给出双方的 alert | TLS SNI 不能代替 HTTPS 请求域名；真实 ECH 内层名、加密 Host、经 TLS 的 HTTP/2 `:authority`、TLS 1.3 的证书未知 |
| DNS、mDNS、LLMNR、NetBIOS NS | 识别消息头与相应端口（DNS 也识别 TCP 上的），标注协议；每条流显示最近的查询名、类型、应答码、失败次数，以及按事务 ID 配对的应答时延（最近一次和最小值）；UDP 53 应答及单段内完整的 TCP DNS 应答的 A/AAAA 作为连接的名称提示 | 尚无跨流的 DNS 查询历史；NetBIOS 目前只识别名称服务 |
| SSH、FTP、MQTT、BitTorrent、STUN、NTP、DHCP/DHCPv6、SNMP、SSDP | 报文负载特征识别；SSH 另记两端的版本标识 | TCP 类协议的签名若跨段拆开可能漏识别；不解析会话内容 |
| Kafka、AMQP、NATS、ZooKeeper、Memcached、SQL Server、Oracle TNS、Cassandra、LDAP、Kerberos、NFS/RPC | AMQP 按协议头、NFS 及 portmapper/mount/lock 按 ONC RPC 调用结构识别；其余按报文结构在默认端口上确认 | 非默认端口上的前一类不猜；不读取查询、主题或凭据 |
| QUIC | 识别带已知版本号（v1、v2、草案、GREASE 等）的长包头；对 v1/v2 客户端 Initial 完成认证、CRYPTO 重组并读取可见 SNI；本机 UDP socket 发出的 Initial 也在 socket 层读取 | 未知版本、ECH 内层名、HTTP/3 authority 或请求数仍未知；短包头通常不能单独归因 |
| WireGuard、OpenVPN、IKE/IPsec | WireGuard 握手报文的类型与长度，以及传输数据的 16 字节对齐；OpenVPN 默认端口上的控制通道重置报文；IKE 头部长度一致性，UDP 4500 上的 NAT 穿越 ESP | 其他端口的 OpenVPN、加密控制包和单凭数据包均不推断协议 |
| SMTP、Redis、PostgreSQL、MySQL、MongoDB、SMB、RDP、VNC、Telnet、SIP、RTSP | 额外的浅层特征识别，端口只用于限定特征 | 只标注应用，不读取凭据、查询或请求详情 |
| VXLAN、GENEVE、Syslog、TFTP、RADIUS | 端口加头部字段校验 | 不解开隧道内层的帧 |
| ICMPv4/v6 | type/code 名称；Echo 按 identifier 成流，给出请求/应答数与 RTT；错误报文解出引用的原始报文并标到对应流；邻居发现目标、分片需要的 MTU；本机发出的 Echo 请求关联发送进程 | 内核应答的 Echo 和内核生成的错误没有进程 |
| ARP 与其他链路层帧 | ARP 请求/应答与 IP→MAC 对应；按 EtherType 计入 LLDP、LACP、PPPoE、MPLS 等帧，802.3 长度帧归为 LLC；PPPoE 会话内的 IP 按普通流统计；tun 类接口按 IP 报文解析 | 不维护设备清单或 MAC 厂商信息 |
| TCP 健康 | 本机 socket 取内核的平滑 RTT、拥塞窗口、已发送段数和重传（与 `ss -ti` 一致）；转发流量用出站 SYN→SYN-ACK 时差样本和有界序号重叠推断 | 无 fast retransmit 或乱序分类 |
| 进程分组 | 按 systemd 服务或容器、cgroup 路径、进程树分组；`--process`、`--pid`（含子孙）、`--cgroup` 只看指定进程 | 只覆盖当前网络命名空间内的进程 |
| PCAPNG | 按活动连接或 PID 主动录制 15 秒、最多 64 MiB，含接口和尽力而为的进程/域名注释 | 非全局连续录制；PID 迟到时不回填；多接口 PID 文件可能含重复报文 |
| NAT | 每条新 TCP/UDP 流向 conntrack 查一次改写前后的元组：网关两侧合为一条 `forwarded` 连接，本机进程的 socket 对上 DNAT/SNAT 之后的报文，详情列出改写 | 需要内核已加载 `nf_nat` 与 `nf_conntrack_netlink`；conntrack zone 非 0 的条目查不到 |
| 扫描 | 被拒和无应答的入站尝试按来源汇总端口数与次数；流表满时先淘汰这类一次性流 | 只统计到达所选接口的尝试，不做告警 |

仍缺的主要诊断项是 QUIC RTT、跨流的 DNS 活动历史、TCP 乱序与 fast retransmit 的独立分类、跨 TCP 段的通用应用签名、设备清单、SCTP/GRE/ESP 等其他网络协议的深入解析，以及 QUIC 未知版本/ECH/HTTP3 加密请求域名的覆盖。tun 接口的报文已能解析，但它和跨接口非对称路径的 PCAPNG 导出尚未用 Wireshark 验收。快照可以输出 JSON；RustNet 的 Prometheus 等其他导出和更多筛选功能没有做。容器、域名拦截、GeoIP 按用户要求不加入。

识别原则：只根据实际负载特征给出 `APP`，不能单凭端口号确认应用协议；`APP=TLS` 不等于已知 HTTPS 请求域名，`APP=QUIC` 不等于已知 HTTP/3。只有 ClientHello 完整、QUIC Initial 认证成功、代理请求给出目标，或 OpenSSL 进程 SNI 准确关联 socket 时，才把名称作为报文或进程证据放入域名页；DNS 应答只作为单独标注的提示。未命名的连接按原因分组，仍保留 IP、PID 与字节统计。
