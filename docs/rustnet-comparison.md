# 与 RustNet 的协议识别对照

对照对象是 [RustNet 当前 main 分支的 README](https://github.com/domcyrus/rustnet)。该 README 明确提示部分功能尚未进入 v1.6.0 发布版；本表不把开发分支的声明当作本机实测。socktrail 仅借鉴功能范围，不复用 RustNet 源码。

| 能力 | socktrail 当前状态 | 边界 |
| --- | --- | --- |
| HTTP/1.1、TLS | 已有有界 TCP 重组；Host 与 ClientHello SNI 分别记录，带 ECH 扩展的标 `[ECH]`；识别 HTTP CONNECT、SOCKS4/4a、SOCKS5 代理目标并解析隧道内握手；跳过 PROXY protocol v1/v2 头并记下原始客户端 | TLS SNI 不能代替 HTTPS 请求域名；真实 ECH 内层名、加密 Host 未知 |
| DNS、mDNS、LLMNR、NetBIOS NS | 识别消息头与相应端口，标注协议；UDP 53 应答的 A/AAAA 作为连接的名称提示 | 尚无 DNS 查询历史、查询与响应配对或 RTT；NetBIOS 目前只识别名称服务 |
| SSH、FTP、MQTT、BitTorrent、STUN、NTP、DHCP/DHCPv6、SNMP、SSDP | 报文负载特征识别 | TCP 类协议的签名若跨段拆开可能漏识别；不解析会话内容 |
| QUIC | 识别带已知版本号（v1、v2、草案、GREASE 等）的长包头；对 v1/v2 客户端 Initial 完成认证、CRYPTO 重组并读取可见 SNI；本机 UDP socket 发出的 Initial 也在 socket 层读取 | 未知版本、ECH 内层名、HTTP/3 authority 或请求数仍未知；短包头通常不能单独归因 |
| WireGuard、OpenVPN、IKE/IPsec | WireGuard 握手报文的类型与长度，以及传输数据的 16 字节对齐；OpenVPN 默认端口上的控制通道重置报文；IKE 头部长度一致性，UDP 4500 上的 NAT 穿越 ESP | 其他端口的 OpenVPN、加密控制包和单凭数据包均不推断协议 |
| SMTP、Redis、PostgreSQL、MySQL、MongoDB、SMB、RDP、VNC、Telnet、SIP、RTSP | 额外的浅层特征识别，端口只用于限定特征 | 只标注应用，不读取凭据、查询或请求详情 |
| VXLAN、GENEVE、Syslog、TFTP、RADIUS | 端口加头部字段校验 | 不解开隧道内层的帧 |
| ICMPv4/v6 | type/code 名称；Echo 按 identifier 成流，给出请求/应答数与 RTT；错误报文解出引用的原始报文并标到对应流；邻居发现目标、分片需要的 MTU；本机发出的 Echo 请求关联发送进程 | 内核应答的 Echo 和内核生成的错误没有进程 |
| ARP 与其他链路层帧 | ARP 请求/应答与 IP→MAC 对应；按 EtherType 计入 LLDP、LACP、PPPoE、MPLS 等帧，802.3 长度帧归为 LLC；PPPoE 会话内的 IP 按普通流统计；tun 类接口按 IP 报文解析 | 不维护设备清单或 MAC 厂商信息 |
| TCP 健康 | 出站 SYN→SYN-ACK 时差样本及有界序号重叠计数 | 无 fast retransmit、乱序分类、丢包率或内核真实重传数 |
| PCAPNG | 按活动连接或 PID 主动录制 15 秒、最多 64 MiB，含接口和尽力而为的进程/域名注释 | 非全局连续录制；PID 迟到时不回填；多接口 PID 文件可能含重复报文 |

仍缺的主要诊断项是 DNS/QUIC RTT、DNS 活动历史、TCP 乱序与 fast retransmit 的独立分类、跨 TCP 段的通用应用签名、设备清单、SCTP/GRE/ESP 等其他网络协议的深入解析，以及 QUIC 未知版本/ECH/HTTP3 加密请求域名的覆盖。tun 接口的报文已能解析，但它和跨接口非对称路径的 PCAPNG 导出尚未用 Wireshark 验收。RustNet 还提供更多筛选和导出功能；此前用户已决定优先完成 PID、连接生命周期和多接口，DNS 历史、JSON/Prometheus 输出等不在本次增量里。容器、域名拦截、GeoIP 按用户要求不加入。

识别原则：只根据实际负载特征给出 `APP`，不能单凭端口号确认应用协议；`APP=TLS` 不等于已知 HTTPS 请求域名，`APP=QUIC` 不等于已知 HTTP/3。只有 ClientHello 完整、QUIC Initial 认证成功、代理请求给出目标，或 OpenSSL 进程 SNI 准确关联 socket 时，才把名称作为报文或进程证据放入域名页；DNS 应答只作为单独标注的提示。未命名的连接按原因分组，仍保留 IP、PID 与字节统计。
