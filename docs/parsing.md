# 解析原理

从 [中文首页](../README.zh-CN.md) 进入。报文先由 [packet.go](../internal/capture/packet.go) 解出网络和传输层；应用协议提示来自 [appproto/detect.go](../internal/appproto/detect.go)，域名证据由 [domain/stream.go](../internal/domain/stream.go) 及各协议解析器维护。域名标签是可见证据，不等于解密后的请求内容。

## 协议识别

连接详情有 `APP`、`SYN RTT`、`RETX` 列。

`APP` 可识别 HTTP、HTTP/2（h2c；请求带 gRPC 内容类型时标 gRPC）、TLS、DNS（含 TCP 上的 DNS）、SSH、FTP、SMTP、Redis、PostgreSQL、MySQL、MongoDB、SQL Server、Oracle TNS、Cassandra、Kafka、AMQP、NATS、ZooKeeper、Memcached、LDAP、Kerberos、NFS 及其 RPC 辅助服务（portmapper、mount、lock）、SMB、RDP、VNC、Telnet、SIP、RTSP、QUIC、MQTT、BitTorrent、WireGuard、OpenVPN、IKE、IPsec ESP（NAT 穿越）、VXLAN、GENEVE、STUN、NTP、mDNS、LLMNR、DHCP、DHCPv6、SNMP、SSDP、Syslog、TFTP、RADIUS、NetBIOS NS。

Kafka、NATS、ZooKeeper、Memcached、SQL Server、Oracle TNS、LDAP、Kerberos、Cassandra 的首包特征不够独特，只在默认端口上按报文结构确认，换了端口不猜；AMQP 和 NFS/RPC 按协议头或 RPC 调用结构识别，不限端口。除 Oracle TNS 和 NFS 外，这些标签都用真实服务和它们自带的客户端核对过，见[验证记录](validation.md)。

连接名称列在域名之后附带应用自报的信息：DNS 的查询名、类型、应答码和失败次数，SSH 两端的版本标识，TLS 握手失败时的 alert。

`4` 的协议页按“协议 + APP”分组：TCP/UDP 之外还有 ICMPv4/ICMPv6、SCTP、GRE、ESP 等 IP 协议名，以及 ARP、LLDP 等非 IP 帧；未知应用仍保留为 TCP/UDP。

多数应用标签采用单包有界特征；QUIC 标签要求长包头带已知版本号，只有成功认证并重组受支持的客户端 Initial 后才会产生 QUIC SNI，且不会生成 HTTP/3 请求数。

与 [RustNet 的功能清单](https://github.com/domcyrus/rustnet) 的具体差异见 [协议与功能对照](rustnet-comparison.md)。

## 域名证据与优先级

### 证据来源

域名来源在页面上分开标为 `HTTP`、`HTTP/2`、`TLS`、`QUIC`、`PROXY`、`OPENSSL`、`DNS`。

`HTTP/2` 是明文 HTTP/2 连接里每个请求的 `:authority`，HPACK 按连接逐块解码，按请求计数，与 HTTP/1.1 的 Host 一样。

前五者来自客户端发出的字节，取自所选接口的报文，报文没给出名字时取 socket 层的同一份字节（连接详情的 `APP` 来源标 `(socket)`）：`PROXY` 是 HTTP CONNECT、SOCKS4/4a 或 SOCKS5 请求里的目标，隧道里的 ClientHello 或明文请求仍按 `TLS`、`HTTP` 记录，连接详情标出经由的代理。

连接开头的 PROXY protocol v1/v2 头（负载均衡器转发到后端时加上）会被跳过，详情列出其中的原始客户端地址。

`OPENSSL` 来自默认开启的本机进程探针，只有同时取得进程、socket 和已观测连接的准确对应关系时才进入域名页；它仍是 SNI，不能当成加密 HTTP Host。

`DNS` 表示连接对端 IP 最近出现在抓到的 DNS 应答里，只给没有握手证据的连接使用；一个 IP 可以服务多个域名，所以它只是提示。

### 命名优先级

每条连接按报文中的 Host/SNI/代理目标、OpenSSL 进程 SNI、DNS 提示的顺序取名字；带 ECH 扩展的 ClientHello 例外，进程 SNI 优先。

客户端没发 SNI（多半是按 IP 连接）而服务端用 TLS 1.2 及以下时，证书还是明文，连接以叶子证书的第一个 DNS 名（没有 SAN 时取 CN）命名，标 `[cert]`；TLS 1.3 的证书是加密的，这类连接仍归入 `no SNI`，详情说明原因。

### 未命名连接与展示

没有名字的连接按原因分组：`handshake not captured`（握手早于抓包，或没经过所选接口）、`no SNI`、`parse failed`（详情给出原因）、`unknown`（握手尚未完成）。

域名页第二行显示启动后建立的 TLS/QUIC 连接流量中已命名的比例、其中来自 DNS 提示的比例和各类未命名原因；启动时内核 socket 表里已有的连接握手早于抓包，它们的流量在同一行单独列出，不计入比例。

连接详情的 `EVIDENCE` 行列出 ECH、客户端提供的 ALPN、服务端选定的 TLS 版本和 ALPN（TLS 1.3 的 ALPN 已加密）、证书名、代理目标、解析错误、连接是否早于抓包、NAT 改写（`SNAT 原地址 as 新地址`、`DNAT 原目标 to 新目标`），以及该 IP 最近解析过的所有域名。

整机页合并同一连接的跨接口证据；同一条连接的字节只进入一个域名分组。

PID 页的 socket I/O 覆盖整个当前网络命名空间，因此 PID 行有流量并不代表抓到了该连接的握手。

### 接口覆盖边界

本机启用 `dae` 时，实测出站 ClientHello 经过 `dae0`，而 `br0` 对同一连接只看到了回包；自动选接口可补充这种非对称路径。

启动前已经完成的握手不能从历史报文补出；进程探针只观察挂载后的库调用。

这类连接只有在应用之后重新解析域名、且 DNS 应答以明文经过采集接口时，才能得到 `DNS` 提示。

## QUIC Initial

客户端 Initial 的解密与 CRYPTO 重组见 [quicinitial](../internal/quicinitial/initial.go)。

QUIC v1/v2 仅解析成功认证的客户端 Initial 中的 ClientHello；乱序 CRYPTO 片段可有界重组。其他 QUIC 版本、HTTP/3 加密的请求域名与请求数仍未知。无 SNI、漏抓握手、解析失败时保留 IP/PID/字节，按原因显示未命名分组；进程探针若恰好观察到该连接的 SNI，可独立补充。

## ECH 与线上 SNI

带 ECH 扩展的 ClientHello 按线上 SNI 分组并标 `[ECH]`。Chrome 117 起、Firefox 启用 ECH 后都会对每个 TLS 和 QUIC 连接发送 GREASE ECH，这时线上 SNI 就是真实域名；真实 ECH 时它是服务商的公共名，内层域名旁路看不到。

## TCP 重组与请求体

[Stream.AddSegment](../internal/domain/stream.go)按 TCP 序号交给解析器：重复区间不重复解析，超前片段暂存，缺口补齐后再继续。暂存最多 64 个片段、64 KiB；若捕获前缀后的字节缺失，解析器只在能按已知长度跳过 HTTP 请求体或帧内容时继续，否则记录截断失败。

客户端 ClientHello 解析完成后不再重组该方向的字节，之后的丢包或超过 16 KiB 保留上限的 TSO/GRO 段不再记为解析失败；HTTP 请求体中没复制到的字节按长度跳过，后续请求照常计数。没看到 SYN 时，从以 ClientHello 或 HTTP 请求行开头的报文开始解析。只有记录层 TLS 应用数据、没有握手的连接归入 `handshake not captured`。

连接开头的字节先要判断是哪种协议。HTTP 请求行要求方法之后的目标像路径、URI 或 authority，完整的一行还要以 `HTTP/1.x` 结尾：NATS 客户端以 `CONNECT {...}` 开头，此前被当成 HTTP 的 CONNECT，之后因为等不到请求头结束而记成解析超时。客户端只发了几个字节就不再发送时（memcached 的 `stats`、Cassandra 9 字节的 OPTIONS 帧），30 秒后归为其他协议，不算解析失败。

## 服务端 TLS 握手

服务端握手解析见 [tls_server.go](../internal/domain/tls_server.go)。

TLS 服务端回复只在客户端 ClientHello 解析成功后读，从服务端第一个以 TLS 记录开头的报文开始（CONNECT 或 SOCKS 的应答因此被跳过）。服务端报文在采集点之前丢失、重传随后才到时，先到的报文暂存，缺口补上后按序处理；暂存与客户端方向同样最多 64 个片段、64 KiB，缺口 10 秒没补上就停止解析。读到 ServerHello 即取版本和 ALPN；TLS 1.3 或客户端带了 SNI 时到此为止，否则继续读到 Certificate 消息里的叶子证书为止，不等证书链其余部分。证书只按 DER 结构取名字，不校验，最多 8 个名字，也不引入 `crypto/x509`（二进制会大约 2 MB）；缓冲最多 64 KiB，读完即释放。服务端解析挂在客户端流对象上，两者属于同一次握手，证据落在同一条记录里。alert 按报文判断：一个报文恰好是一条 7 字节的明文 alert 记录才算，所以只看得到握手失败时的 alert；握手后的 alert 都是加密的。

## 明文 HTTP/2

帧和 HPACK 解析见 [http2.go](../internal/domain/http2.go)。

明文 HTTP/2 从客户端的连接前言开始解析，只读 HEADERS 和 CONTINUATION 帧，其余帧按长度跳过，没抓全的 DATA 帧也能跳过。一个头部块最多 64 KiB，HPACK 动态表最多 64 KiB；同一个流的第二个头部块（trailers）不重复计数。经 TLS 的 HTTP/2 是加密的，看不到。

经 HTTP/1.1 `Upgrade: h2c` 升级的连接，客户端只在服务端回 101 之后才发 HTTP/2 前言。所以升级请求之后，客户端接下来的字节以前言开头就换成 HTTP/2 解析，升级请求本身的 Host 按一次请求计；服务端拒绝升级时客户端继续发 HTTP/1.1 请求，照常计数。其他 `Upgrade`（如 WebSocket）之后停止解析。

## DNS 与 SSH

DNS 流（含 TCP 上的 DNS、mDNS、LLMNR）显示最近的查询名和类型、它的应答码，以及查询不止一次时的次数和失败的应答数，例如 `AAAA api.example.test NXDOMAIN failed=1`；TCP 上的 DNS 只解析一个报文里完整的消息。应答按事务 ID 对上最近 4 个未应答的查询，用两者的抓包时间算出往返时间，显示最近一次和最小值，例如 `rtt=50.1ms min=48.9ms`；它是采集点到服务端的往返，采集点之前的排队（比如本机出口上的 netem）不在其中。SSH 只取两端的版本标识行，限可打印 ASCII、255 字节。

## socket 层前缀读取

本机 dae 这类透明代理会让出站报文绕开被选接口，`br0` 上只看到回包；TSO/GRO 会把 ClientHello 并进超过复制上限的大段；Chrome 131 起的 ClientHello 有 1.7–1.8 KB，常跨两个 TCP 段。这些情况里报文侧都可能拿不到完整的客户端字节，但应用写进 socket 的字节是完整、有序的。这个思路来自 [qtap](https://github.com/qpoint-io/qtap) 在系统调用层读首次写入的做法，socktrail 挂在 `tcp_sendmsg`/`tcp_recvmsg` 上，直接拿到 `struct sock` 和五元组，不必跟踪 fd，也覆盖 write、send、sendmsg、writev 等所有写入路径；qtap 读 TLS 库明文的部分没有采用。

socket 层前缀读取只覆盖当前网络命名空间内本机进程的 socket：TCP 每个 socket 每个方向最多前 16 KiB，以 4 KiB 为块经 ring buffer 送到用户态，每块带 socket cookie、流内偏移、进程和五元组；UDP 只读发出的 QUIC 长包头数据报，同样以每个 socket 16 KiB 为限，其他数据报不占预算。数据在内存中解析后丢弃，不写盘。TLS 和 QUIC 在这一层除握手外都是密文，所以它看到的内容和线上报文一致，不涉及 TLS 明文。

TCP 两个方向都会解析，只有读成客户端的 ClientHello、请求头或代理握手的方向才可能用来命名。连接的发起方已知时，还要求字节确实来自客户端：客户端 socket 发出的，或服务端 socket 收到的。服务端的回复也可能读起来像请求，例如 SQL Server 的 TDS pre-login 应答以 `04 01` 开头，结构上就是一个 SOCKS4 CONNECT 请求，此前让 sqlcmd 的连接显示成 `PROXY 0.0.1.0`。它要挂到至少一个采集接口上观察到的连接；完全没经过任何所选接口的连接不单独列出，连接的报文晚到时证据最多保留 10 秒等待。

未 connect 的 UDP socket 没有固定的本地地址，按本地端口和对端地址找连接。HTTP 请求数仍以报文为准，只有报文没给出名字时才用 socket 层的字节。转发、桥接给虚拟机或其他网络命名空间的流量不经过本机 socket，只能靠报文。

## DNS 提示缓存

DNS 提示取 UDP 53 应答中提问名对应的 A/AAAA 地址（包括 CNAME 之后的地址），每个 IP 最多保留 4 个名字、10 分钟。从握手开始观察到的连接只用建立前的应答；抓包前建立的连接也接受之后的重新解析。它不受 `--port` 过滤，看不到 DoH/DoT 等加密 DNS。

## 为什么以握手为主

“域名”有三层：连接级的 SNI，请求级的 Host 或 `:authority`（HTTP/2 复用时一条连接服务多个域名），以及解析级的“哪个域名解析到这个 IP”。请求级只能靠在进程里读明文，需要逐个 TLS 库挂钩，还会打破不读正文的约定；本机常用的 HTTPS 客户端又多是静态链接的 TLS（BoringSSL、rustls、Go）或 GnuTLS，挂钩覆盖差。反过来，它们的 ClientHello 在线上都看得到。所以覆盖面集中在握手：新连接都能取到 SNI，其余缺口用标明来源的补充证据填补，找不到时按原因分组。

## 参考实现

- [Inspektor Gadget trace_sni](https://github.com/inspektor-gadget/inspektor-gadget/blob/main/gadgets/trace_sni/program.bpf.c)：在 socket filter 里按长度字段遍历 ClientHello，比搜索字节模式可靠，但只看单个报文、只支持 IPv4。socktrail 在用户态完整重组，不把解析放进内核。
- [Suricata](https://github.com/OISF/suricata/blob/main/src/app-layer-ssl.c) 与 [Zeek](https://docs.zeek.org/en/current/scripts/base/protocols/ssl/main.zeek.html)：SNI、客户端提供的 ALPN、服务端选定的协议分开记录，重复 SNI 扩展算异常，取到握手证据后可以不再解析加密负载。socktrail 同样先重组、再按 record、handshake、extension 的长度解析，重复 SNI 扩展或同一列表里重复的 `host_name` 算解析错误。
- [gopacket reassembly](https://github.com/google/gopacket/blob/master/reassembly/tcpassembly.go)：TCP 重组与协议解析分层，重组按序号和缓冲上限交付有序字节。
- [ptcpdump](https://github.com/mozillazg/ptcpdump)：用 socket cookie 把报文关联到进程，在 `nf_nat_manip_pkt` 记录 NAT 前后的元组。socktrail 的 socket 层读取按 cookie 区分 socket；NAT 只需要每条连接查一次，改为向 conntrack 按元组查询。
- [packetd](https://github.com/packetd/packetd)、[pktstat-bpf](https://github.com/dkorunic/pktstat-bpf)：比较了 AF_PACKET、cgroup skb、TC、XDP 的吞吐和进程可见性。TC/XDP 在内核里聚合能减少复制，但要重写字节统计和 PCAPNG 录制；socktrail 用 TPACKET_V3 共享环并按解析所需长度截断。

## 仍然拿不到名字的情况

- 抓包前建立、之后没有重新解析域名的连接：没有被动来源。socket 层读取只能看到启动后的字节；内核 socket 表能认出其中的本机连接，覆盖率行把它们单独列出。
- 没经过任何所选接口的连接：socket 层证据要挂到已观测的连接上。转发、桥接给虚拟机或其他网络命名空间的流量不经过本机 socket，只能靠报文。
- 真实 ECH，尤其同时用 DoH 时：只能看到服务商的公共名。
- 逐请求的域名和 HTTPS 请求数（经 TLS 的 HTTP/2、HTTP/3）：只能靠读明文。明文 HTTP/2 已按请求计数。
- 客户端没发 SNI、服务端用 TLS 1.3：证书在加密的握手消息里，只有 DNS 提示可用。
- OpenSSL 探针不覆盖 Go TLS、静态链接的 TLS 库、其他 TLS 库以及不经已挂调用路径的握手。

与 [RustNet](https://github.com/domcyrus/rustnet) 的功能差异见 [协议与功能对照](rustnet-comparison.md)。
