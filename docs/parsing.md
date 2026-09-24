# 解析原理

从 [中文首页](../README.zh-CN.md) 进入。报文先由 [packet.go](../internal/capture/packet.go) 解出网络和传输层；应用协议提示来自 [appproto/detect.go](../internal/appproto/detect.go)，域名证据由 [domain/stream.go](../internal/domain/stream.go) 及各协议解析器维护。域名标签是可见证据，不等于解密后的请求内容。

## 协议识别

连接详情有 `APP`、`SYN RTT`、`RETX` 列。

`APP` 可识别 HTTP、HTTP/2（h2c；请求带 gRPC 内容类型时标 gRPC）、TLS、DNS（含 TCP 上的 DNS）、SSH、FTP、SMTP、Redis、PostgreSQL、MySQL、MongoDB、SQL Server、Oracle TNS、Cassandra、Kafka、AMQP、NATS、ZooKeeper、Memcached、LDAP、Kerberos、NFS 及其 RPC 辅助服务（portmapper、mount、lock）、SMB、RDP、VNC、Telnet、SIP、RTSP、QUIC、MQTT、BitTorrent、WireGuard、OpenVPN、IKE、IPsec ESP（NAT 穿越）、VXLAN、GENEVE、STUN、NTP、mDNS、LLMNR、DHCP、DHCPv6、SNMP、SSDP、Syslog、TFTP、RADIUS、NetBIOS NS。

Kafka、NATS、ZooKeeper、Memcached、SQL Server、Oracle TNS、LDAP、Kerberos、Cassandra 的首包特征不够独特，只在默认端口上按报文结构确认，换了端口不猜；AMQP 和 NFS/RPC 按协议头或 RPC 调用结构识别，不限端口。

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

## 服务端 TLS 握手

服务端握手解析见 [tls_server.go](../internal/domain/tls_server.go)。

TLS 服务端回复只在客户端 ClientHello 解析成功后读，从服务端第一个以 TLS 记录开头的报文开始（CONNECT 或 SOCKS 的应答因此被跳过），只接受按序到达的报文，缺段就停。读到 ServerHello 即取版本和 ALPN；TLS 1.3 或客户端带了 SNI 时到此为止，否则继续读到 Certificate 消息里的叶子证书为止，不等证书链其余部分。证书只按 DER 结构取名字，不校验，最多 8 个名字；缓冲最多 64 KiB，读完即释放。alert 按报文判断：一个报文恰好是一条 7 字节的明文 alert 记录才算，所以只看得到握手失败时的 alert；握手后的 alert 都是加密的。

## 明文 HTTP/2

帧和 HPACK 解析见 [http2.go](../internal/domain/http2.go)。

明文 HTTP/2 从客户端的连接前言开始解析，只读 HEADERS 和 CONTINUATION 帧，其余帧按长度跳过，没抓全的 DATA 帧也能跳过。一个头部块最多 64 KiB，HPACK 动态表最多 64 KiB；同一个流的第二个头部块（trailers）不重复计数。经 TLS 的 HTTP/2 是加密的，看不到。

## DNS 与 SSH

DNS 流（含 TCP 上的 DNS、mDNS、LLMNR）显示最近的查询名和类型、它的应答码，以及查询不止一次时的次数和失败的应答数，例如 `AAAA api.example.test NXDOMAIN failed=1`；TCP 上的 DNS 只解析一个报文里完整的消息。SSH 只取两端的版本标识行，限可打印 ASCII、255 字节。

## socket 层前缀读取

socket 层前缀读取只覆盖当前网络命名空间内本机进程的 socket：TCP 每个 socket 每个方向最多前 16 KiB；UDP 只读发出的 QUIC 长包头数据报，同样以每个 socket 16 KiB 为限，其他数据报不占预算。数据在内存中解析后丢弃，不写盘。TLS 和 QUIC 在这一层除握手外都是密文，所以它看到的内容和线上报文一致，不涉及 TLS 明文。TCP 两个方向都会解析，只有读成客户端的 ClientHello、请求头或代理握手的方向才会用来命名，服务端回复不会。它要挂到至少一个采集接口上观察到的连接；完全没经过任何所选接口的连接不单独列出。

未 connect 的 UDP socket 没有固定的本地地址，按本地端口和对端地址找连接。HTTP 请求数仍以报文为准，只有报文没给出名字时才用 socket 层的字节。转发、桥接给虚拟机或其他网络命名空间的流量不经过本机 socket，只能靠报文。

## DNS 提示缓存

DNS 提示取 UDP 53 应答中提问名对应的 A/AAAA 地址（包括 CNAME 之后的地址），每个 IP 最多保留 4 个名字、10 分钟。从握手开始观察到的连接只用建立前的应答；抓包前建立的连接也接受之后的重新解析。它不受 `--port` 过滤，看不到 DoH/DoT 等加密 DNS。

相关实现对照：[HTTPS 域名覆盖](https-domain-coverage-plan.md) · [HTTPS 解析对照](https-parsing-review.md) · [协议与功能对照](rustnet-comparison.md)。
