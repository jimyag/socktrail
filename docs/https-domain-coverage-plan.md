# HTTPS 域名覆盖与当前实现

状态：2026-09-23 已完成 QUIC v1/v2 Initial 解析、系统 OpenSSL SNI 进程探针、握手侧多来源域名证据，以及 socket 层客户端字节读取的本机原型；2026-09-24 增加 SOCKS4/4a 与 PROXY protocol、UDP socket 的 QUIC Initial 读取、QUIC 版本号校验，并把启动前已有的连接从覆盖率里单独列出；同日又增加明文 HTTP/2 `:authority`、TLS 服务端握手（版本、ALPN、无 SNI 时的证书名、alert）和基于 conntrack 的 NAT 映射。默认启用 OpenSSL 探针，`--openssl-probe=false` 可关闭。RFC 向量、本机真实 QUIC 握手、从独立网络命名空间发来的真实 QUIC Initial 和 `lo` 上的受控 HTTPS/代理流量已通过（见[验证记录](validation.md)）；其他内核、TLS 库与真实 ECH 尚未验收。

目标：给本机发起或接收的每条 HTTPS/TLS 连接尽量找到目标域名，并标明来源；找不到时按原因分组，而不是静默丢失。域名页的连接字节仍互斥计数，每条连接只进入一个分组。

## 为什么以握手侧为主

“域名”有三层：连接级的 SNI、请求级的 Host/`:authority`（HTTP/2 复用时一条连接服务多个域名），以及解析级的“哪个域名解析到这个 IP”。请求级只能靠进程内读明文，需要逐个 TLS 库挂钩，HTTP/2 还要按连接维护 HPACK 状态。本机常用的 HTTPS 客户端分别使用：

- claude：静态编译的 TLS，进程里没有加载 libssl；
- codex：Rust musl 静态二进制；
- git-remote-https、apt：GnuTLS；
- docker、tailscaled：带符号的 Go 程序；
- dae、containerd、gh：去掉符号的 Go 程序；
- node：自带 OpenSSL。

这些客户端大多无法稳定挂钩，而且读明文会改变“不读取请求正文”的约定。反过来，它们的 ClientHello 在线上都可见。所以覆盖面集中在握手侧：新连接都能取到 SNI，其余缺口用有来源标注的补充证据填补。

## 来源与优先级

1. **客户端字节**：明文 HTTP/1.1 Host、TCP ClientHello SNI、QUIC v1/v2 Initial SNI，以及 HTTP CONNECT、SOCKS4/4a、SOCKS5 请求中的代理目标。隧道里的 ClientHello 继续按 TLS 解析；负载均衡器在连接开头加的 PROXY protocol v1/v2 头会被跳过，其中的原始客户端地址放进详情，之后的字节照常解析。没看到 SYN 时，从以 ClientHello 或请求行开头的报文开始解析。带 ECH 扩展的 ClientHello 按线上 SNI 分组并标 `[ECH]`，原因见 [HTTPS 解析对照](https-parsing-review.md)。这些字节有两份来源：所选接口的报文，以及 socket 层读取的同一份字节（见下文“socket 层读取”）。报文给出名字时用报文，否则用 socket 层那份。明文 HTTP/2（h2c）从连接前言开始解码 HEADERS，每个请求的 `:authority` 像 HTTP/1.1 的 Host 一样计数。客户端没发 SNI 时，服务端的 TLS 1.2 及以下证书是明文，叶子证书的名字也算这一类证据，行名标 `[cert]`：按 IP 连接的内部服务多属这种情况。TLS 1.3 的证书加密，这类连接仍是 `no SNI`，详情写明原因。
2. **OpenSSL 进程 SNI**：探针观察 `SSL_ctrl` 设置的客户端 SNI 和 `SSL_get_servername` 返回的服务端 SNI，经 `SSL_set_fd`、`BIO_new_socket` 或 `SSL_connect` 期间的同线程 `tcp_sendmsg` 关联到内核五元组后才发出事件。它补充报文未知的连接；线上 ClientHello 带 ECH 时，它优先于线上名。
3. **DNS 提示**：从所有采集接口的 UDP 53 应答中取提问名对应的 A/AAAA 地址，维护跨接口共享的“IP → 最近解析到它的域名”（每个 IP 最多 4 个名字，保留 10 分钟）。它只给没有前两类证据的 TCP 连接和 QUIC/未识别 UDP 流使用，标为 `DNS`，不当作 Host/SNI。从握手开始观察到的连接只取建立前的应答；抓包前建立的连接也接受之后的重新解析。
4. **按原因分组的未命名连接**：`handshake not captured`（只见 TLS 应用数据）、`no SNI`、`parse failed`（详情给出原因）、`unknown`（握手尚未完成）。

域名页第二行给出启动后建立的 TLS/QUIC 连接 IP 字节中已命名的比例、其中来自 DNS 提示的比例和各未命名原因的比例，作为覆盖率的可量化验收口径。启动时内核 socket 表里已有的连接，握手早于抓包，任何被动来源都拿不到，它们的字节在同一行单独列出，不计入比例。连接详情的 `EVIDENCE` 行列出代理目标、ECH、客户端提供的 ALPN、服务端选定的版本和 ALPN、证书名、解析错误、NAT 改写，以及该连接对端 IP 最近解析过的所有域名，用来提示 HTTP/2 连接复用。握手失败时，失败一方的 alert（如 `client alert: unknown certificate authority`、`server alert: protocol version`）直接附在连接名后。

## socket 层读取

本机 dae 这类透明代理会让出站报文绕开被选接口，`br0` 上只看到回包；TSO/GRO 会把 ClientHello 并进超过复制上限的大段；Chrome 131 起的 ClientHello 有 1.7–1.8 KB，常跨两个 TCP 段。这三种情况里，报文侧都可能拿不到完整的客户端字节，但应用写进 socket 的字节是完整、有序的。

[`internal/sockstream`](../internal/sockstream/sockstream.bpf.c) 在 `tcp_sendmsg`、`tcp_recvmsg` 上挂 fentry/fexit：fentry 记下调用方缓冲区的位置（单个用户缓冲区或 iovec 数组），fexit 按实际收发的字节数从该缓冲区复制。每个 socket 每个方向最多复制前 16 KiB，以 4 KiB 为块经 ring buffer 送到用户态。每块带 socket cookie、流内偏移、进程和五元组，用户态按偏移交给现有的 ClientHello/HTTP/代理解析器。Linux 5.12 之前 tracing 程序不能取 cookie，改用 socket 的内核地址，socket 销毁时清掉该地址的预算，用户态见到偏移 0 就重新开始解析，避免地址被新 socket 复用后接着旧状态。超过预算的 socket 每次调用只做一次 map 查询。只有读成客户端握手、请求头或代理握手的方向才会挂到同五元组的连接上。连接的报文晚到时，证据最多保留 10 秒等待。

UDP 用同一套程序挂在 `udp_sendmsg`、`udpv6_sendmsg` 上，只复制首字节是 QUIC 长包头的数据报，其他数据报不占预算；每个 socket 仍以 16 KiB 为限，足够放下客户端 Initial。未 connect 的 socket 的目的地址取自 `sendto` 传入的地址，本地地址要到路由时才确定，所以用户态按本地端口和对端地址找连接；已 connect 的 socket 按完整五元组匹配。每个对端单独解析 Initial，解出的 ClientHello 挂到该 UDP 流上，来源标 `(socket)`。

## 借鉴与取舍

- **[Inspektor Gadget trace_sni](https://github.com/inspektor-gadget/inspektor-gadget/blob/main/gadgets/trace_sni/program.bpf.c)**
  - 做法：在 socket filter 里按长度字段遍历 ClientHello，比搜索字节模式可靠。
  - 局限：只看单个报文、只支持 IPv4、最多 20 个扩展，SNI 在第二个段时同样拿不到。socktrail 在用户态做完整重组，不把解析放进内核。
- **[qtap](https://github.com/qpoint-io/qtap)**
  - 做法：在系统调用层读取连接的首次写入，ClientHello 一次拿全，并带进程上下文。socktrail 采用了这个思路，但挂在 `tcp_sendmsg`/`tcp_recvmsg` 上：直接拿到 `struct sock` 和五元组，不必跟踪 fd，也覆盖 write、send、sendmsg、writev 等所有写入路径。
  - 未采用：qtap 读 TLS 库明文的部分，不符合“不读明文”的约定。
- **[ptcpdump](https://github.com/mozillazg/ptcpdump)**
  - 做法：用 socket cookie 把报文关联到进程；在 `nf_nat_manip_pkt` 记录 conntrack 改写前后的五元组，能把 NAT 后的报文还原到原连接。
  - 状态：socket 层读取按 cookie 区分 socket。NAT 映射已实现，但没有挂 `nf_nat_manip_pkt`：那个 hook 在每个被改写的报文上触发，socktrail 只需要每条连接一次，所以改为新流出现时向 conntrack 按元组查询一次。
- **[packetd](https://github.com/packetd/packetd)、[pktstat-bpf](https://github.com/dkorunic/pktstat-bpf)**
  - 二者比较了 AF_PACKET、cgroup skb、TC、XDP 的吞吐和进程可见性。TC/XDP 在内核里聚合计数能减少复制，但需要重写字节统计与 PCAPNG 录制，暂未改动；AF_PACKET 改用 TPACKET_V3 共享环并按解析所需长度截断，逐包的系统调用和复制已经去掉。

## 实现要点

QUIC Initial 用 Go 标准库的 AES-GCM、SHA-256、HKDF 解保护，复用 ClientHello 解析器；每个 UDP 流的 CRYPTO 缓冲不超过约 64 KiB，未知版本保持未命名，不解密 1-RTT 数据。TCP 方向的解析在 ClientHello 完成后停止，之后的丢包和超过 16 KiB 保留上限的 TSO/GRO 段不计为解析失败；HTTP 请求体中没复制到的字节按长度跳过。DNS 应答的复制上限为 4 KiB。

## 仍然拿不到的情况

- 抓包前建立、之后没有重新解析域名的连接：没有被动来源。系统解析器缓存可以补这一类，但依赖 systemd-resolved，本机未启用。socket 层读取只能看到启动后的字节，这类连接开头的握手同样拿不到。内核 socket 表能认出其中的本机连接，覆盖率行把它们单独列出，进程和方向也由它补上，但名字仍然没有。
- 没经过任何所选接口的连接：socket 层证据需要挂到一条已观测的连接上，这类连接目前不单独列出。转发、桥接给虚拟机或其他网络命名空间的流量不经过本机 socket，只能靠报文。
- 真实 ECH 与 DoH 同时使用：只能看到服务商公共名。
- 逐请求域名与 HTTPS 请求数（经 TLS 的 HTTP/2 复用、HTTP/3）：只能靠读明文。明文 HTTP/2 已按请求计数。
- 客户端没发 SNI、服务端用 TLS 1.3：证书在加密的握手消息里，只有 DNS 提示可用。
- OpenSSL 探针不覆盖 Go TLS、静态链接 TLS 库、其他 TLS 库及不经已挂调用路径的握手。
