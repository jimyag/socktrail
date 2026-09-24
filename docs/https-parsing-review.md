# HTTPS 域名解析实现对照

状态：2026-09-23 源码对照，同日补充多来源域名证据。这里的“域名”主要指被观察到的 TLS ClientHello SNI；它是客户端声明的目标提示，不等于解密后的 HTTP Host，也不能证明握手成功。代理目标、OpenSSL 进程 SNI 与 DNS 提示作为单独来源记录，见 [HTTPS 域名覆盖](https-domain-coverage-plan.md)。

## 开源实现怎样处理

| 实现 | 观察到的做法 | 对 socktrail 的影响 |
| --- | --- | --- |
| [Inspektor Gadget trace_sni](https://github.com/inspektor-gadget/inspektor-gadget/blob/main/gadgets/trace_sni/program.bpf.c) | socket filter 在单个报文内按长度字段遍历 session id、cipher suites、扩展，最多 20 个扩展。 | 按结构解析比搜索字节模式可靠，但仍不跨段、只支持 IPv4；socktrail 保持用户态完整重组。 |
| [qtap](https://github.com/qpoint-io/qtap) | 在系统调用层读取每个连接的首次写入并识别协议，ClientHello 一次拿全，带进程上下文。 | socktrail 在 `tcp_sendmsg`/`tcp_recvmsg` 读每个 socket 每个方向前 16 KiB，报文拿不到名字时用这份字节；不采用它读 TLS 库明文的部分。 |
| [Suricata TLS 解析器](https://github.com/OISF/suricata/blob/main/src/app-layer-ssl.c)与 [SNI 检测](https://github.com/OISF/suricata/blob/main/src/detect-tls-sni.c) | TLS 有 ClientHello 完成状态，SNI 是该状态之后的独立字段；重复 SNI 扩展会产生异常事件。其 [TLS 输出](https://docs.suricata.io/en/latest/output/eve/eve-json-format.html)区分 SNI、客户端提供的 ALPN、服务端 ALPN、证书和指纹。 | 先重组，再按 record、handshake、extension 长度解析；对歧义和解析失败保留状态。客户端 ALPN 列表不能写成服务端协商结果。 |
| [Zeek SSL/TLS 分析](https://docs.zeek.org/en/current/scripts/base/protocols/ssl/main.zeek.html) | `server_name`、客户端 ALPN、服务端选择的协议及 `established` 分开记录；可在识别加密流量后停止继续解析。 | 连接流量仍可继续计数，但得到 ClientHello 证据后无须保留后续加密负载。只见 ClientHello 不能声称 TLS 会话建立成功。 |
| [Rusticata tls-parser](https://github.com/rusticata/tls-parser) 与 [gopacket reassembly](https://github.com/google/gopacket/blob/master/reassembly/tcpassembly.go) | TLS 记录解析器本身不负责 TCP 分片；重组组件按连接、序列号和缓冲上限交付有序字节。 | socktrail 继续保留有界 TCP 重组与 TLS 解析两层，不把单包 TLS 解码当作完整连接解析。 |

## 当前实现与这次修正

[`internal/domain/stream.go`](../internal/domain/stream.go)按 TCP 序列号处理跨包、乱序和重传，限制待重组分片与字节数；[`internal/domain/tls.go`](../internal/domain/tls.go)按 TLS record、handshake 和 extension 长度读取 ClientHello，解析 SNI 与客户端**提供**的 ALPN，完成后释放握手缓冲。两者只接收客户端方向的负载；连接 IP 字节仍由抓包计数，与解析结果相互独立。

对照 [TLS 1.2 规范](https://www.rfc-editor.org/rfc/rfc5246.html)及 Suricata 的异常处理后，此前修正了两处边界：无 extensions 的合法 ClientHello 正常结束，现归入 `no SNI`；重复 SNI 扩展或同一 SNI 列表中重复 `host_name` 报解析错误，归入 `parse failed`。测试还覆盖 SNI 位于 400 B padding 之后、ClientHello 跨 TLS record。真实 `curl` HTTPS 握手和 `openssl s_client` 有/无 SNI 对照通过，记录见[验证记录](validation.md)。

2026-09-23 的多来源改动修正了解析器外围的问题，ClientHello 解析本身未变；本机 Go、curl、openssl、node、python 的真实握手仍全部正确解析：

- 解析完成即停止：客户端 ClientHello 解析完成后，该方向不再重组。此前 HTTPS 上传会继续进入重组，之后任何一次丢包、10 秒缺口或超过 16 KiB 的 TSO/GRO 段都会给已拿到 SNI 的连接记上解析错误，并让顶部常驻 `INCOMPLETE`。
- 截断段按长度跳过：抓包层给出 IP 头声明的 TCP 负载长度。HTTP 请求体中没复制到的字节按剩余长度扣减，后续请求照常计数；只有截断落在请求头或 ClientHello 里才判失败。`lo` 的 MTU 为 65536 且开着 TSO，这类段很常见。
- 代理隧道：HTTP CONNECT 的 authority 和 SOCKS5 请求中的地址记为 `Proxy`，随后对隧道里的字节重新判断协议，ClientHello 或明文请求照常解析。RFC 1929 用户名/密码只按长度跳过，不保存。407 后同一连接重发 CONNECT 也能继续。2026-09-24 起同样处理 SOCKS4/4a（4a 带域名）请求；负载均衡器加在连接开头的 PROXY protocol v1（文本）和 v2（二进制签名）头被跳过，原始客户端地址放进详情，之后的 ClientHello 或请求照常解析。
- 没看到 SYN 也能解析：没看到 SYN 的 TCP 流，如果某个客户端报文以 ClientHello 记录或 HTTP 请求行开头，就从这里开始解析。只见 TLS 应用数据记录的连接标为 `handshake not captured`，不再从域名页消失。
- Host 字节校验：HTTP Host 与 CONNECT authority 除 IP 字面量外必须是可打印 ASCII，防止控制序列进入终端。
- socket 层读取：同一个解析器也处理 [`internal/sockstream`](../internal/sockstream/sockstream.bpf.c) 在 socket 层读到的客户端字节，不受接口选择、TSO/GRO 与透明代理改路影响。本机只抓 `br0`（dae 拦截的连接在这里只有回包）时，curl、git、node、python、Go 以及 uTLS 生成的 Chrome 133/131 握手都拿到了 SNI；上一版只有两条靠 OpenSSL 探针命名。

## ECH 的分组方式

[RFC 9849](https://www.rfc-editor.org/rfc/rfc9849.html) 的外层 ClientHello 带公共名称，真实 SNI 在加密的内层；同一扩展也用于 GREASE，旁路无法区分两者。[Chrome 自 117 起默认启用 ECH 并实现 GREASE](https://groups.google.com/a/chromium.org/g/blink-dev/c/CmlXjQeNWDI/m/hx-_4lNBAQAJ)，[Firefox 启用 ECH 后对每个 TLS 和 QUIC 连接发送 GREASE ECH](https://wiki.mozilla.org/Security/Encrypted_Client_Hello)。因此“有 ECH 扩展”在浏览器流量里几乎总成立，而其中绝大多数连接的外层 SNI 就是真实域名。此前把带扩展的连接一律归入未知，会让浏览器和 Electron 应用的 HTTPS 几乎全部失去域名。

现在按线上 SNI 分组，标签加 `[ECH]`，详情说明它可能是服务商的公共名。真实 ECH 时，这个名字如实反映线上可见内容，例如服务商的 ECH 公共名。OpenSSL 进程探针若看到内层 SNI，它优先于带 ECH 标记的线上名，也不计为冲突。

## 仍需区分的 HTTPS 情况

- **真实 ECH**：内层 SNI 受加密保护，旁路只能看到公共名；DNS 未加密时，DNS 提示可能给出客户端实际解析的名字。
- **ALPN 与握手结果**：当前只读取客户端提出的 ALPN 列表。[TLS 1.3](https://www.rfc-editor.org/rfc/rfc8446.html) 的服务端选择结果在加密握手消息中；不能把列表中的 `h2` 写成已协商 HTTP/2，也不能仅凭 SNI 标记请求数。若要展示握手是否成功或 TLS 1.2 的服务端选择，需新增服务端方向的握手状态机，并对 TLS 1.3 可见性单独标注。
- **QUIC/HTTP/3**：[RFC 9001](https://www.rfc-editor.org/rfc/rfc9001.html)和 [RFC 9369](https://www.rfc-editor.org/rfc/rfc9369.html)的 v1/v2 Initial 密钥可由公开的连接 ID 和版本 salt 推导。当前已独立解保护并有界重组 CRYPTO 中的 ClientHello；官方加密向量、本机 quic-go 实际握手和从独立网络命名空间发来的 aioquic Initial 均能识别 SNI。报文没抓到时，本机 UDP socket 发出的 Initial 在 socket 层读取。HTTP/3 `:authority` 位于加密应用数据内；SNI 不能生成请求数。未知版本和漏抓 Initial 仍显示未命名。QUIC 标签要求长包头带已知版本号：此前任意“长包头形状”的数据报都算 QUIC，ZeroTier 和部分 DNS 查询因此被误标，现已排除。
- **请求级域名**：HTTP/2 连接复用时，一条 TLS 连接可以服务多个域名；逐请求的 Host/`:authority` 和 HTTPS 请求数只能靠读取进程内明文取得。本机常用客户端的 TLS 栈包括静态 BoringSSL、rustls、GnuTLS 和去掉符号的 Go 程序，挂钩覆盖差，而且读明文会改变“不读取请求正文”的约定，因此没有采用。连接详情列出同一 IP 最近解析过的所有域名，用来提示可能存在的复用。

增加服务端握手字段时，继续把“客户端提供”“服务端选择”“实际 HTTP 请求”分开显示。
