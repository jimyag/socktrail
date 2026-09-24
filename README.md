# socktrail

`socktrail` 是 Linux 终端实时流量观察程序。它用 AF_PACKET 分接口统计以太网和 tun 类接口（WireGuard、Tailscale）上的报文：IPv4/IPv6 的 TCP、UDP、ICMP 及其他 IP 协议按流统计，ARP 和其他非 IP 帧按 EtherType 计入，IP 分片归入首片所在的流。ICMP 错误报文会解出所引用的原始报文，标到对应的 TCP/UDP 流上。eBPF 探针关联 TCP/UDP 的本机 PID 与 socket I/O；启动前已建立、或建立早于探针挂载的连接，由内核 socket 表（ss/netstat 的数据源）补上进程和方向。程序从明文 HTTP/1.1 请求头、TCP TLS ClientHello、QUIC v1/v2 客户端 Initial 提取可见的 Host/SNI，识别 HTTP CONNECT、SOCKS4/4a、SOCKS5 代理请求的目标并继续解析隧道里的 ClientHello，跳过负载均衡器加的 PROXY protocol 头。同样的客户端字节还会在 socket 层读取：eBPF 程序在 `tcp_sendmsg`/`tcp_recvmsg` 处读每个本机 TCP socket 每个方向的前 16 KiB，在 `udp_sendmsg`/`udpv6_sendmsg` 处读 UDP socket 发出的 QUIC 长包头数据报；报文没经过所选接口、被 TSO/GRO 拆分或被透明代理改走时，仍能拿到完整的 ClientHello 或请求头。默认还尝试对系统 OpenSSL 安装进程探针，补充可关联到 socket 的 SNI；没有这些证据的连接可用抓到的 DNS 应答作为单独标注的名称提示。所有域名证据在同一页；日常域名解析不展示逐条 HTTP 请求，也不存储请求正文或 TLS 密钥。用户主动录制 PCAPNG 时会保存原始报文。

目前是原型：本机 Linux 6.8 上做过实机验证；5.10 到 7.0 的几个发行版内核只在虚拟机里验证过探针加载和回环流量；容器网络和 NAT 场景尚未验收。实测项目和限制见 [验证记录](docs/validation.md)。

## 构建与运行

需要 Linux、Go 1.27。仓库已包含生成的 eBPF 对象；普通构建不需要 clang。`CGO_ENABLED=0` 构建出静态二进制，可以直接拷到其他发行版运行；默认的 cgo 构建依赖构建机的 glibc 版本，例如在 Ubuntu 24.04 上构建的要求 glibc 2.34，在 Debian 11、Ubuntu 20.04 上无法启动。

```sh
CGO_ENABLED=0 go build -o socktrail ./cmd/socktrail
sudo ./socktrail
sudo ./socktrail --interface lo
sudo ./socktrail --interface lo --interface br0
sudo ./socktrail --interface br0,dae0
sudo ./socktrail --openssl-probe=false  # 禁用默认开启的系统 OpenSSL 探针
sudo ./socktrail --socket-sniff=false   # 禁用默认开启的 socket 层前缀读取
```

连接详情有 `APP`、`SYN RTT`、`RETX` 列。`APP` 可识别 HTTP、TLS、DNS、SSH、FTP、SMTP、Redis、PostgreSQL、MySQL、MongoDB、SMB、RDP、VNC、Telnet、SIP、RTSP、QUIC、MQTT、BitTorrent、WireGuard、OpenVPN、IKE、IPsec ESP（NAT 穿越）、VXLAN、GENEVE、STUN、NTP、mDNS、LLMNR、DHCP、DHCPv6、SNMP、SSDP、Syslog、TFTP、RADIUS、NetBIOS NS。`4` 的协议页按“协议 + APP”分组：TCP/UDP 之外还有 ICMPv4/ICMPv6、SCTP、GRE、ESP 等 IP 协议名，以及 ARP、LLDP 等非 IP 帧；未知应用仍保留为 TCP/UDP。多数应用标签采用单包有界特征；QUIC 标签要求长包头带已知版本号，只有成功认证并重组受支持的客户端 Initial 后才会产生 QUIC SNI，且不会生成 HTTP/3 请求数。与 [RustNet 的功能清单](https://github.com/domcyrus/rustnet) 的具体差异见 [协议与功能对照](docs/rustnet-comparison.md)。

在 `conns` 底栏选中一条活动连接，按 `c` 可录制该连接后续 15 秒的原始报文；在 PID 页主表选中 PID 后按 `c`，录制该 PID 后续关联的连接。再按 `c` 提前结束，按 `q` 也会关闭文件。默认写到当前目录的 `socktrail-captures/`，可用 `--capture-dir /path/to/dir` 修改；文件权限为 `0600`，目录新建时为 `0700`，大小最多 64 MiB。状态页 `!` 和退出提示给出 PCAPNG 的绝对路径，可用 `tcpdump -nnr <文件>` 或 Wireshark 打开。文件保存**实际捕获到的原始帧**，超过接收缓冲区的帧可能截断，且明文应用数据可能包含在内；只有按 `c` 后才创建。单连接录制选择一个采集接口，可能漏掉走另一接口的反向报文；PID 录制覆盖所有已选接口，同一报文跨接口可在文件内重复出现。PID 和域名注释来自录制时已关联的证据，晚到事件不会回填。录制期间仍需关注状态页的采集丢包。

默认进入整机 PID 页，显示当前网络命名空间的进程 socket 收发量与跨接口识别的连接、Host/SNI。顶部的 `a OVERVIEW` 表示按 `a` 回到多网卡合并视图；`OVERVIEW` 是界面范围，和 HTTP `Host` 域名无关。按 `1`—`4` 切换 PID、来源 IP、目标 IP、协议，按 `d` 看域名（HTTP Host、TCP/QUIC SNI、代理目标、OpenSSL 进程 SNI、DNS 提示）。`0` 打开网卡诊断总览；选中网卡按 `Enter` 进入该网卡详情。需要排查采集路径时可按 `i` 逐张切换。

不指定 `--interface` 时，程序自动选择当前网络命名空间内最多 8 个处于 UP 且 RUNNING 状态的宿主接口，包括 loopback、物理接口和隧道接口；跳过名称以 `veth`、`br-`、`docker`、`vnet`、`ovs-` 开头的常见容器/虚拟机子接口。超过 8 个候选时会报错，要求显式选择，不会悄悄漏抓。自动选择只决定从哪里采集报文，不要求在主页面选网卡。相同五元组和 TCP 代次的跨接口观测在整机页合为一条连接，只取一个采集点的 IP 字节，优先保留已识别的 Host/SNI。NAT 改写五元组时仍可能留下两个观测流，所以整机页的 IP 字节是观测值，不能作为精确整机总量。`--interface` 可重复指定最多 8 个接口，也可用逗号分隔；显式指定可选择自动模式跳过的接口。用 `ip -br link` 查看名称。交互界面按 `1` PID、`2` 来源 IP、`3` 目标 IP、`4` 协议、`d` 域名切换；多接口时按 `i` 切换接口。详情区默认约占半屏，提供 `conns` 和 `process` 两个标签。窗口变宽时表格会展开，变窄时保留完整列数据；用 `←/→` 或 `h/l` 横向滚动当前焦点的表格。可以用鼠标点击顶部视图、主表行、底部标签及连接；点击主表、连接表或进程表的任意列标题按该列排序，再点同一列切换升降序，当前方向标在标题旁。滚轮滚动当前列表，Shift+滚轮或水平滚轮横向滚动鼠标所在表格，拖动横向分隔线调整详情区高度。`Enter` 切换主表和底栏焦点，`Tab` 切换底栏标签，`/` 过滤，`s` 恢复主表总字节/总速率排序并切换两者，`?` 帮助，`!` 状态，`q` 退出。终端需支持 SGR 鼠标报告；退出时程序关闭鼠标报告并恢复终端。

查看单个进程时，按 `1` 进入 PID 页，用 `/` 输入完整 PID 并回车；也可直接点击该 PID 行。默认的 `conns` 底栏列出该 PID 关联的 TCP/UDP 连接，包含来源、目标、协议、状态、Host/SNI 和连接 IP 字节；选中连接后显示**该 PID**在此连接上的 socket RX/TX。按 `Enter` 聚焦底栏后可用方向键逐条查看，也可以用鼠标点击或滚轮切换连接。PageUp/PageDown 会在当前聚焦的主列表或连接列表中翻页。切到 `process` 标签可看进程启动时间、父 PID、可执行文件、工作目录、命令行和环境变量；多个进程用方向键或点击列表选择，环境变量用 PageUp/PageDown 或鼠标滚轮滚动。启动信息来自 `/proc`，只有进程仍在运行且启动标识匹配时才可读取；权限不足或进程退出会显示原因。环境变量显示的是 `/proc/<pid>/environ` 提供的启动时快照，可能包含凭据，仅显示在终端，不写入日志。PID 汇总可能包含未匹配到已采集连接的 socket I/O，因此连接观测 IP 字节不能直接与 PID socket 字节相加或要求相等。

交互界面把进程显示为 `PID 进程名`，例如 `1224 tailscaled`。同一 PID 在观测期内被复用时，历史行会显示 `#1`、`#2` 以便区分；内部仍以 PID 和进程启动标识分别统计。启动日期可在 `process` 详情页查看。非交互式快照保留完整 `PID@启动纳秒`，便于核对原始身份。启动时间与 `/proc/<pid>/stat` 同一基准（开机后经过的时间，挂起期间也计入），并按内核时钟节拍（通常 10 ms）取整，这样 eBPF 事件和 socket 表找到的同一进程归为一行。

域名来源在页面上分开标为 `HTTP`、`TLS`、`QUIC`、`PROXY`、`OPENSSL`、`DNS`。前四者来自客户端发出的字节，取自所选接口的报文，报文没给出名字时取 socket 层的同一份字节（连接详情的 `APP` 来源标 `(socket)`）：`PROXY` 是 HTTP CONNECT、SOCKS4/4a 或 SOCKS5 请求里的目标，隧道里的 ClientHello 或明文请求仍按 `TLS`、`HTTP` 记录，连接详情标出经由的代理。连接开头的 PROXY protocol v1/v2 头（负载均衡器转发到后端时加上）会被跳过，详情列出其中的原始客户端地址。`OPENSSL` 来自默认开启的本机进程探针，只有同时取得进程、socket 和已观测连接的准确对应关系时才进入域名页；它仍是 SNI，不能当成加密 HTTP Host。`DNS` 表示连接对端 IP 最近出现在抓到的 DNS 应答里，只给没有握手证据的连接使用；一个 IP 可以服务多个域名，所以它只是提示。每条连接按报文中的 Host/SNI/代理目标、OpenSSL 进程 SNI、DNS 提示的顺序取名字；带 ECH 扩展的 ClientHello 例外，进程 SNI 优先。没有名字的连接按原因分组：`handshake not captured`（握手早于抓包，或没经过所选接口）、`no SNI`、`parse failed`（详情给出原因）、`unknown`（握手尚未完成）。域名页第二行显示启动后建立的 TLS/QUIC 连接流量中已命名的比例、其中来自 DNS 提示的比例和各类未命名原因；启动时内核 socket 表里已有的连接握手早于抓包，它们的流量在同一行单独列出，不计入比例。连接详情的 `EVIDENCE` 行列出 ECH、客户端提供的 ALPN、代理目标、解析错误、连接是否早于抓包，以及该 IP 最近解析过的所有域名。整机页合并同一连接的跨接口证据；同一条连接的字节只进入一个域名分组。PID 页的 socket I/O 覆盖整个当前网络命名空间，因此 PID 行有流量并不代表抓到了该连接的握手。本机启用 `dae` 时，实测出站 ClientHello 经过 `dae0`，而 `br0` 对同一连接只看到了回包；自动选接口可补充这种非对称路径。启动前已经完成的握手不能从历史报文补出；进程探针只观察挂载后的库调用。这类连接只有在应用之后重新解析域名、且 DNS 应答以明文经过采集接口时，才能得到 `DNS` 提示。

可以运行限时文本快照，方便留存和对照抓包：

```sh
sudo ./socktrail --interface lo --duration 15s
sudo ./socktrail --duration 15s
sudo ./socktrail --interface lo --duration 15s --port 443
```

运行需 root 或相应的 `CAP_BPF`、`CAP_PERFMON`、`CAP_NET_RAW`、`CAP_NET_ADMIN` 权限，内核要支持 fentry/fexit 和 BPF ring buffer，并带 BTF（`CONFIG_DEBUG_INFO_BTF=y`，存在 `/sys/kernel/btf/vmlinux`）。x86-64 上已在 Debian 11 的 5.10、Ubuntu 的 5.11、5.13、5.15（22.04）、6.8（24.04）、6.17、7.0 内核里实测三个探针都能加载。5.4 及更早的内核没有 fentry；Ubuntu 的 5.8 内核没有 BTF，都无法运行。内核接口的版本差异由程序自己处理：recvmsg 在 5.19 去掉了 nonblock 参数，探针按内核 BTF 里的参数个数加载对应版本；5.12 之前 tracing 程序不能取 socket cookie，socket 层读取改用 socket 的内核地址区分连接。基础 PID/抓包能力缺失时程序报错。OpenSSL 用户态探针默认尝试启用；不可用时继续抓包，但顶部标出 `OPENSSL-PROBE-UNAVAILABLE`，`!` 状态页显示原因与事件数。它目前针对 x86_64 上动态链接的系统 OpenSSL 3/1.1，读取 `SSL_ctrl`/`SSL_get_servername` 暴露的 SNI，并通过 `SSL_set_fd`、`BIO_new_socket` 或 `SSL_connect` 期间的同线程 TCP 发送关联 socket；后者已用 curl 8.5 的自定义 BIO 路径在 OpenSSL 3.0.13 上实测。同线程路径是时间窗口关联：如果握手回调同时向其他 TCP socket 发送数据，可能产生错误关联；跨线程发送则可能漏报。并非每次握手都会产生额外域名：正常捕获到 ClientHello 时，报文解析通常已有相同 SNI。Go TLS、静态链接库、其他 TLS 库、未覆盖的自定义 BIO 调用路径、真实 ECH 的内层名和 HTTP/2/3 加密的请求域名不在当前覆盖范围。可用 `--openssl-probe=false` 关闭。socket 层前缀读取同样默认开启，不可用时顶部标出 `SOCKET-SNIFF-UNAVAILABLE`，`!` 状态页显示读取的数据块、内核丢失和队列丢弃数，可用 `--socket-sniff=false` 关闭。重新生成探针对象才需要 clang、libbpf 头文件及 `go generate ./internal/probe ./internal/tlsprobe ./internal/sockstream`。

## 数据口径

- IP、协议和域名页的字节是 **IP 层报文长度**，包括 IP/传输层头部与观察到的重传，不含链路层头。整机页对相同五元组的同一代连接只取一个采集点的观测字节，不把网卡计数直接相加；NAT、代理或隧道改写地址后仍可能出现多个观测流，所以这些字节不构成精确整机总量。按 `0` 可查看逐网卡原始计数。
- PID 页的 RX/TX 是当前网络命名空间内 TCP/UDP `sendmsg`/`recvmsg` 返回的**应用 socket I/O 字节**，可按执行 I/O 的 PID 加进程启动时间汇总；它不受所选接口或 `--port` 限制，不与 IP 报文字节相加。连接详情只在五元组匹配时显示该 PID 的 socket I/O。PID 连续 5 分钟没有新 I/O 后，明细回收，累计字节保留在过期汇总行。探针丢事件、没有匹配流或走未覆盖的 socket 路径时，PID/连接明细可能不完整；状态页展示丢失和未关联到所选流的字节。启动前已经进入阻塞读调用的进程，其第一次调用返回也可能不被新挂载的 fexit 探针计到。accept 在 Linux 6.8 起改由 `__inet_accept` 观测，这个函数在等到连接之后才调用，所以启动前就阻塞在 `accept()` 里的服务也能拿到第一条连接；更早的内核用 `inet_csk_accept` 的 fexit，会漏掉这一次，仍然存在的连接再由 socket 表补上。
- `lo` 只保留 AF_PACKET 的发送副本，避免本机同一包重复计数。因此它的 RX/TX 是抓包方向，通常显示 TX；不表示本机客户端与服务端各自的收发量。
- TCP 来源/目标按 SYN 或已关联的 connect/accept 确定。没看到建立过程时，发出 ClientHello 或 HTTP 请求行的一端是客户端；本机连接再查内核 socket 表：本地端口上有监听 socket，或本地地址不属于本机（透明代理接受的连接）时为入站，否则为出站。方向不按端口号猜测，都判断不了时详情列出两个带 `?` 的观测端点。UDP 和其他 IP 协议的来源/目标是首次观测报文的端点，ICMP Echo 以首个请求的发送方为发起方。UDP 两端 PID 按本机 socket 所在端点记录，不因服务端回包而交换。TCP 显示 SYN、established、closing、closed、reset 或 midstream 观察状态；同五元组的新 SYN 建立新代次。不能可靠关联的 PID 显示未知或有歧义。
- `SYN RTT` 只对看到本机发出 SYN、收到匹配 SYN-ACK 的 TCP 连接给出一次握手时差样本；入站或中途开始时为 `-`。`RETX` 统计当前采集点观察到的重复 SYN 和已保存序号区间重叠的 TCP 数据段，不是内核的重传计数；每方向最多保留 128 个区间，丢包、乱序、序号回绕或多接口合并会影响判定。两列是网络诊断提示，不与报文字节另行相加。
- HTTP/1.1 `Host` 统计已完整观察的请求数。同一 TCP 连接出现多个 Host 时，连接字节归入 `multiple Hosts` 一组，不按请求拆分。TCP/QUIC/进程侧的 TLS `SNI` 是连接级域名证据，只统计连接与流量，不推断 HTTPS 请求数。入站 Host/SNI 指被访问的服务名，不是客户端来源域名。
- QUIC v1/v2 仅解析成功认证的客户端 Initial 中的 ClientHello；乱序 CRYPTO 片段可有界重组。其他 QUIC 版本、HTTP/3 加密的请求域名与请求数仍未知。无 SNI、漏抓握手、解析失败时保留 IP/PID/字节，按原因显示未命名分组；进程探针若恰好观察到该连接的 SNI，可独立补充。
- ICMP/ICMPv6 的 Echo 按两端地址和 identifier 合成一条流，显示请求/应答数、最近序号和 RTT，ping 洪泛不会把流表撑满；其他消息按两端地址和 type/code 成流，显示类型名，邻居发现和重定向显示目标地址，“需要分片”显示 MTU。错误报文解出所引用原始报文的协议和端点，对应的 TCP/UDP 流在状态列标出错误名，例如 UDP 发往关闭端口后显示 `port-unreachable`。本机进程发出的 Echo 请求，无论走原始 socket 还是 ping socket，都按对端地址和 identifier 关联到发送进程；入站 Echo 由内核应答，内核生成的错误报文也没有进程。
- 没有 IP 头的帧同样计入：ARP 显示请求/应答数和各 IP 宣告的 MAC 地址；PPPoE 会话里的 IPv4/IPv6 解开后按普通流统计；其他帧按 EtherType 分组，802.3 长度帧归为 `802.3 LLC`，这类流没有 IP 端点，显示为 `-`。tun 类接口没有链路层头，按帧里的 IP 报文直接解析；录制 PCAPNG 时给这类帧补一个空以太网头，保持文件只有一种链路类型。
- IPv4/IPv6 分片：后续分片按（源地址、目的地址、协议、分片 ID）归入首片所在的流，包括大包 ping 的 ICMP Echo；首片没抓到时，后续分片单独成流。关联表最多 4096 项，30 秒过期。
- 带 ECH 扩展的 ClientHello 按线上 SNI 分组并标 `[ECH]`。Chrome 117 起、Firefox 启用 ECH 后都会对每个 TLS 和 QUIC 连接发送 GREASE ECH，这时线上 SNI 就是真实域名；真实 ECH 时它是服务商的公共名，内层域名旁路看不到。
- 客户端 ClientHello 解析完成后不再重组该方向的字节，之后的丢包或超过 16 KiB 复制上限的 TSO/GRO 段不再记为解析失败；HTTP 请求体中没复制到的字节按长度跳过，后续请求照常计数。没看到 SYN 时，从以 ClientHello 或 HTTP 请求行开头的报文开始解析。只有记录层 TLS 应用数据、没有握手的连接归入 `handshake not captured`。
- socket 层前缀读取只覆盖当前网络命名空间内本机进程的 socket：TCP 每个 socket 每个方向最多前 16 KiB；UDP 只读发出的 QUIC 长包头数据报，同样以每个 socket 16 KiB 为限，其他数据报不占预算。数据在内存中解析后丢弃，不写盘。TLS 和 QUIC 在这一层除握手外都是密文，所以它看到的内容和线上报文一致，不涉及 TLS 明文。TCP 两个方向都会解析，只有读成客户端的 ClientHello、请求头或代理握手的方向才会用来命名，服务端回复不会。它要挂到至少一个采集接口上观察到的连接；完全没经过任何所选接口的连接不单独列出。未 connect 的 UDP socket 没有固定的本地地址，按本地端口和对端地址找连接。HTTP 请求数仍以报文为准，只有报文没给出名字时才用 socket 层的字节。转发、桥接给虚拟机或其他网络命名空间的流量不经过本机 socket，只能靠报文。
- 内核 socket 表（`/proc/net/tcp`、`tcp6`、`udp`、`udp6` 与 `/proc/<pid>/fd`，即 ss/netstat 的数据源）是进程归属的补充来源。存在两端都没有 PID 的 TCP/UDP 连接时，程序每 10 秒最多读一次，只在找到匹配的 socket 时才扫描进程的文件描述符；它给启动前已建立、或 connect/accept 早于探针挂载的连接补上进程，并按上文规则确定中途开始的 TCP 连接方向。启动时先读一份，用来判断哪些连接早于抓包。只覆盖当前网络命名空间；在两次读取之间开始又结束的连接，这里拿不到。
- DNS 提示取 UDP 53 应答中提问名对应的 A/AAAA 地址（包括 CNAME 之后的地址），每个 IP 最多保留 4 个名字、10 分钟。从握手开始观察到的连接只用建立前的应答；抓包前建立的连接也接受之后的重新解析。它不受 `--port` 过滤，看不到 DoH/DoT 等加密 DNS。
- 页面显示 AF_PACKET 丢包、PID 事件丢失、解析失败及索引淘汰。GSO/GRO、首片丢失的 IP 分片、桥接、NAT、转发、抓包缺口和高负载可能影响报文与进程归属；整机页 IP 数字只代表选定采集点的观测结果。本机受控 `sendfile` 已被 `tcp_sendmsg` 探针计到；splice、内核 TLS 及其他不经过已挂探针的路径仍可能让 PID socket I/O 少计。

实现约定见 [开发说明](docs/development.md)，HTTPS 解析与开源实现的对照见 [HTTPS 解析对照](docs/https-parsing-review.md)，当前页面与交互见 [界面说明](docs/ui-design.md)。
