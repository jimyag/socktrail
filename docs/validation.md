# socktrail 验证记录

日期：2026-09-23。主机：开发机，Ubuntu Linux `6.8.0-139-generic`，x86_64，Go `1.27.1`。以下均为本机当前网络命名空间的短时观察，不代表跨内核或生产负载验收。部分表格记录的是界面调整前的版本，已在对应行标注。

## 构建与自动检查

界面曾把多网卡合并视图标为 `HOST`，下方历史 PTY 记录保留当时的实际输出；现已改为 `OVERVIEW`，避免与 HTTP Host 混淆，按键 `a` 的行为未变。

此前执行 `go build -o /tmp/socktrail-multi ./cmd/socktrail`、`go test ./...`、`go test -race ./...`、`go vet ./...`，均通过。整机视角更新后再次执行 `go test ./...`、`go vet ./...` 和 `go build -o socktrail ./cmd/socktrail`，均通过。单元测试覆盖 IPv4/IPv6/ICMP 报文解析、TCP 分段/乱序/重传、HTTP 多 Host 与请求体边界、TLS SNI 与 ECH 外层名、跨 TLS record、SNI 位于长 padding 后、无 extensions 的 TLS 1.2 ClientHello、重复 SNI 拒绝、IP/应用字节分离、TCP FIN/RST 与代次、PID 复用分组与同五元组新代次、共享 socket 的接受者和 I/O 执行者分离、PID I/O 明细过期守恒及 UDP wildcard PID 歧义。

本次增加应用协议标签、TCP 健康指标和短时 PCAPNG 后，重新执行 `go test ./...`、`go test -race ./...`、`go vet ./...`、`go build -o socktrail ./cmd/socktrail`，均通过。新增测试覆盖 OpenVPN TCP/UDP 特征与非默认端口不猜测、QUIC 固定位校验、TCP 重复 SYN 与序号重叠、UDP 以太网 padding 排除、PCAPNG 块长度与注释，以及用系统 `tcpdump` 独立读取测试生成的文件。

实机 `lo` 上运行短时 HTTP/1.1 服务：报表显示 `APP=HTTP`、`protocol.example.test` Host、1 次请求和该连接 623 个观测 IP 字节。交互界面选中 PID 后按 `c` 录制后续流量：TCP 样本为 35 个可由 `tcpdump -nnr` 解析的报文，UDP 样本为 10 个；两次均按 `c` 停止、按 `q` 退出码 0。临时录制目录权限 `0700`，文件权限 `0600`；`pgrep -x socktrail` 没有发现残留进程。首次 UDP 测试在界面/抓包尚未启动完成前就发送流量，生成 68 B 的空 PCAPNG；等界面出现后重测才得到 10 个 UDP 报文。这说明录制只覆盖启动后的新流量，不能补历史。没有用受控远端重传、真实 OpenVPN/QUIC 会话或生产负载验收新标签与健康指标；它们目前以构造样本和有限本机流量为证据。

## 受控流量

| 场景 | 本机观测结果 |
| --- | --- |
| TCP IPv4 HTTP | `lo` 上指定 `Host: api.example.test`，同时显示客户端和本机服务 PID；Host 进入 HTTP/TLS 页。 |
| TCP IPv4 TLS | `openssl` 发起带 `cdn.example.test` SNI 的 ClientHello，显示 SNI、客户端和服务 PID；没有由 SNI 生成 HTTP 请求数。 |
| TCP IPv6 HTTP | `::1` 上显示 HTTP Host 和参与 PID。 |
| UDP IPv4/IPv6 | 本机 UDP 客户端、服务端分别触发 send/receive 关联，两端 PID 可显示；歧义时显示 ambiguous。 |
| HTTP 多 Host | 单 TCP 连接先后出现 `a.example.test`、`b.example.test`，首个请求头被分段；Host 次数各 1，连接 764 IP 字节仅进入 `multiple Hosts` 一组。 |
| TLS 分段 | 517 字节 ClientHello 分为 12 字节和余下片段发送；识别 `split.example.test`，连接 989 IP 字节只计一次。 |
| 真实 HTTPS 握手与请求 | 使用本机临时自签名证书，`curl -k --resolve` 完成 TLS 握手及加密 HTTP 请求，客户端收到 `hello`；`lo` 捕获 14 包、3,411 IP 字节，识别 `https.example.test` SNI，HTTP Host 请求数为 0，客户端和服务端 PID 均显示，AF_PACKET 与 PID ring 无丢失。这个 0 表示旁路未观察到明文 HTTP 请求头，并非 HTTPS 服务未处理请求。 |
| 无 SNI 的真实 ClientHello | `openssl s_client -noservername` 发 293 B ClientHello，另一个带 `-servername real.example.test` 发 319 B；两个连接分别进入 `tls unknown` 与 `tls real.example.test`，IP/PID/流量均保留，HTTP Host 请求数均为 0。测试服务器只读取 ClientHello，未完成握手，因此这行只验 ClientHello 分类。 |
| UDP 字节对照 | 3 字节 UDP 负载对应 31 字节 IPv4 报文；socktrail 与 tcpdump 都记录 IP `length 31`，AF_PACKET 丢包 0。 |
| ICMPv4/ICMPv6 | `ping` 报文进入统计；更新后的 IPv4 实测输出 `type=8 code=0 id=38624 seq=1` 和 Echo Reply 的 type/code/id/seq；ICMP PID 保持 unknown。 |
| 繁忙接口 | `br0` 10 秒捕获 1100 IP 包、177975 IP 字节、194 观测流；AF_PACKET delivered 1166/dropped 0，PID events 1313/ring lost 0/queue dropped 0。没有新完整握手的现存连接不被虚构为已知域名。 |
| 交互界面与退出 | 在 PTY 中打开 HTTP/TLS 页，显示 HTTP Host 与 TLS SNI 行；按 `q` 退出后终端恢复，检查未留下 eBPF 程序。 |
| 鼠标与半屏详情 | 在 40 行 PTY 中启动交互界面，默认分隔线位于第 20 行，底栏默认显示 `conns`；注入 SGR 鼠标按下、拖动和释放，将分隔线移至第 28 行。另在 60 列 PTY 中点击 `process` 标签并滚动其列。退出码 0，鼠标报告启用与关闭序列均写出。单元测试覆盖跨读缓冲的鼠标序列、滚轮、行与标签选择、拖动边界。这里验证的是终端协议与程序行为，尚未在每种终端模拟器上逐一人工操作。 |
| 自适应宽度与横向滚动 | 80 列 PTY 的主表与连接表都能通过方向键横向滚动；单元测试确认窄窗口的原始表格行仍保留完整 IPv6 地址与长 Host。300 列 PTY 的主表占满可用宽度，`graph` 不再出现。同一运行中的 PTY 从 80×40 调整到 300×30 后，主表宽度从 79 列更新为 299 列，可见行数与分隔线位置同步变化。另在 60 列 PTY 验证 `process` 底栏可横向滚动。 |
| PID socket I/O | `lo` 上 curl 请求 `io.example.test`：curl 发送 78 B、接收 605 B；Python 服务接收 78 B、发送 605 B；同一连接的 IP 报文字节 1323 B。PID 应用字节没有混入 IP 总量，PID ring lost 0。 |
| TCP 生命周期 | 普通 HTTP 连接结束后报告 `closed`；FIN 半关闭、第二个 FIN、RST 和同五元组新 SYN 的状态与代次有单元测试。 |
| 多接口 | 同时指定 `--interface lo --interface br0`，本机 HTTP 请求只在 `lo` 形成 1378 IP 字节，`br0` 对该端口为 0；PID socket I/O 在报告末尾只列一次。交互 TUI 用 `i` 在 `lo`/`br0` 切换，`q` 后恢复终端。 |
| 多网卡总览 | 界面调整前，用 `sudo -n ./socktrail --interface lo --interface br0` 在 120×40 PTY 启动，默认显示 `IFACES (2)` 及两张网卡；按 `i` 切换选择并按 `Enter` 进入所选网卡视图，按 `q` 后退出码 0、终端恢复。单元测试让同一五元组在两张网卡各出现一次，确认总览保留两个独立的 40 B 行，没有生成跨网卡合计。该构造测试不等于实机同包跨接口去重验收。 |
| 自动选网卡 | `sudo -n ./socktrail --duration 2s --limit 1` 无 `--interface` 正常退出；自动选择 `br0,dae0,eno1,lo,tailscale0,ztdhgp6hvy`，界面调整前每张分别输出 IP 计数。`go test ./...` 通过；候选超过 8 个时显式报错，避免静默漏抓。当时在 PTY 无参数启动，界面显示 `IFACES (6)`，按 `q` 后退出码 0，终端恢复；此次短时快照没有新完整 TLS 握手，不用于域名解析验收。 |
| 整机默认页面 | 更新后执行 `sudo -n ./socktrail --duration 2s --limit 3`：报告只有一个 `HOST` 观测连接列表与一份 PID socket I/O 汇总；PTY 无参数启动首先显示 `socktrail HOST` 和整机 PID 行，按 `q` 后退出码 0、终端恢复。单元测试构造同一 TCP 连接在两接口各出现一次、Host 仅在第二接口可见：整机页只有 1 条连接、1 次 HTTP 请求、200 B 单点 IP 观测值，PID socket 收发量只保留一份；不同 TCP SYN 序号的复用连接保持两代。实机 NAT 改写后五元组不同，仍可能形成两个观测流，因此 IP 列明确不是精确整机总量。 |
| 整机页导航与过期 | 最终二进制在 PTY 无参数启动显示 `socktrail HOST`；按 `0` 显示 `IFACES (6)`，按 `a` 返回整机，按 `d` 打开 HTTP/TLS 页，按 `q` 后退出码 0、终端恢复；退出只报告采集接口数及丢包，不把逐接口 IP 字节相加。单元测试覆盖同一观测流切换代表接口后详情指针保持稳定、过期时只保留一份累计字节与域名证据。 |
| 页面刷新闪烁 | 修复前常规 `render` 每次都发送 `ESC[2J` 整屏清空；改为只更新变化行并清除行尾残留。PTY 无参数运行时，启动阶段有 1 次整屏清空，之后连续 5 秒刷新记录中为 0 次；按 `q` 后退出码 0、终端恢复。单元测试核对未变化行不重画、缩短的行清除旧字符。尚未逐一检查不同终端模拟器的视觉表现。 |
| 整机页本机 TLS SNI | 启动无参数 6 秒快照和临时 `openssl s_server`，再用 `openssl s_client -servername hostglobal.example.test` 连接 `127.0.0.1:19443`。整机报告显示 1 条已关闭 TCP 连接、TLS `hostglobal.example.test` 1 条、HTTP Host 请求数 0，单采集点 IP 观测值 3,148 B；AF_PACKET dropped 0、PID ring lost 0。服务启动早于探针，服务 PID 本次未知；这是握手域名和全局页合并验收，不作为双端 PID 验收。临时服务已退出。 |
| `dae` 下的 HTTPS 域名 | 用 `curl -4 --noproxy '*' --local-port 40124 https://example.com` 触发新连接；`tcpdump -i any -e` 看到客户端 ClientHello 从 `dae0` 发出，服务端报文经过 `dae0` 和 `br0`。单抓 `br0` 的另一受控连接只有入站报文，socktrail 在 `br0` 的短时快照中没有域名；改抓 `dae0` 并发起新连接后，快照显示 `tls example.com`、6728 IP 字节，AF_PACKET 丢包 0、PID ring 丢事件 0。接口选择决定能否看到域名，不能从 PID socket I/O 或单侧回包推断 SNI。 |
| 两个并发客户端 PID | 两个 curl 同时访问本机 HTTP 服务，报告有两条连接，分别关联不同的 curl PID 与 `one.example.test`、`two.example.test`，并都关联同一服务 PID；PID 应用 I/O 分别记录。首次运行有 900 B I/O 事件先于抓包流处理而无法归入连接，PID 总量未丢；加入有界 2 秒待匹配队列后复测两个 curl，`unmatched=0`、PID ring lost 0，两个 Host 和 PID 仍分开。 |
| UDP 双端应用字节与归属 | 探针先启动，再让 Python UDP 客户端发 `hello`、服务端回 `world`：`lo` 捕获 2 个 IP 包、66 B；客户端与服务端各显示 RX 5 B、TX 5 B；连接行分别保留客户端 PID 和服务端 PID，不因服务端回包而交换。`--port 18890` 仅筛接口流，PID I/O 仍是全网络命名空间；这次主机有约 1.47 MB 其他 I/O 未关联到所选流，不能视为抓包丢失。 |
| 共享 TCP socket | Python 父进程 `accept` 后 `fork` 子进程读写同一个已接受 socket；独立客户端发 45 B HTTP 请求并收 62 B。`lo` 捕获 10 包、643 IP 字节；服务端连接角色保留父 PID，子 PID 单独显示 RX 45 B、TX 62 B，客户端 PID 显示 TX 45 B、RX 62 B；识别 `shared.example.test`，PID ring lost 0。首次用固定等待启动抓包时遗漏这条短连接；改为等程序输出采集就绪行再发请求后复现成功，因此首次 0 包不能作为抓包代码故障或验证通过的证据。 |
| `sendfile` | Python 服务进程调用 `os.sendfile` 发送 65,536 B，客户端收到 65,536 B；本机 `tcp_sendmsg` 探针记录服务端 TX 65,536 B、客户端 RX 65,536 B，`lo` 捕获 10 包、66,072 IP 字节，AF_PACKET 与 PID ring 均无丢失。这只证实本机这条路径，不能推断所有零拷贝或其他内核也受同一 hook 覆盖。 |
| 短连接压力样本 | 探针就绪后，同一客户端和服务端进程在约 20 秒的观察窗口内完成 2,500 次独立 TCP 连接，每次请求与响应各 64 B。`lo` 记录 2,500 个流、27,427 个 IP 包、1,786,204 IP 字节；AF_PACKET delivered 55,298/dropped 0，PID events 17,502/ring lost 0/queue dropped 0/invalid 0，流索引丢弃 0。观察中进程 RSS 约 27 MiB。此样本不是长期或极限吞吐验收。 |
| 关闭连接过期回收 | 探针就绪后完成 1,000 条短 TCP 连接，再保持采集至 72 秒。最终 `lo` 显示 10,975 包、714,700 IP 字节、保留流 0、过期流 1,000；过期流量汇总 TX 714,700 B，未索引字节 0。AF_PACKET delivered 24,786/dropped 0，PID events 28,680/ring lost 0/queue dropped 0/invalid 0。采集进程运行中 RSS 从约 25.7 MiB 到约 24.9 MiB；这个短窗口只验证一分钟回收路径，不能证明长期内存稳定。 |

此前更新 ICMP 字段后，以 `sudo /tmp/socktrail-final --interface lo --duration 6s --limit 20` 重新运行，观察到 180 个被计入的 IP 包、25136 IP 字节；AF_PACKET delivered 368（包括被排除的 `lo` 接收副本与非 IP 数据）、dropped 0；PID ring lost 0、queue dropped 0。由于其他本机流量同时存在，这组总量不用于精确对照。上表的受控案例在开发过程中分别运行，并非同一次快照。

## 2026-09-23 HTTPS 域名增量

最终执行 `go test ./...`、`go test -race ./...`、`go vet ./...`、`go build -o socktrail ./cmd/socktrail` 均通过；生成的本机 x86_64 可执行文件约 6.8 MiB。限时抓包后 `pgrep -x socktrail` 未见残留进程。

| 场景 | 本机结果 |
| --- | --- |
| QUIC v1/v2 官方向量 | RFC 9001、RFC 9369 附录中的 1200 B 加密客户端 Initial 均通过认证，重组出 `example.com` ClientHello；篡改认证标签或截断报文时不产生域名。跨 CRYPTO offset、重复和冲突片段有单元测试。 |
| 真实 QUIC v1 | 临时 quic-go v0.57.0 客户端和服务端在 `lo:18555` 完成连接，客户端 SNI 为 `quic.example.test`。`socktrail --interface lo --port 18555 --duration 6s` 显示 1 条 `UDP QUIC` 流、`quic quic.example.test` 连接 1、观测 IP 字节 9975、HTTP 请求数 0；双方 PID 为同一个临时进程。AF_PACKET dropped 0、PID ring lost 0。quic-go 打印了 UDP 接收缓冲区不足的提示，但此次连接成功；这不构成高负载验收。 |
| 默认 OpenSSL 探针加载 | 本机 x86_64、Linux 6.8、系统 OpenSSL 3.0.13 下默认加载成功，状态显示库路径；无需修改受测进程。`--openssl-probe=false` 可关闭。 |
| OpenSSL 出站进程 SNI | 临时 C 客户端使用 `SSL_set_fd`、`SSL_set_tlsext_host_name`、`SSL_connect` 连接本机 `openssl s_server`；探针收到 2 个 SNI 事件、invalid 0、queue dropped 0。抓包也独立识别 `process.example.test`；同一连接只进入一个 `tls` 域名流量分组，没有重复字节或请求数，详情显示 `OpenSSL-PID=<客户端 PID>`。另用 `openssl s_client -servername openssl.example.test` 完成一次握手，探针同样收到 2 个事件。开始受控连接前必须等快照打印探针就绪行；固定睡眠启动可能漏抓。 |
| OpenSSL 自定义 BIO | 本机 curl 8.5.0 使用 `SSL_set0_rbio` 的自定义 BIO，不经过 `SSL_set_fd`/`BIO_new_socket`；新增的同线程 `SSL_connect` + `tcp_sendmsg` 关联后，探针收到 2 个 SNI 事件，invalid 0、queue dropped 0，连接显示 `OpenSSL-PID=<curl PID>`。`--interface lo --port 18474 --duration 7s` 快照只有 1 条 TCP 连接、1 个 `tls probe.example.test` 域名分组、3,501 IP B，无重复字节；AF_PACKET dropped 0、PID ring lost 0。curl 因测试服务未返回 HTTP 响应而退出码 52，TLS 握手和 SNI 观测已完成。报文 ClientHello 同时也能解析此 SNI，因此此测试证明进程关联，不证明额外域名覆盖率。 |
| OpenSSL 直接 fd 路径回归 | 用 `openssl s_client -servername regression.example.test` 连接本机 `s_server`；重构 socket 发射函数后探针仍收到 2 个 SNI 事件，invalid 0、queue dropped 0，域名页仍只有 1 条 TLS 连接、3,148 IP B，连接详情显示 OpenSSL 客户端 PID；AF_PACKET dropped 0、PID ring lost 0。 |

OpenSSL 探针 map 键最初含未初始化的对齐字节，导致相同 SSL 指针的 fd/SNI 查找失败；显式填充键结构后，上述受控 C 客户端可产生事件。进程探针只读 SNI 和已关联 socket 的内核五元组，不读取请求正文或 TLS 密钥。缺少可验证 fd、进程退出、网络命名空间不匹配或未捕获到对应 IP 流时，不将事件硬归到连接。

## 2026-09-23 HTTPS 多来源域名

`go test ./...`、`go test -race ./...`、`go vet ./...`、`go build -o socktrail ./cmd/socktrail` 均通过，可执行文件约 6.8 MiB。新增测试覆盖：ClientHello 完成后的丢包、缺口超时与超大 TSO 段不再记为解析失败；HTTP 请求体截断时按长度跳过，截断落在请求头时报错；CONNECT、407 重试、CONNECT 内非 TLS、带 RFC 1929 认证且分段到达的 SOCKS5、SOCKS5 IPv4 目标；ECH 标记与进程 SNI 优先；无 SYN 的 ClientHello 与仅有应用数据的 TLS 连接；DNS 应答 CNAME 链、非应答和截断报文、应答与连接的时间匹配、过期；Host 中的终端控制字节被拒绝。

解析器直接喂入本机真实客户端的握手字节：Go crypto/tls、curl 8.5（OpenSSL 3.0.13）、node（内置 OpenSSL 3.5.6）都解析出正确 SNI；curl 经 HTTP CONNECT（`-x`）和 SOCKS5（`--socks5-hostname`）代理时，得到 `CONNECT`/`SOCKS5` 代理目标和隧道内 SNI。

`lo` 受控实机：临时 Go 程序在 `127.0.0.1` 提供 HTTPS、HTTP、CONNECT 代理和 SOCKS5 代理，并在 socktrail 启动前先建立一条到 `example.com:443` 的 TLS 连接；等快照打印 OpenSSL 就绪行后再发起流量，`sudo socktrail --duration 20s`（自动 6 个接口）的结果如下：

| 场景 | 结果 |
| --- | --- |
| 直连 HTTPS | `TLS direct.lab.test`，详情含客户端 ALPN `h2,http/1.1` 与 `OpenSSL-PID` |
| curl 经 CONNECT 代理 | 客户端到代理的连接为 `TLS connect.lab.test (CONNECT connect.lab.test)`，代理到服务端的连接为 `TLS connect.lab.test`；域名组 2 条连接 |
| curl 经 SOCKS5 代理 | 客户端到代理的连接为 `TLS socks.lab.test (SOCKS5 socks.lab.test)`，代理到服务端的连接为 `TLS socks.lab.test` |
| 8 MiB HTTPS 上传 | `TLS upload.lab.test`，8,519,258 IP B，无解析错误。报告计入 132 个超过 64 KiB 接收缓冲而截断的帧；它们和超过 16 KiB 复制上限的 TSO 段都没有产生解析错误 |
| 8 MiB HTTP 请求体后同连接第二个 Host | `HTTP multiple Hosts`，Host 请求数 2 |
| 抓包前建立的 TLS 连接 | 启动后重新解析 `example.com`，应答经 `lo` 上的本机 DNS；该连接显示 `DNS example.com` |
| 覆盖率行 | `TLS/QUIC named 98% of 8.2MB (DNS hint 0%); unnamed: handshake not captured 1%, unknown 0%`；未命名部分是本机其他启动前已建立的连接 |

AF_PACKET dropped 0、PID ring lost 0、OpenSSL SNI 事件 8 个且 invalid 0；报告中没有 `parse error`，结束后无残留 socktrail 进程。另在 140×40 PTY 中启动交互界面，按 `d` 显示覆盖率行，按 `Enter` 聚焦连接后显示 `EVIDENCE` 行，按 `q` 退出码 0。

本次观察到 ZeroTier（UDP 9993）的报文被现有 QUIC 长包头特征识别为 `QUIC`，进入 `QUIC unknown`；这是此前已有的误识别，未在本轮修改。QUIC 路径只调整了证据字段，没有重新做真实 QUIC 握手，仍以 RFC 向量和单元测试为据。

## 2026-09-23 socket 层客户端字节读取

新 eBPF 对象用 clang-18 经 bpf2go 生成，`go test ./...`、`go test -race ./...`、`go vet ./...`、`go build` 均通过。`sudo go test ./internal/sockstream/` 加载探针后建立本机连接，依次用 `write`、3 个 iovec 的 `writev` 和一次 20 KB 写入发送数据：客户端发送流与服务端接收流读到的都恰好是前 16,384 字节，逐字节一致。普通用户运行时该测试跳过。

只抓 `br0`、时长 25 秒，同时运行上一版和当前版本。dae 拦截的连接在 `br0` 上只有回包。依次运行 curl（github.com）、git ls-remote（GnuTLS，github.com）、node fetch（registry.npmjs.org）、python urllib（pypi.org）、Go net/http（proxy.golang.org），以及用 uTLS 发出的 Chrome 133（www.google.com）和 Chrome 131（www.youtube.com）真实握手。

| 版本 | 结果 |
| --- | --- |
| 上一版 | github.com 与 pypi.org 只靠 OpenSSL 探针命名，npm、golang、google、youtube 没有名字；TLS/QUIC 已命名 85% |
| 当前版 | 7 条连接全部显示 `TLS <域名>`，两个 Chrome 握手带 `[ECH]`（uTLS 的 Chrome 指纹发送 GREASE ECH）；socket 层数据块 460 个，内核丢失 0、队列丢弃 0、无效 0；TLS/QUIC 已命名 92%，剩余 7% 是启动前已建立的连接 |

另用当前版本重跑上一节的 `lo` 受控实验：各场景结果不变，socket 层数据块 1,184 个且无丢失。8 MiB 请求体后的第二个 Host 仍计 2 次请求，报文与 socket 两份字节没有重复计数。抓包前建立的连接仍显示 `DNS example.com`：它在 socket 层读到的是密文，不会被当成 ClientHello。

## 2026-09-24 入站流量与全协议覆盖

PID 探针与 socket 层读取的 eBPF 对象用 clang-18 经 bpf2go 重新生成；`go test ./...`、`go test -race ./...`、`go vet ./...`、`go build -o socktrail ./cmd/socktrail` 均通过。root 下的 `internal/sockstream` 测试两项通过：TCP 两个方向读到的前 16,384 字节逐字节一致；双栈、未 connect 的 UDP socket 先发 4 B 短包头、再发 1200 B 长包头数据报，只读到后者，目的地址取自 `sendto`，本地地址为未指定。

入站实验用临时网络命名空间 `sttest` 充当外部客户端，经 veth 连到主机侧 `stext0`（10.99.0.1/24、fd99::1/64）。主机上运行 Python HTTP 服务（IPv4、IPv6 各一个）、`openssl s_server`、Python UDP 服务和一个每秒推送一行的 socat 服务；socktrail 启动前，先从命名空间建立一条到 socat 的连接。脚本等快照打印探针就绪行后再发流量。`sudo socktrail --interface stext0 --duration 20s` 的最终结果：

| 场景 | 结果 |
| --- | --- |
| ping 3 次；3000 B 大包 ping，IPv4、IPv6 各 2 次 | 每个 Echo identifier 一条 `inbound` 流，请求/应答数、序号和 RTT 齐全。大包的后续分片并入同一条流（IPv4 6,136 B、IPv6 6,304 B），请求数没有因分片重复计 |
| ARP、ICMPv6 邻居发现与路由请求 | ARP 流显示请求/应答数和双方 MAC；NS/NA 显示目标地址，RS 单独成流 |
| HTTP 入站，IPv4 与 IPv6 | `HTTP inbound-http.example.test` 和 `HTTP fd99::1`，方向 inbound，服务端 PID 为 python3 |
| TLS 入站 | `TLS inbound.example.test`，服务端 PID 为 `openssl s_server` |
| QUIC 入站 | 把 aioquic 生成的真实客户端 Initial 发到本机没有服务的 UDP 443：IPv4、IPv6 都显示 `QUIC quic-inbound.example.test (ALPN offered h3)`，方向 inbound，状态 `port-unreachable` |
| UDP 发到监听端口，含 4,000 B 分片数据报 | 两个数据报共 4,101 B 并入一条流，服务端 PID 为 python3 |
| UDP 发到关闭端口 | 该 UDP 流状态为 `port-unreachable`；主机回复的 ICMP 流写明所引用的原始 UDP 端点 |
| TCP 连关闭端口 | 状态 `reset`，方向 inbound |
| 启动前建立的入站 TCP | `midstream inbound`，服务端 PID 为 socat，来自内核 socket 表 |

AF_PACKET dropped 0、PID ring lost 0，socket 层数据块 1,465 个、内核丢失 0。结束后命名空间、veth 和临时服务都已清理。另有主机的 NetBIOS 广播和 ZeroTier 按接口发出的 ARP 出现在 `stext0` 上，socktrail 如实列出。

实验中发现并修正的问题：

- **tun 接口**：`tailscale0` 是 ARPHRD_NONE 设备，帧从 IP 头开始。此前一律按以太网解析，读出的“EtherType”其实是 IP 源地址前两个字节，整个 tailnet 的流量都没进入统计。现在按 `sll_hatype` 区分，整机快照里能看到 tailnet 上的 HTTP、ICMP 流。
- **accept 探针**：挂载时已经阻塞在 `accept()` 里的服务拿不到第一条连接的 accept 事件。临时打开 `kernel.bpf_stats_enabled` 核对（结束后已恢复），`inet_csk_accept` 的 fexit 程序在运行，但阻塞中的那次调用返回时不经过 trampoline。改挂 `__inet_accept` 的 fentry 后，启动前就阻塞的 `openssl s_server` 和阻塞式双栈 Python 服务，第一条连接都有 accept 事件，IPv4 映射连接和 IPv6 连接的服务端 PID 都正确。
- **accept 与 SYN 的处理顺序**：抓包和 eBPF 两个通道没有固定的处理顺序。accept 事件先于入站 SYN 被处理时，原逻辑把这条角色当成旧连接的丢掉；现在没有旧流、且角色是 2 秒内记录的就采用。
- **分片**：大包 ping 的后续分片此前另成一条流；IPv6 后续分片还被记成协议 44（分片扩展头本身）。

整机快照（自动 6 个接口）：启动前已建立的连接有了方向和进程，例如 nginx 的入站 443、frps 的入站连接、本机进程的出站 443；无连接的入站 UDP（tailscaled、zerotier-one）也有服务端 PID；覆盖率行把这些连接的 TLS 流量单独列出。tailscale 的数据报此前只在握手包上标 `WireGuard`，现在传输数据也能识别。另外，此前记录的 ZeroTier 被误标为 QUIC 已修正：QUIC 标签要求长包头带已知版本号。

回归：`lo` 受控实验（直连 HTTPS、CONNECT、SOCKS5、8 MiB 上传、多 Host、DNS 提示）各场景结果不变，覆盖率行为 `TLS/QUIC named 100% of 8.1MB (DNS hint 0%); 111.4KB on connections open before start`。只抓 `br0` 的 dae 对照中，当前版 7 条新连接全部命名，`named 100% of 634.5KB`，启动前的连接 48.7 KB 另列；上一版为 84%。socket 层数据块 553 个，无丢失。

## 2026-09-24 旧内核兼容

起因是 Ubuntu 22.04（5.15）上启动即报 `func 'tcp_recvmsg' arg5 type INT is not a struct`：recvmsg 系列在 5.19 去掉了 nonblock 参数，按新签名写的 fexit 把第 6 个参数当成返回值读取，被校验器拒绝。本机只有 6.8，所以改用 QEMU/KVM 直接启动各发行版的官方内核包，initramfs 里放 socktrail、两个探针包的 root 测试和一个静态链接的 Go init。init 挂载 proc/sys、拉起 lo，运行 root 测试，再让 socktrail 抓 10 秒：这 10 秒里 init 自己在回环上发起 HTTP、TLS、UDP、真实 QUIC Initial，以及原始 socket 和 ping socket 的 ping，最后关机。每个内核启动加测试约 15 秒。

| 内核 | 结果 |
| --- | --- |
| Debian 11 5.10.0-32 | 5 项 root 测试通过；PID、OpenSSL、socket 层三个探针加载；socket 层按 socket 地址区分连接 |
| Ubuntu 20.04 HWE 5.11.0-46 | 同上 |
| Ubuntu 20.04 HWE 5.13.0-52 | 5 项通过，socket 层使用 cookie |
| Ubuntu 22.04 5.15.0-194 | 5 项通过；PID 探针加载 recvmsg 旧签名版本 |
| Ubuntu 24.04 6.8.0（本机） | 5 项通过 |
| Ubuntu 24.04 HWE 6.17.0-42、7.0.0-34 | 5 项通过；accept 走 `__inet_accept` |
| Ubuntu 20.04 HWE 5.8.0-63 | 内核没有 BTF，无法加载，属硬性限制 |

各内核上 socktrail 的快照一致：HTTP、TLS、QUIC 流都有名字，TCP 两端和 UDP、ICMP 的发送方都归到 init 进程，两种 ping 各成一条带 RTT 的 Echo 流，QUIC 发往无服务端口时标 `port-unreachable`。

逐个内核发现并修正的问题：

- recvmsg 签名：`tcp_recvmsg`、`udp_recvmsg`、`udpv6_recvmsg` 各加一个旧签名版本，加载器按内核 BTF 中 `tcp_recvmsg` 的参数个数保留其一。socket 层读取的 `tcp_recvmsg` 入口还要读 flags 判断 `MSG_PEEK`，旧签名下它的位置也不同。
- 5.15 上 OpenSSL 探针报 `invalid indirect read from stack`：写入 map 的结构体尾部有对齐填充，老版本校验器不接受未初始化的字节。三个结构都补上显式填充字段。
- 5.15 上 socket 层读取报“程序过大，处理了 100 万条指令”，每次加载还耗时约 22 秒：分块循环里的分支组合让老版本校验器无法剪枝。循环游标改放在 per-CPU map 内存里，校验器不跟踪那里的值，各分支回到循环头时状态相同；UDP 只复制一块、不走循环。改后 5.15 上加载只需零点几秒，本机 6.8 上 socket 层 root 测试也从约 3 秒降到 0.6 秒。
- 同一问题导致虚拟机里的第一次快照一个包都没抓到：`--duration` 从加载探针之前开始计时，22 秒的校验耗尽了 10 秒窗口。现在从抓包开始运行时计时。
- 5.11、5.13 上原始 socket 的 ping 没有事件，5.13 上 socket 层读取加载失败：`iov_iter.iter_type` 从 5.14 才有，之前是同时带传输方向的 `type` 位集合。补了 CO-RE 回退。
- 5.10、5.11 上 tracing 程序不能调用 `bpf_get_socket_cookie`（5.12 才开放）。加载器用一个极小的探测程序判断；不可用时通过只读常量改用 socket 的内核地址作键，校验器会删掉不走的分支和其中的 helper 调用。第一版在 `sk_free` 时清理地址，本机强制走这条路径的测试立刻失败：TCP 每次发送后 `tcp_wfree` 都会调用 `sk_free` 释放写内存引用，发送方向的预算因此不断被清零。改挂 `inet_sock_destruct` 后通过。这条路径现在由 root 测试在任何内核上都跑一遍，用户态也在偏移 0 时重建解析状态。
- 5.8 上 socket 层读取单独运行时报 memlock 不足：5.11 之前 BPF map 计入 memlock，只有 PID 探针调用了 `RemoveMemlock`。三个探针的入口现在都各自调用。
- 进程启动时间原来读 `task->start_time`，它不计挂起时间，而 `/proc` 用的是计入挂起的 boottime；挂起过的机器上，同一进程在两个来源里会对不上。现在改读 `start_boottime`（5.5 之前为 `real_start_time`）。这台机器没挂起过，这一点没有实测复现。

本机 6.8 上重跑：`go test -race ./...`、`go vet ./...` 通过；8 秒快照里，ICMP 流的发送进程能对上，除了手动运行的 `ping`，还找出了一个持续 ping 多个主机的监控进程 `pingexporter`，此前这些本机 ping 都没有进程。`tailscale0` 单独抓 6 秒得到 109 个 IP 包、31 条流，没有伪造的 EtherType 行。

tun 接口的录制：录制测试改为按 tun 路径构造帧，即 IP 报文加空以太网头，系统 tcpdump 能从生成的 PCAPNG 里解出 `UDP, length 3`。

UDP 的 socket 层 QUIC 读取：本机用 aioquic 连 `cloudflare-quic.com:443`，这条网络上 QUIC 不通，没有回包；Initial 走 IPv6 发出，没有被 dae 截走，线路上已被抓到并命名为 `QUIC cloudflare-quic.com`，发送进程也对上了。“只看得到回程方向”的透明代理场景在这里复现不出来，这条路径目前由各内核上的 root 测试和单元测试覆盖。

分发：默认的 cgo 构建在 Ubuntu 24.04 上要求 glibc 2.34，拷到 Debian 11 或 Ubuntu 20.04 上无法启动；虚拟机测试用的都是 `CGO_ENABLED=0` 的静态构建，README 的构建命令已改为这种方式。

## 尚未完成的验收

- 真正的操作系统 PID 数值复用仍未在实机强制复现；目前 PID 身份包含进程启动时间，且有同 PID、不同启动时间的代次单元测试。共享 socket 的 `accept`/读写由不同进程执行已实测，但 fd 传递、多个写者和更复杂的 socket 交接仍需验证。
- NAT、桥接转发、非当前网络命名空间及不同内核版本的 PID/方向验证；多接口已能分别观察；整机页按同五元组、同 TCP 代次合并观测，但 NAT 改写的不同五元组仍无法可靠去重，“精确整机 IP 总量”未实现。`lo` 只数发送副本，IP RX/TX 不等于本机两端 socket 各自的字节。
- `sendfile` 在本机这个受控样本经 `tcp_sendmsg` 计到完整 65,536 B；splice、内核 TLS、其他零拷贝路径及跨内核行为仍未验证。目前 PID 应用字节只承诺已挂 TCP/UDP sendmsg/recvmsg 探针的返回值，其他路径可能少计。
- 探针挂载前已经进入阻塞 `recvfrom` 的 UDP 服务，首次返回可能少计；服务进程在探针之后启动的对照场景两端各为 RX/TX 5 B。启动时抓取的中途连接和调用不能补历史数据。Linux 6.8 以前的内核没有 `__inet_accept`，回退到 `inet_csk_accept` 的 fexit 已在 5.10 至 5.15 上加载并收到 accept 事件，但挂载前就阻塞着的第一次 accept 仍会漏掉，只能靠 socket 表补上仍存在的连接。
- 内核 socket 表只覆盖当前网络命名空间，每 10 秒最多读一次，两次读取之间开始又结束的连接拿不到。
- 旧内核只在虚拟机里验证了回环流量；arm64（fentry 要到 6.0 才支持）、RHEL 这类大量回移特性的内核都没有测。
- socket 层读取在高并发短连接和大吞吐下的开销未测；UDP 只读发出的 QUIC 长包头，DNS 应答仍只靠报文；QUIC Initial 的 socket 层读取只有 root 单元测试，尚未用真实本机 QUIC 客户端在透明代理下验收。NAT 改写前后五元组的映射尚未实现。
- 极限吞吐、数小时以上运行、物理网卡上的 GSO/GRO、首片丢失的 IP 分片、丢包后的重组恢复，以及真实 ECH 与浏览器 GREASE ECH 流量。`lo` 上的 TSO 截断、无 SYN 的 ClientHello 和 veth 上的 IPv4/IPv6 分片已有受控样本或单元测试，但不代表这些场景都已验收。
- ICMP 只有 Echo 请求能归属进程：带 `IP_HDRINCL` 的原始 socket 自己拼 IP 头，其中的 ICMP 不识别；Echo 以外的 ICMP 与其他协议的原始 socket 流量没有进程。tun 接口帧的录制只在单元测试里经 tcpdump 解码，没有在真实 tun 接口上经 TUI 录制并用 Wireshark 核对；跨接口非对称路径的 PCAPNG 导出也没有核对。
- QUIC v2 目前只有 RFC 官方加密向量，没有本机真实 v2 客户端；QUIC v1 已完成本机真实握手样本。QUIC 长连接同五元组重用、极限乱序/丢包、真实 ECH 和 HTTP/3 加密的 `:authority` 尚未验收或实现。
- OpenSSL 进程探针目前仅覆盖系统动态库及已验证的 fd 或同线程 `SSL_connect`/TCP 发送关联路径；其他自定义 BIO 路径、Go TLS、静态链接 TLS、其他 TLS 库与解密后 HTTP/2/3 请求域名未覆盖。正常抓到 ClientHello 时，进程 SNI 通常与报文 SNI 重合，不能保证“所有 HTTPS 域名”。

IP、协议、域名界面及连接报告的字节取捕获 IP 报文长度；整机页对每条逻辑流只选一个采集点，不能当作精确整机 IP 总量。PID 页和报告末尾的 PID 汇总取 eBPF socket 事件的应用读写字节，两者不相加。`AF_PACKET delivered` 是内核交付给抓包 socket 的数量，包含后来因 `lo` 去重、非 IP 或解析条件而未计入的报文，不能直接与 `IP packets` 相减来当作丢包数。测试用服务为临时进程，不作为程序的一部分。
