# 历史验证记录

本页保留 2026-09-23 至 2026-09-25 的实测记录。记录中的命令、代码路径、接口数量限制和待验证事项对应当时的版本，不能作为当前使用说明；当前入口和限制见[使用指南](../user/usage.md)与[数据口径](../user/measurement.md)。

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
| 整机默认页面 | 更新后执行 `sudo -n ./socktrail --duration 2s --limit 3`：报告只有一个 `HOST` 观测连接列表与一份 PID socket I/O 汇总；PTY 无参数启动首先显示 `socktrail HOST` 和整机 PID 行，按 `q` 后退出码 0、终端恢复。单元测试构造同一 TCP 连接在两接口各出现一次、Host 仅在第二接口可见：整机页只有 1 条连接、1 次 HTTP 请求、200 B 单点 IP 观测值，PID socket 收发量只保留一份；不同 TCP SYN 序号的复用连接保持两代。实机 NAT 改写后五元组不同，当时仍会形成两个观测流，因此 IP 列明确不是精确整机总量（NAT 映射后来实现，见“2026-09-24 协议补充、NAT 与抓包性能”）。 |
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

## 2026-09-24 协议补充、NAT 与抓包性能

本轮新增 sendfile/splice 计数、DNS 查询与应答码、TCP 上的 DNS 提示、SSH 版本标识、入站扫描汇总与流表淘汰、明文 HTTP/2、十余种应用协议标签、TLS 服务端握手信息和 conntrack NAT 映射，抓包改为 TPACKET_V3 环。`go vet ./...`、`go test ./...`、`go test -race ./...`、`CGO_ENABLED=0 go build` 通过；本机 6.8 上 probe、sockstream、capture、conntrack、tlsprobe、cmd 各包以 root 运行的测试全部通过。

新功能的单元测试：

- DNS 的查询与应答、TCP 上的 DNS（含名称提示缓存）；SSH 两端的版本标识。
- 扫描：30 次被拒的 TCP、15 次无应答、1 次 UDP 端口不可达，流表满时淘汰一次性流而不是丢掉新流，来源页标签正确。
- 协议标签：每个新协议一个正例，另有非默认端口上的 Kafka、ZooKeeper 端口上非四字命令的反例。
- HTTP/2：每次喂 7 字节，第二个请求的头部块跨 HEADERS 和 CONTINUATION 并引用 HPACK 动态表，计 2 次请求并识别 gRPC；只抓到前缀的 20,000 B DATA 帧按长度跳过。
- TLS 服务端：用 crypto/tls 在回环 TCP 上做真实握手，按 100 B 切段喂入。TLS 1.2 无 SNI 取到两个 SAN 名并标 `[cert]`；TLS 1.3 给出版本和原因；客户端拒绝自签名证书得到 `client alert: bad certificate`；服务端只接受 1.3 时得到 `server alert: protocol version`。
- conntrack：构造的 ctnetlink 应答（SNAT、ENOENT、其他请求的序号）。root 测试在私有网络命名空间里加一条 nftables DNAT 规则，建立连接后从两个方向都查到同一条目；原始元组反过来查、以及不存在的元组，都返回未跟踪。
- NAT 关联：网关两侧的流合为一条 `forwarded` 连接，字节只算一份；本机进程连 DNAT 服务地址时，connect 事件和之后的 socket I/O 都挂到抓到的后端元组上。
- 抓包环：root 测试在 lo 上发一个 40 KB 的 TCP 段，环里只保留 SnapLength，负载前 16 KiB 与原文一致，不计截断。

跨内核：Debian 11 的 5.10 以及 Ubuntu 的 5.11、5.13、5.15、6.17、7.0 虚拟机里，probe、sockstream、capture、conntrack 的测试每个内核通过 15 项（DNAT 测试因镜像里没有 nft 而跳过），包括 sendfile/splice 计数和抓包环。5.10 至 5.15 的 splice 写 socket 走 `generic_splice_sendpage` 的探针，6.17、7.0 走 `tcp_sendmsg`，都计到了。各内核的回环快照都是 7 条流、AF_PACKET 丢包 0，TLS 行带 `server chose TLS 1.3`。

NAT 实验：两个临时网络命名空间 stcli（10.99.1.2）和 stsrv（10.99.2.2）经 veth 接到主机的 stcl0（10.99.1.1）和 stsv0（10.99.2.1）。主机转发，并用一张 nftables 表做三件事：出 stsv0 时 masquerade，stcl0 进来的 8080 DNAT 到 10.99.2.2:80，本机发往 10.99.9.9:80 的连接在 OUTPUT DNAT 到 10.99.2.2:80。stsrv 里跑 Python HTTP 服务、只允许 TLS 1.2 的 `openssl s_server`（证书 SAN 为 lab.internal.test 和 *.lab.internal.test）和只允许 TLS 1.3 的 `openssl s_server`。`sudo socktrail --interface stcl0,stsv0 --duration 20s` 的结果：

| 场景 | 结果 |
| --- | --- |
| stcli 里 `curl http://10.99.2.2/` | 两个接口各一条流，都带 `[SNAT 10.99.1.2:P as 10.99.2.1:P]`，名称 `HTTP 10.99.2.2` |
| `curl http://10.99.1.1:8080/` | `[SNAT …, DNAT 10.99.1.1:8080 to 10.99.2.2:80]`，Host 仍是客户端写的 `10.99.1.1` |
| `curl -k --tls-max 1.2 https://10.99.2.2/` | `TLS lab.internal.test [cert]`，详情为 `server chose TLS 1.2; name from the server certificate, not SNI: lab.internal.test,*.lab.internal.test` |
| `curl -k https://10.99.2.2:8443/` | `TLS no SNI`，详情为 `server chose TLS 1.3; no SNI, and TLS 1.3 encrypts the server certificate` |
| 不带 `-k`，`--resolve` 到 lab.internal.test | `TLS lab.internal.test; client alert: unknown certificate authority` |
| `--tls-max 1.2` 连只接受 1.3 的服务 | `TLS no SNI; server alert: protocol version` |
| `curl --http2-prior-knowledge -H 'content-type: application/grpc'` | APP 为 gRPC，名称 `HTTP/2 10.99.2.2` |
| 主机上 `curl http://10.99.9.9/`，只抓 stsv0 | 后端元组 `主机地址:P → 10.99.2.2:80` 的流带 curl 的 PID 和 `[DNAT 10.99.9.9:80 to 10.99.2.2:80]` |

conntrack 查询 14 次，全部查到改写。长稳负载下另跑的 20 秒自动选接口快照里，279 条经 SNAT 转发的连接每条只有一行，方向都是 `forwarded`；查询 1,204 次，查到改写 406 次，队列满 0，失败 0。

抓包性能：iperf3 从 stcli 经主机转发到 stsrv，socktrail 同时抓 stcl0、stsv0，先跑 10 秒 TCP 单流，再跑 10 秒 64 B 的 UDP（`-b 0`）。CPU 是 socktrail 进程在该阶段的平均占用，100% 为一个核。

| 版本 | TCP 吞吐 | CPU | UDP 报文率 | CPU | AF_PACKET 丢包 |
| --- | --- | --- | --- | --- | --- |
| 不运行 socktrail | 23.9 Gbps | - | 11.1 万/s | - | - |
| 原实现：recvfrom 逐包读取、逐包送主循环 | 20.5 Gbps | 约 230% | 8.6 万/s | 约 180% | 0 |
| 批量送主循环 | 19.4 Gbps | 243% | 8.1 万/s | 186% | 0 |
| TPACKET_V3 环（8 MiB），整帧 | 17.1 Gbps | 99% | 9.6 万/s | 20% | 每接口约 400 |
| 环内每帧截到 16 KiB | 20.1 Gbps | 92% | 9.4 万/s | 20% | 0 |
| 解码时不再复制负载 | 20.6 Gbps | 22% | 9.8 万/s | 13% | 0 |
| 环缩到 4 MiB | 21.0–21.7 Gbps | 30% | 9.7 万/s | 12% | 每接口 340–435 |
| socket 表改为后台读取（当前） | 22.1–22.2 Gbps | 32% | 9.7–9.8 万/s | 13% | 0 |

用 perf 采样原实现：采集 goroutine 在 recvfrom 里阻塞、被逐包唤醒占约 40%，Go 调度器因此反复停起线程（futex）约 30%，真正处理报文的主循环只占 12%，批量送主循环也就没有效果。换成环以后，TCP 大流量下剩下的开销是解码时的负载复制（memmove 15%）和它带来的 GC（约 25%），于是让负载直接引用环内存，主循环处理完一批再把块还给内核。环整帧拷贝时，64 KiB 的 GSO 帧在转发报文的软中断里整帧拷进环，TCP 吞吐降到 17.1 Gbps 并开始丢包；截到解析器会读的 16 KiB 后恢复。环从 8 MiB 缩到 4 MiB 后又丢了包，原因是主循环每 10 秒同步扫描一次所有进程的 fd，本机 6,400 个描述符要 30 ms，而 4 MiB 在 20 Gbps 下只够约 6 ms；扫描移到后台后两轮都是 0。改成环后，快照结束时的统计里还出现过几十到上百个丢包，运行中每秒读取的统计却始终为 0：退出时读取方先停下，探针卸载要几秒，这期间填满的环让内核把之后的报文记为丢包。现在读取方停止时把过滤器改成全部丢弃，lo、br0 上重跑都是 0。

录制：iperf3 以 2 Gbps 运行时，在 PTY 里按 `2`、`/5201`、`Enter`、`c` 录制这条连接，文件达到 64 MiB 上限时自动停止，共 2,827 个包，最大帧 65,226 B，说明录制期间环保留了完整帧。按 `c` 时已在环里的 8 帧只有 16,640 B。第一版把这类帧的原始长度也写成捕获长度，tcpdump 报 `truncated-ip`；现在 EPB 记下线上的原始长度，读取工具会把它们显示为截断帧，报文注释也标出 `captured_frame_truncated=true`。完整帧的上限同时从 256 KiB 改为 64 KiB，与 PCAPNG 接口块声明的抓包长度一致，否则更大的 BIG TCP 帧会让写入器报错并中止录制。

其他回归：lo 上的 HTTP 请求，Host `lo.example.test` 和两端 PID（curl、python3）与之前一致；抓包接口被删除时，程序报 `capture on stdum0: network is down` 并以 1 退出，与原实现一致。最初的环实现在这里会因为 poll 一直返回 POLLERR 而空转，已修正。

界面走查：在 50 行 × 200 列的 PTY 里无参数启动，自动选中包括两张实验 veth 在内的 8 个接口。在长稳负载运行中依次按 `d`、`/cert`、`Enter`、`/gRPC`、`Enter`、`2`、`4`、`!`，结果如下：

- 域名页有 `TLS lab.internal.test [cert]`、`HTTP/2 10.99.2.2`、`HTTP 10.99.9.9` 等行。
- 选中 `[cert]` 行的连接后，EVIDENCE 为 `ALPN offered h2,http/1.1; server chose TLS 1.2; name from the server certificate, not SNI: lab.internal.test,*.lab.internal.test; SNAT 10.99.1.2:33476 as 10.99.2.1:33476`。
- 来源页有 `10.99.1.2  tried 41 ports: refused 82, unanswered 0`，同时列出两个真实的公网来源，分别被拒 6 次和 74 次。
- 状态页有 `NAT lookups 1567  NAT'd 539  queue full 0  failed 0`，AF_PACKET dropped 0。
- 按 `q` 后退出码为 0。

走查中发现并修正了两处：一是合并后的转发连接方向原来显示为 `unknown`（两侧分别是 inbound 和 outbound），现在为 `forwarded`；二是 `tried 1 ports` 的单复数。另外，个别连接在 conntrack 结果回来之前会短暂显示为两行，下一次刷新即合并。

长稳：在 50 × 200 的 PTY 里无参数运行界面 60.6 分钟，自动选中 8 个接口。所用版本不含之后改的三处小问题：接口删除后空转、PCAPNG 原始长度、`forwarded` 方向。负载脚本每轮从主机发一个经 OUTPUT DNAT 的请求，从 stcli 发 HTTP、TLS 1.2、h2c 三个经 SNAT 的请求，每 60 轮从 stcli 扫一次主机的 41 个关闭端口。一小时共 16,802 轮，约 6.7 万个连接、约 280 次扫描，另有主机本身的真实流量。每 10 秒采样一次：

- CPU 平均 8.3%，峰值 14%。
- RSS 启动时 98 MiB，6 分钟内升到约 175 MiB，因为流表、DNS 提示和 NAT 表按 1 到 10 分钟的有效期逐步填满；此后在 175 到 185 MiB 之间波动，结束时 173 MiB。其中 32 MiB 是 8 个抓包环，约 18 MiB 是 eBPF map，其余主要是 Go 堆。
- 同负载下另起一个带 `GODEBUG=gctrace=1` 的 15 分钟快照，GC 后的存活堆在第 4 分钟后稳定在 44 到 49 MB，堆目标约是它的两倍，没有持续增长。
- 退出码为 0。

最终画面顶部带 `INCOMPLETE`。这个标记在任一采集计数非零、或当前有解析失败的连接时出现，长稳实例退出后已读不到是哪一项。同负载下，15 分钟快照的 AF_PACKET 丢包为 0（交付 802,184 个包）；另跑的 6 分钟界面会话里，丢包、截断、流索引淘汰、PID 事件丢失、解析失败都是 0。所以更可能是主机真实流量里某条连接解析失败，但这一点没有证实。长稳期间，同一主机上还跑了虚拟机矩阵、界面走查和 iperf3 录制测试，它们的流量也被长稳实例抓到了。

## 2026-09-24 终端安全与退出

- 进程名：一个非特权进程用 `prctl(PR_SET_NAME)` 把名字设为 `\x1b[7mEVIL\x1b[0m`，建立一条回环连接。修复前，`--duration` 快照的连接行和 PID 汇总各带一处原样的 ESC 序列，在终端里会被执行；修复后输出中没有 ESC 字节，名字显示为 `?[7mEVIL?[0m`。PID 探针、socket 层读取、OpenSSL 探针和 `/proc/<pid>/comm` 四个来源改用同一个过滤函数，单元测试覆盖 C0 控制字符、8 位 CSI（U+009B）、双向排版控制符（U+202E）、非法 UTF-8 和 NUL 之后的内容。
- 过滤：单元测试确认过滤框可以输入 `quic`，`Ctrl-C` 仍然退出；主表、帮助、状态页按 `q` 仍是一次退出。
- 挂断：在 PTY 里运行界面，探针就绪后关闭 PTY 主端，程序 2.3 秒后退出，没有残留进程。此前一次长稳测试里，PTY 关闭后程序一直运行，那次是用 `nohup` 启动的，子进程继承了被忽略的 SIGHUP，不代表正常挂断时的行为。现在挂断信号会走正常退出流程，输入读到 EOF 或出错也会退出；SIGHUP 在启动时就被忽略的（`nohup`）保持忽略。

## 2026-09-24 路线图补充

本轮实现了路线图里的内核重传计数、kTLS 字节、DNS 时延、`INCOMPLETE` 分项、h2c 升级、TLS 服务端乱序、JSON 快照、预触发录制、每条流的内存、arm64、CI 和发布来源证明。`go vet ./...`、`go test -race ./...` 通过；本机 6.8 上 probe、sockstream、capture、conntrack 的测试以 root 全部通过，其中 probe 包 5 项、sockstream 包 2 项。

### 内核矩阵

虚拟机工具已放进仓库的 `test/vm/`：`run.sh` 按 [kernels.txt](../../test/vm/kernels.txt) 下载发行版内核（Debian/Ubuntu 取 Packages 索引里最新的包，CentOS Stream 在对应镜像里用 dnf 下载），把 socktrail、四个包的 root 测试、Debian 12 的 openssl 客户端和一个 Go init 打进 initramfs，在 QEMU 里启动，按 init 打印的 `VM-RESULT` 行判定。amd64 有 KVM 时每个内核约 20 秒；arm64 在 x86 宿主上用 TCG 模拟，每个内核约 8 分钟。

| 内核 | 结果 |
| --- | --- |
| amd64：Debian 11 5.10，Ubuntu 5.11、5.13、5.15、6.8、6.17、7.0，CentOS Stream 9 5.14、10 6.12 | 各 16 项通过、3 项跳过；回环快照 8 条流，AF_PACKET 丢包 0，OpenSSL SNI 事件 2 个 |
| arm64：mainline 6.4、Ubuntu 6.8 | 同上，OpenSSL 探针按 arm64 寄存器读参数，PID 与 SNI 都对 |
| arm64：Debian 12 6.1、Ubuntu 6.2、mainline 6.3 | 挂载 fentry/fexit 报 `create raw tracepoint: not supported`；arm64 的 ftrace 直接调用在 6.4 合入，所以 6.4 是 arm64 的最低版本，程序报错时提示这一点 |

跳过的 3 项是重传与 DNAT 测试（镜像里没有 nft）和 kTLS 测试（镜像里没有 tls 模块），这三项在本机和 CI runner 上运行。

arm64 上 sockstream 的测试起初失败两项，查下来都是测试本身的问题。一是它按“内核地址高于 `0xffff800000000000`”区分地址和 cookie，arm64 的内核地址从 `0xffff000000000000` 开始，改为看最高位。二是接收方向总差几个数据块：带时间戳复测，全部读调用 56 ms 内完成，数据块却每 0.5 秒才被消费一个，原因是测试对每个块都调用一次 cookie 支持探测，它要加载一个 BPF 程序，在 TCG 下将近一秒；产品代码只在启动时探测一次。改为只探测一次后两项通过。排查中用单线程 TCG 排除了多线程 TCG 内存序的影响。

### 重传、kTLS 与 DNS 时延

- 重传：root 测试在私有网络命名空间里用 nft 按比例丢包，传 1 MiB，探针报告的最大值与 `TCP_INFO` 的 `total_retrans` 相等；另一项让 SYN 连不上的端口重传两次以上，数值同样相等。起初少计一次，原因是尾部丢失探测直接调用 `__tcp_retransmit_skb`，补挂 `tcp_send_loss_probe` 后一致。端到端：veth 上加 `netem delay 20ms loss 3%`，从主机向实验命名空间发 6 MiB 后保持连接，`ss -ti` 显示 `retrans:0/127`，socktrail 的 JSON 快照为 `retransmits=127`、来源 `kernel`。
- kTLS：root 测试给回环连接设 `TCP_ULP tls` 和 AES-GCM 密钥（发送端 TLS_TX，接收端 TLS_RX），两个方向各 64 KiB，探针计到的字节与写入的一致。本机 openssl 3.0.13 没有启用 kTLS，没有用 `s_server` 做端到端验证。
- DNS 时延：实验命名空间里的应答程序出口加 `netem delay 50ms`，主机用 dig 查询 3 次，dig 显示 49 ms，socktrail 显示 `rtt=50.1ms`。时延加在主机一侧出口时 socktrail 显示约 100 µs：AF_PACKET 在报文经过本机 qdisc 之后才抓到它，本机排队不在测量范围内，文档已写明。

### 真实服务的协议标签

用 docker `--network host` 在本机运行各服务，流量走 lo，用各自的客户端发请求，socktrail 抓 lo 做 JSON 快照：

| 服务与客户端 | APP | 进程 |
| --- | --- | --- |
| apache/kafka，kafka-topics.sh | Kafka | kafka-admin-cli → data-plane-kafka |
| rabbitmq:3，Python pika | AMQP | python3 → erts_sched |
| nats，nc 和 Python nats-py | NATS | nc、python3 → nats-server |
| zookeeper:3.9，zkCli.sh | ZooKeeper | main-SendThread → NIOServerCxnFactory |
| memcached，nc 和 pymemcache | Memcached | nc、python3 → memcached |
| mssql/server:2022，sqlcmd | SQL Server | sqlcmd → sqlservr |
| cassandra:5，cqlsh | Cassandra | python3 → epollEventLoopGroup |
| osixia/openldap，ldapsearch | LDAP | ldapsearch → slapd |
| MIT krb5 KDC，kinit 走 TCP 和 UDP | Kerberos | kinit → krb5kdc |
| grpc-go helloworld，同一连接 5 次调用 | gRPC，`HTTP/2 localhost`，请求数 5 | grpc-client → grpc-server |

第一次运行发现并修正了四个问题：

- NATS 客户端先发 `CONNECT {...}`，被当成 HTTP CONNECT，标签是 HTTP 且记为解析失败。现在 HTTP 请求行要求目标像路径、URI 或 authority。
- memcached 的 `stats\r\n` 没被识别：命令按空格切分，不带参数的命令后面没有空格。
- sqlcmd 的连接显示成 `PROXY 0.0.1.0`：socket 层把服务端 TDS pre-login 应答（`04 01 00 30 …`，结构上是一个 SOCKS4 CONNECT 请求）当成了客户端字节。现在发起方已知时只采用来自客户端的字节。
- nc 发的 13 字节 memcached 命令和 Cassandra 9 字节的 OPTIONS 帧不足以分辨协议，30 秒后被记成解析超时。现在归为其他协议。

修正后复测，全部标签正确，解析失败 0。Oracle TNS 和 NFS 没有用真实服务验证。

### 抓包与事件的开销

在主机和实验命名空间之间的 veth 上用 iperf3 加压，socktrail 只抓主机一侧，CPU 为 socktrail 进程的平均占用（1.00 为一个核），6 核 Ryzen 5 6600H：

| 负载 | 报文率 | 原实现 | PID 事件直接读取 | 事件批量唤醒 |
| --- | --- | --- | --- | --- |
| TCP 单流 | 约 19 万/s | 0.72 | 0.65 | 0.29 |
| TCP 4 流 | 约 60 万/s | 1.38，丢包 0.6% | 1.20，丢包 0.4% | 0.92，丢包 1.2% |
| UDP 64 B 单流 | 约 15 万/s | 1.46 | 1.45 | 0.32 |
| UDP 64 B 4 流 | 约 48 万/s | 1.88 | 1.57 | 1.05 |

perf 显示原实现的 CPU 大半花在调度上：PID 探针每个事件都唤醒一次 ring buffer 的读取协程，再经 channel 唤醒主循环，futex、epoll 和 Go 调度器占了六成，事件处理本身只有一成；另有一成是 `encoding/binary` 反射解码。改为 ring 积压 512 KiB 才唤醒、读取方每 100 ms 兜底读一次，事件按块交给主循环后，四档负载的 CPU 降到原来的 22% 到 67%。中途一版仍逐个事件送主循环，批量到达的事件把 2,048 个槽位的 channel 撑满，丢了四成事件，所以改成按块传递；最终各档负载下 PID 事件丢失都是 0。

TCP 4 流的丢包不是主循环跟不上：此时 socktrail 用了不到一个核。每个 GSO 帧截到 16 KiB 后占环里 16.6 KB，4 MiB 的环只放得下约 240 帧，60 万帧/秒下缓冲不到 0.5 ms。临时把环改成 16 MiB，两轮丢包分别是 2,168 和 1。现在各接口的环共分 16 MiB、每个至少 4 MiB，单接口复测丢包 0.13%。多队列的 `PACKET_FANOUT` 因此没有实现。

### 内存与 GC

基准测试构造 1 万条完成 TLS 握手的流，GC 后的存活堆从每条 2,149 B 降到 1,541 B：流结构里只有 DNS、ICMP 流用到的状态改为指针（流结构从 1,152 B 的分配规格降到 768 B），流解析器的 HTTP/2 状态和两个 map 改为按需分配，整机视图每秒重建时不再给每条流新建空 map。

GC 目标用最耗内存的场景评估：界面在 PTY 里运行 3 分钟，只抓一个 veth，每秒 300 条短连接，流表常驻约 1.8 万条已关闭的流。

| 设置 | RSS 峰值 | RSS 平均 | CPU |
| --- | --- | --- | --- |
| 默认（GOGC=100） | 257 MiB | 213 MiB | 0.21 |
| GOGC=50 | 204 MiB | 174 MiB | 0.25 |
| GOMEMLIMIT=64MiB | 152 MiB | 137 MiB | 6.68 |

GOGC=50 用多 18% 的 CPU 换少 18% 的 RSS，没有设为默认，需要时可自行设置环境变量；内存上限低于存活堆时 GC 不停运行，占满了 Go 允许 GC 使用的一半 CPU，不能固定写进程序。

### 其他场景

- PID 复用：一个进程发 1,000 B 后退出，写 `ns_last_pid` 让下一个 fork 拿到同一个 PID，它再发 2,000 B。快照里两个身份分开：同一 PID、启动时间相差 0.51 秒，各自的连接和字节正确。
- fd 传递：建立连接的进程写 1,000 B 后用 `SCM_RIGHTS` 把 socket 传给另一个进程，后者写 2,000 B。两个进程的 socket TX 分别是 1,000 B 和 2,000 B，服务端 RX 3,000 B；连接的发起方仍是建立连接的进程。
- 网桥：两个命名空间接在主机网桥的两个端口上，互相访问。网桥设备本身看不到这些桥接流量（socktrail 不开混杂模式）；端口上能看到 HTTP（Host 正确）、ICMP 和 ARP，没有进程，方向按该端口的收发显示为 inbound。
- 预触发录制：`--record-before 10s` 下，一个进程每 200 ms 在一条连接上写一行，约 9 秒后在界面里过滤出它的 PID 并按 `c`，3 秒后停止。文件共 131 个包，按键前的 101 个从这条连接的 SYN 开始，tcpdump 能读。
- JSON 快照：与文本快照同一份数据，单元测试核对字段名；本机、真实服务和实验网络的验证都用它取数。
- h2c 升级和 TLS 服务端乱序：单元测试覆盖升级成功与被拒两种情况，以及服务端第 2、3 个报文交换顺序后仍取到证书名。
- 安装脚本：从固定的 release tag 下载，v0.0.1 路径实测可用；来源证明要到下一个版本才有，`gh attestation verify` 分支尚未实际运行。

### CI

推送本轮提交后的第一次运行全部通过：Check 的格式与测试、BPF 对象一致性，以及 `ubuntu-24.04` 和 `ubuntu-24.04-arm` 两种 runner 上的 root 测试和冒烟快照（arm64 runner 是实机，这是 socktrail 第一次在 arm64 实机上运行）；Kernels 的 amd64 作业用 KVM 约 5 分钟跑完 9 个内核，arm64 作业在模拟器里约 6 分钟跑完 2 个内核，都含下载和打包 initramfs 的时间。

## 2026-09-25 进程过滤、服务分组与内核 TCP 状态

本轮新增 `--process`、`--pid`、`--cgroup` 过滤，服务页（按服务、cgroup、进程树分组），以及每条本机 TCP 连接的内核 RTT、拥塞窗口和重传。`go vet ./...`、`go test ./...` 通过；本机 6.8 上 probe 包的 5 项 root 测试通过，其中 socket 事件测试新增两项检查：TCP 收发事件带非零的 RTT、拥塞窗口和已发送段数；connect 事件的父进程等于测试进程的父进程，cgroup ID 等于测试进程所在 cgroup 目录的 inode（没有挂载 cgroup v2 的虚拟机里只要求非零）。

单元测试用临时目录伪造 `/proc`，覆盖：
- 进程表从 `/proc` 补齐不碰网络的祖先（bash、脚本）。
- 中间的脚本退出后，`--pid <bash>` 仍然选中 curl。
- 同一 cgroup 里已退出的进程按 cgroup ID 取到路径。
- 按服务、cgroup、进程树分组，以及进程树的排序和缩进。
- 进程名的 15 字节截断、通配符，cgroup 的路径前缀与目录名通配。
- 服务名推导（容器 ID 缩到 12 位），cgroup 文件的 v2、混合模式和仅 v1 三种格式。
- 服务页的分组和字节汇总，以及过滤后的 PID 页和快照。

本机验证：
- `--process curl --output json`：同时有 curl 和一个 Python 客户端访问本机 HTTP 服务，结果只有 curl 这条连接（client 为 curl，server 为 python3，RTT 38 µs，来源 kernel）、curl 进程（带父进程和所在的会话 scope）和这个 scope 的服务汇总，Python 客户端不出现。
- `--pid <bash>`：bash 延时后启动 curl，结果只有这个子进程的连接，连接的 client 为 curl，其父进程是这个 bash。
- 在 PTY 里按 `5`、连按三次 `g`、再按 `Enter` 和 `Tab`，界面依次显示按服务、cgroup、进程树分组，最后回到服务分组，进程标签页有 `PPID` 列和 `CGROUP` 行，退出码为 0。
- 本机的服务页列出 zerotier-one.service、tailscaled.service、dae.service、会话 scope、`docker-e5ed6df559c6.scope` 等；进程树页以 sshd、dockerd、nginx 主进程、zellij 等为根。

发现并修正了一个回归：上一轮把 PID 事件改为批量唤醒后，事件最多晚 100 ms 到达。像 curl 这样的短连接，报文（握手到双方 FIN）常在同一个抓包块里处理完，connect 和收发事件到达时连接已经关闭，而此前关闭的连接不再接收事件，于是这类连接两端都没有进程。上一轮的冒烟测试只查了 OpenSSL 的 PID 和 Host，PID 复用和 fd 传递实验里的连接又都活了半秒以上，所以没有发现。现在关闭后 2 秒内的连接仍接收自己的事件；新增的单元测试让事件在连接关闭之后到达，修正后本机的 curl 连接两端进程都在。

查看 dockerd 的进程树时又发现一处统计错误：快照和文本报告里服务汇总的连接数只统计第一个抓包接口（本机为 br0）上的连接，界面的服务页不受影响。docker-proxy 的连接走 `lo`，所以 docker.service 有 socket 字节，连接数却是 0。现在按合并了所有接口的整机连接计数。修正后 `--pid <dockerd>` 的快照里，docker.service 为 4 个进程、4 条连接，与以 docker-proxy 为一端的 4 条连接一致。同样的过滤下，界面的进程树页只剩 dockerd 一行，`process` 标签页以 dockerd 为根，下面缩进列出有流量的 docker-proxy 子进程。

底栏的连接表和进程表随后改为按内容定宽。服务页的连接表新增第一列 `I/O PID`，连接详情里各进程的 socket 收发行也带上进程名。在 200 列的 PTY 里：
- SSH 会话那棵进程树的连接行宽 168 列，`ORIGIN PID` 和 `TARGET PID` 不用横向滚动就能看到。
- 这条连接的 `TARGET PID` 是接受连接的父进程 3027445(sshd)，`I/O PID` 是实际收发的子进程 3027544(sshd)。
- dockerd 那棵树里，dockerd 自己发出的 DNS 查询和各个 docker-proxy 的连接各自标明了进程。

单元测试确认这一列只列出组内的进程，不包括另一个服务里的对端。

按内容定宽要在每次重绘时格式化所选分组的每条连接。基准测试用 2 万条连接的分组：
- 最初的实现在服务页每次重绘约 25 ms，分配 16 MB。原来固定最小宽度的布局约 5 ms。
- 改为复用单元格切片，字节数和 `PID(进程名)` 改用 strconv 拼接（输出不变）之后，服务页约 14 ms、2 MB，PID 页约 10 ms。
- 同样 2 万条连接时，主表按 PID 分组约 9 ms。

2 千条连接以内的分组，列宽计算约 1 ms。

随后给界面加了配色。检查方法和结果：
- 在 190×44 的 PTY 里截取了 PID 页、服务页（焦点在连接表）、进程标签页、网卡页和帮助页的实际输出，分别按 One Dark 和 One Light 两套主题渲染成图片检查。
- 高亮条在两种主题下都清楚：深色主题下是青底深色字，浅色主题下是深青底浅色字。黄色、绿色、洋红和变暗的文字也都可读。
- 设置 `NO_COLOR` 后，程序名、当前页和选中行改用反色，零值和时间仍然变暗。
- 在屏幕上点击 `5 SVC` 和 `process` 标签所在的位置，分别切到服务页和进程标签，说明鼠标定位和显示的文字一致。
- 单元测试确认：着色并横向滚动后，可见文字不变；焦点表格的选中行铺满整行；各种连接状态的颜色正确。测试在设置 `NO_COLOR` 时同样通过。
- 2 万条连接的列宽计算耗时和配色前相同。

顶栏原来把范围键 `a OVERVIEW` 和页面键排在一起。启动时本来就在合并视图的 PID 页，按 `a` 和按 `1` 都看不出变化，看起来像同一类按键。合并视图下 `a` 本身不起作用却一直显示，真正能进入单网卡视图的 `i` 反而被隐藏了。

现在页面键和范围键用竖线隔开，范围键只列出当前有效的。另外，从合并视图按 `i` 原来会跳过当前网卡，现在先打开当前网卡。PTY 里的验证：
- 依次点击顶栏上显示的 `i per interface`、`i next interface`、`a overview`，范围分别变为 br0 (1/6)、dae0 (2/6) 和 OVERVIEW。
- 单元测试确认从合并视图按 `i` 打开的是当前网卡。

接着统一了底栏连接表的列：
- 各页都依次是 `I/O PID`、`IFACE`、`DIR`…`RETX`、`PID RX`、`PID TX`、`ORIGIN PID`、`TARGET PID`、`FIRST`、`LAST`。
- `I/O PID` 和 `PID RX`/`PID TX` 描述所选行的进程：PID 页是选中的进程，服务页是组内进程，其他页是所有进程。

网卡名的实现：
- 每条连接新增一个 8 位位图，采集接口最多 8 个。
- 位图放在结构体原有的对齐空隙里，flow 仍是 760 字节。
- 整机视图合并时取各份观测的并集。

验证：
- 单元测试覆盖四种页面下 `I/O PID` 的取值，以及合并后 br0 和 eno1 两张网卡都在。
- JSON 快照里每条连接都带 `interfaces`。本机大多数连接是 `br0,eno1`：eno1 挂在网桥 br0 下，同一个报文在两处各抓到一次。
- 文本报告多了 `IFACE` 列。
- 在 200 列的 PTY 里，PID 页和协议页的连接表列一致，主表也有 `IFACE` 列。

内存：连接记录两端的内核 TCP 状态多了 64 B，ARP 和 SSH 两端版本改为按需分配后，每条完成握手的 TLS 流仍是 1,541 B 存活堆。

新的事件字段要读 `task_struct` 的 `real_parent`、`tgid`，调用 `bpf_get_current_cgroup_id`，并读 `tcp_sock` 的 `srtt_us`、`mdev_us`、`snd_cwnd`、`data_segs_out`。内核矩阵的 11 个内核（amd64 的 5.10 到 7.0 及 CentOS Stream 9、10，arm64 的 6.4 和 6.8）全部通过，各 16 项测试通过、3 项按预期跳过。

## 尚未完成的验收

以下是记录时尚未完成的验收，后续状态以当前代码和[数据口径](../user/measurement.md)为准。

- 容器网络，以及非当前网络命名空间的 PID 与方向：探针只统计当前网络命名空间的 socket，其他命名空间的流量只有报文。桥接只验证了抓网桥端口的情况，同时抓两个端口时整机页按规则会合成一条 `forwarded` 连接，没有实测。NAT 只在本机网络命名空间搭的网关上验收了 SNAT、DNAT 和本机 OUTPUT DNAT；conntrack zone 非 0 的条目（部分 OVS、CNI 场景）查不到。“精确整机 IP 总量”未实现。`lo` 只数发送副本，IP RX/TX 不等于本机两端 socket 各自的字节。
- `sendfile`、splice 和内核 TLS 的计数由 root 测试核对；io_uring 的零拷贝发送等其他路径没有验证，PID 应用字节只承诺已挂探针的返回值。
- 探针挂载前已经进入阻塞 `recvfrom` 的 UDP 服务，首次返回可能少计；服务进程在探针之后启动的对照场景两端各为 RX/TX 5 B。启动时抓取的中途连接和调用不能补历史数据。Linux 6.8 以前的内核没有 `__inet_accept`，回退到 `inet_csk_accept` 的 fexit 已在 5.10 至 5.15 上加载并收到 accept 事件，但挂载前就阻塞着的第一次 accept 仍会漏掉，只能靠 socket 表补上仍存在的连接。
- 内核 socket 表只覆盖当前网络命名空间，每 10 秒最多在后台读一次，两次读取之间开始又结束的连接拿不到。
- 其他内核只在虚拟机里验证了回环流量；arm64 实机只有 CI 的 GitHub arm64 runner（root 测试和冒烟快照），没有带真实负载运行过；RHEL 系只测了 CentOS Stream 9、10。
- UDP 的 socket 层读取只读发出的 QUIC 长包头，DNS 应答仍只靠报文；QUIC Initial 的 socket 层读取只有 root 单元测试，尚未用真实本机 QUIC 客户端在透明代理下验收。
- 抓包性能只在 veth 上测过（每秒约 60 万个 TCP 帧、48 万个 64 B UDP 报文），物理网卡、多队列 RSS、百万级 pps 没有测；长稳运行只做了 1 小时。另外还缺物理网卡上的 GSO/GRO、首片丢失的 IP 分片、丢包后的重组恢复，以及真实 ECH 与浏览器 GREASE ECH 流量。`lo` 上的 TSO 截断、无 SYN 的 ClientHello 和 veth 上的 IPv4/IPv6 分片已有受控样本或单元测试，但不代表这些场景都已验收。
- ICMP 只有 Echo 请求能归属进程：带 `IP_HDRINCL` 的原始 socket 自己拼 IP 头，其中的 ICMP 不识别；Echo 以外的 ICMP 与其他协议的原始 socket 流量没有进程。tun 接口帧的录制只在单元测试里经 tcpdump 解码，没有在真实 tun 接口上经 TUI 录制并用 Wireshark 核对；跨接口非对称路径的 PCAPNG 导出也没有核对。
- QUIC v2 目前只有 RFC 官方加密向量，没有本机真实 v2 客户端；QUIC v1 已完成本机真实握手样本。QUIC 长连接同五元组重用、极限乱序/丢包、真实 ECH 和 HTTP/3 加密的 `:authority` 尚未验收或实现。经 HTTP/1.1 `Upgrade: h2c` 升级的连接只有单元测试，没有真实客户端样本。
- OpenSSL 进程探针目前仅覆盖系统动态库及已验证的 fd 或同线程 `SSL_connect`/TCP 发送关联路径；其他自定义 BIO 路径、Go TLS、静态链接 TLS、其他 TLS 库与解密后 HTTP/2/3 请求域名未覆盖。正常抓到 ClientHello 时，进程 SNI 通常与报文 SNI 重合，不能保证“所有 HTTPS 域名”。
- TLS 服务端首批报文的乱序只有单元测试；证书名只用 openssl 自签名证书和 Go 生成的证书验证过，没有覆盖多值 RDN、超长证书链或非 DNS 形式的 SAN。Oracle TNS 和 NFS/RPC 的识别只有构造报文的单元测试。
- 发布来源证明要到 v0.0.1 之后的第一个版本才会生成，安装脚本里 `gh attestation verify` 的分支还没有实际运行过。

IP、协议、域名界面及连接报告的字节取捕获 IP 报文长度；整机页对每条逻辑流只选一个采集点，不能当作精确整机 IP 总量。PID 页和报告末尾的 PID 汇总取 eBPF socket 事件的应用读写字节，两者不相加。`AF_PACKET delivered` 是内核交付给抓包 socket 的数量，包含后来因 `lo` 去重、非 IP 或解析条件而未计入的报文，不能直接与 `IP packets` 相减来当作丢包数。测试用服务为临时进程，不作为程序的一部分。
