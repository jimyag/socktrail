# 数据口径与限制

从 [中文首页](../../README.zh-CN.md) 进入。读数字前先区分报文 IP 字节、进程 socket I/O 和域名证据；这些量不能直接相加。

## IP 字节与整机视图

IP 流的字节是 **IP 层报文长度**，包括 IP/传输层头部与观察到的重传，不含链路层头；ARP 等非 IP 帧记录以太网负载长度。整机页对相同五元组的同一代连接只取一个采集点的观测字节，不把网卡计数直接相加；conntrack 关联上的 NAT 两侧也只算一份；代理或隧道改写地址后仍可能出现多个观测流，所以这些字节不构成精确整机总量。按 `0` 可查看逐网卡原始计数。

## 进程 socket RX/TX

PID 页的 RX/TX 是当前网络命名空间内 TCP/UDP `sendmsg`/`recvmsg` 返回的**应用 socket I/O 字节**，可按执行 I/O 的 PID 加进程启动时间汇总；它不受所选接口或 `--port` 限制，不与 IP 报文字节相加。连接详情只在五元组匹配时显示该 PID 的 socket I/O。PID 连续 5 分钟没有新 I/O 后，明细回收，累计字节保留在过期汇总行。探针丢事件、没有匹配流或走未覆盖的 socket 路径时，PID/连接明细可能不完整；状态页展示丢失和未关联到所选流的字节。

启动前已经进入阻塞读调用的进程，其第一次调用返回也可能不被新挂载的 fexit 探针计到。accept 在 Linux 6.8 起改由 `__inet_accept` 观测，这个函数在等到连接之后才调用，所以启动前就阻塞在 `accept()` 里的服务也能拿到第一条连接；更早的内核用 `inet_csk_accept` 的 fexit，会漏掉这一次，仍然存在的连接再由 socket 表补上。

## loopback 方向

`lo` 只保留 AF_PACKET 的发送副本，避免本机同一包重复计数。因此它的 RX/TX 是抓包方向，通常显示 TX；不表示本机客户端与服务端各自的收发量。

## 连接方向

TCP 来源/目标按 SYN 或已关联的 connect/accept 确定。没看到建立过程时，发出 ClientHello 或 HTTP 请求行的一端是客户端；本机连接再查内核 socket 表：本地端口上有监听 socket，或本地地址不属于本机（透明代理接受的连接）时为入站，否则为出站。方向不按端口号猜测，都判断不了时详情列出两个带 `?` 的观测端点。UDP 和其他 IP 协议的来源/目标是首次观测报文的端点，ICMP Echo 以首个请求的发送方为发起方。UDP 两端 PID 按本机 socket 所在端点记录，不因服务端回包而交换。

TCP 显示 SYN、established、closing、closed、reset 或 midstream 观察状态；同五元组的新 SYN 建立新代次。不能可靠关联的 PID 显示未知或有歧义。

整机合并视图为连接分配运行期间稳定的 ID。TCP 关闭后等待 2 秒接收晚到的进程事件，再把最后一份合并记录放入最多 5000 条的内存历史；连接从采集表消失时，也会以 `idle` 或 `evicted` 记录。历史目前只供后续实时事件功能使用，快照 `flows[]` 仍只列采集表中的连接。历史满时最早的记录被覆盖，程序退出后不持久化。

## RTT 与 RETX

`RTT` 有两种来源，连接详情在数字后标明：

- `kernel`：连接有本机 socket 时，取内核 `tcp_sock` 的平滑 RTT，也就是 `ss -ti` 的 `rtt`，每次收发都更新，抓包开始前建立的连接也有。回环上两端都在本机时取发起方的。
- `SYN`：其他连接用抓到的握手时差，只对看到本机发出 SYN、收到匹配 SYN-ACK 的 TCP 连接给出一次样本；入站、转发或中途开始时为 `-`。

连接详情的 `TCP` 行列出每个本机端 socket 的内核状态：`rtt 3ms±1ms`（平滑 RTT 与平均偏差）、`cwnd`（拥塞窗口，单位是报文段）、`sent`（已发送的数据段）和 `retrans`（重传段数及占已发送的比例）。这些是事件发生时的快照：连接没有收发时不再更新。

`RETX` 有两种来源，连接详情在数字后标明：

- `kernel`：连接有本机 socket（任一端有 PID，或收到过重传事件）时，取内核 `tcp_sock` 里的累计重传数，与 `ss -ti` 的 `retrans` 总数一致，包括 SYN 重传和尾部丢失探测。回环上两端都在本机，两个 socket 的重传相加。
- `capture`：转发或采集点之外的连接，统计本采集点观察到的重复 SYN 和已保存序号区间重叠的 TCP 数据段，是推断值；每方向最多保留 128 个区间，丢包、乱序、序号回绕或多接口合并会影响判定。

两列是网络诊断提示，不与报文字节另行相加。DNS 流另有应答时延，见[解析原理](../internals/parsing.md#dns-与-ssh)；它和握手时差一样是采集点之后的往返，本机出口排队的时间不在其中。

## HTTP Host 与 TLS SNI

HTTP/1.1 `Host` 统计已完整观察的请求数。同一 TCP 连接出现多个 Host 时，连接字节归入 `multiple Hosts` 一组，不按请求拆分。TCP/QUIC/进程侧的 TLS `SNI` 是连接级域名证据，只统计连接与流量，不推断 HTTPS 请求数。入站 Host/SNI 指被访问的服务名，不是客户端来源域名。

PROXY protocol v2 的 AUTHORITY 来自转发代理提供的头部；只有没有 SNI 或 HTTP Host 时才用于连接命名。它代表代理声称的原始访问域名，可信程度取决于代理配置。

STARTTLS 等协议升级后，若抓到 ClientHello，SNI 仍来自客户端握手；`evidence.upgrade` 标明 SMTP、IMAP、POP3、FTP、XMPP、LDAP、PostgreSQL 或 MySQL 的升级路径。升级前的明文命令不作为域名证据。

加密 DNS 的 `evidence.encrypted_dns` 是端口或服务名推断：TCP 853 为 DoT，UDP 853 为 DoQ；443 端口的 SNI 或 DNS 提示命中内置 DoH 服务名时为 DoH，`--doh-list name1,name2` 可补充服务名。它不表示 socktrail 能读取加密的查询内容。

DNS 流详情保留最近 8 次查询，显示名字、类型、应答码、最多 4 个应答地址、RTT 和时间；JSON 连接记录的 `dns` 字段提供同样的结构化历史，原有 `detail` 字符串仍保留。要把应用查询本机 stub resolver 的 DNS 流归到该应用，需要采集 `lo`；自动选择接口时默认包含它。

## 入站连接尝试

入站的连接尝试按来源汇总：被拒绝（目标回 RST，或 UDP 目标回端口不可达）和没有应答（只有 SYN 或单向的一两个 UDP 报文）的尝试计数，并记下尝试过的端口（最多 1024 个）。来源 IP 页在该来源的行上显示 `tried N ports: refused …, unanswered …`；流表满时先批量淘汰这类一次性的流（每次最旧的 10%），扫描不会挤掉正常连接，被淘汰的流仍留在汇总里。汇总 10 分钟没有新尝试后删除。

## 丢失、索引淘汰与未覆盖路径

任何一项缺失计数非零时，顶部标出 `INCOMPLETE` 并列出非零的项和数量，例如 `INCOMPLETE drop=12 parse=1`：

| 项 | 含义 |
| --- | --- |
| `drop` | AF_PACKET 环满时内核丢掉的报文 |
| `trunc` | IP 报文比抓到的帧长，负载没抓全 |
| `flow-index` | 流表满时没能建流的报文 |
| `pid-index` | 连接角色索引满时丢掉的 connect/accept/UDP 端点记录 |
| `pid-lost` | PID 事件在内核 ring 里丢失，或主循环跟不上被整批丢弃 |
| `io-unindexed` | 进程索引满时没能按进程记下的 socket I/O 字节 |
| `sniff-lost` | socket 层读取的数据块丢失 |
| `parse` | 当前解析失败的连接数 |

快照的 `capture status` 行给出同样的计数，`!` 状态页有更细的分项。GSO/GRO、首片丢失的 IP 分片、桥接、未被 conntrack 关联的地址改写、抓包缺口和高负载可能影响报文与进程归属；整机页 IP 数字只代表选定采集点的观测结果。

PID 事件最多晚 100 ms 到达主循环（见[实现原理](../internals/architecture.md#pid-探针)），socket I/O 和进程关联在界面上可能比报文晚一次刷新。

`sendfile` 和 splice 的字节计入 PID socket I/O：6.5 之前的内核里，写往 socket 的 splice 走 `generic_splice_sendpage`，另挂探针；6.5 起它和 `sendfile` 一样走 `tcp_sendmsg`；从 socket 读出的 splice 走 `tcp_splice_read`，各内核都挂。开启内核 TLS 的 socket 读写走 tls 模块，`tls_sw_sendmsg`、`tls_device_sendmsg`、`tls_sw_recvmsg`、`tls_sw_splice_read` 另有探针，计的是应用明文的字节数，与普通 socket 一样；tls 模块没加载时这些探针不加载。其他不经过已挂探针的路径仍可能让 PID socket I/O 少计。

历史实测范围见 [验证记录](../archive/validation.md)；本页记录当前的数据口径与限制。
