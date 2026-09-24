# 数据口径与限制

从 [中文首页](../README.zh-CN.md) 进入。读数字前先区分报文 IP 字节、进程 socket I/O 和域名证据；这些量不能直接相加。

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

## SYN RTT 与 RETX

`SYN RTT` 只对看到本机发出 SYN、收到匹配 SYN-ACK 的 TCP 连接给出一次握手时差样本；入站或中途开始时为 `-`。`RETX` 统计当前采集点观察到的重复 SYN 和已保存序号区间重叠的 TCP 数据段，不是内核的重传计数；每方向最多保留 128 个区间，丢包、乱序、序号回绕或多接口合并会影响判定。两列是网络诊断提示，不与报文字节另行相加。

## HTTP Host 与 TLS SNI

HTTP/1.1 `Host` 统计已完整观察的请求数。同一 TCP 连接出现多个 Host 时，连接字节归入 `multiple Hosts` 一组，不按请求拆分。TCP/QUIC/进程侧的 TLS `SNI` 是连接级域名证据，只统计连接与流量，不推断 HTTPS 请求数。入站 Host/SNI 指被访问的服务名，不是客户端来源域名。

## 入站连接尝试

入站的连接尝试按来源汇总：被拒绝（目标回 RST，或 UDP 目标回端口不可达）和没有应答（只有 SYN 或单向的一两个 UDP 报文）的尝试计数，并记下尝试过的端口（最多 1024 个）。来源 IP 页在该来源的行上显示 `tried N ports: refused …, unanswered …`；流表满时先批量淘汰这类一次性的流（每次最旧的 10%），扫描不会挤掉正常连接，被淘汰的流仍留在汇总里。汇总 10 分钟没有新尝试后删除。

## 丢失、索引淘汰与未覆盖路径

页面显示 AF_PACKET 丢包、PID 事件丢失、解析失败及索引淘汰。GSO/GRO、首片丢失的 IP 分片、桥接、未被 conntrack 关联的地址改写、抓包缺口和高负载可能影响报文与进程归属；整机页 IP 数字只代表选定采集点的观测结果。

`sendfile` 和 splice 的字节计入 PID socket I/O：6.5 之前的内核里，写往 socket 的 splice 走 `generic_splice_sendpage`，另挂探针；6.5 起它和 `sendfile` 一样走 `tcp_sendmsg`；从 socket 读出的 splice 走 `tcp_splice_read`，各内核都挂。内核 TLS 及其他不经过已挂探针的路径仍可能让 PID socket I/O 少计。

实测范围与剩余缺口见 [验证记录](validation.md)。
