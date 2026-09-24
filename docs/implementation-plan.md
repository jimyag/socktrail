# socktrail 实施计划

状态：前四阶段已有可运行原型，交付验证和边界场景仍在推进。实测结果见 [验证记录](validation.md)；不以界面草图的模拟数据代替实机结果。

1. **采集原型：部分完成**。AF_PACKET 按接口捕获 IPv4/IPv6 TCP、UDP、ICMP 及其他 IP 协议，ARP 和其他非 IP 帧按 EtherType 计入，tun 类接口按 IP 报文解析，IP 分片归入首片的流；内嵌 eBPF 采集 TCP connect/accept/send/receive 和 UDP send/receive 的 PID、启动时间与返回的应用字节，内核 socket 表补充启动前已有连接的进程与方向。当前主机已验证普通本机双端 I/O、两个并发客户端 PID、共享 socket 的接受者与 I/O 执行者、IPv6、UDP、loopback、`lo`/`br0` 同时采集，以及从独立网络命名空间发起的入站 ICMP/ARP/分片/TCP/UDP/QUIC，网络命名空间网关上的 SNAT/DNAT 与本机 OUTPUT DNAT；真实 PID 数值复用尚待系统性验收。
2. **正式 PID 采集：完成原型**。探针对象已嵌入可执行文件，运行不依赖 bpftrace；不能可靠归属的流量保留未知。跨内核 hook 兼容性仍待验证。
3. **连接与协议：部分完成**。接口 IP 层字节与整个网络命名空间的 PID 应用 socket I/O 字节分开显示；有界 TCP 重组、HTTP Host 次数、TCP TLS ClientHello SNI、QUIC v1/v2 Initial SNI、ECH 外层名处理已有测试。QUIC v1 已用真实本机握手验证，v2 用 RFC 加密向量验证；默认 OpenSSL 进程探针已用本机 `SSL_set_fd` 客户端验证，其他库/调用路径仍需适配。TCP 显示 SYN/established/closing/closed/reset/midstream 状态、出站握手 RTT 样本及有界序号重叠计数。报文特征可标注 RustNet 清单中的主要应用协议，具体覆盖和弱点见 [协议对照](rustnet-comparison.md)。分片、丢包后的恢复、真实 ECH、真实 OpenVPN/QUIC v2 会话和复杂 TCP 生命周期需继续验证。
4. **展示：完成原型**。PID、来源 IP、目标 IP、传输/应用协议和合并域名页，以及排序、过滤、详情、帮助、接口切换和采集状态可用。可从 PID 或活动连接主动录制短时 PCAPNG。多 Host IP 字节互斥分组及 PID socket I/O 与 IP 字节分离有单元测试。
5. **交付验证：进行中**。README 与验证记录已补齐；2,500 次短连接压力样本、`sendfile`/splice 计数（5.10 至 7.0）、veth 上 20 Gbps TCP 与每秒约 10 万个小 UDP 报文的抓包、NAT 网关实验和 1 小时界面运行通过，仍需物理网卡上的极限吞吐、内核 TLS 等路径及数小时以上运行验收。退出后应不留探针或后台进程。容器、域名拦截和 GeoIP 不在本轮范围。

## 依赖判断

报文采集选 Linux AF_PACKET；PID 探针选 cilium/ebpf 的内嵌 CO-RE 对象，不需要运行时 bpftrace。socket 事件端点与所选接口报文五元组能在已测本机直连场景对应，`fork` 后子进程读写共享 socket 已实测，NAT 两侧的元组经 conntrack 关联，fd 传递、多写者和短连接极端时序仍是风险。若目标机不支持所需 fexit/BTF，不应静默降级为无 PID 统计。
