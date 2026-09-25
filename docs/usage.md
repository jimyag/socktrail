# 使用指南

从 [中文首页](../README.zh-CN.md) 进入。这里集中说明构建、界面、录制和运行要求。

## 构建与启动

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

`./socktrail --version` 无需抓包权限，会输出构建时的 tag、构建时间和 Go 版本；本地未注入 tag 的构建会回退到 Go 构建信息。

安装了 [Task](https://taskfile.dev/) 后，也可用 `task` 或 `task build` 构建，注入 Git 版本和构建时间（同发布构建）；以普通用户运行 `task install` 会先构建，再使用 `sudo install` 将程序安装到 `/usr/local/bin/socktrail` 并设置下面的 file capabilities。

### 不使用 sudo 运行

可以给安装后的可执行文件授予 Linux file capabilities，但仅有网络权限不够：AF_PACKET 抓包需要 `CAP_NET_RAW`，eBPF 探针需要 `CAP_BPF` 和 `CAP_PERFMON`，conntrack NAT 查询需要 `CAP_NET_ADMIN`。例如在 5.11 及更新的内核上：

```sh
sudo install -o root -g "$(id -gn)" -m 0750 ./socktrail /usr/local/bin/socktrail
sudo setcap 'cap_bpf,cap_perfmon,cap_net_raw,cap_net_admin+ep' /usr/local/bin/socktrail
getcap /usr/local/bin/socktrail
socktrail --interface lo
```

5.10 内核的 eBPF map 仍受 `RLIMIT_MEMLOCK` 限制，还需授予 `CAP_SYS_RESOURCE`：

```sh
sudo setcap 'cap_bpf,cap_perfmon,cap_net_raw,cap_net_admin,cap_sys_resource+ep' /usr/local/bin/socktrail
```

安装文件应由 root 持有，并限制可执行用户；这些能力允许读取网络流量。替换二进制后需要重新执行 `setcap`。file capabilities 还会受容器 capability bounding set、`nosuid` 挂载和系统安全策略限制。

这组权限可运行核心抓包、socket 探针和 NAT 查询，但不保证能读取其他用户的 `/proc` 信息或挂载 OpenSSL 用户态探针；失败原因可在 `!` 状态页查看。内核模块 BTF 不允许读取时会提示并跳过可选的 kTLS 探针。需要完整进程信息或 OpenSSL 探针时使用 `sudo`。`--version` 不需要这些权限。

## 连接录制

在 `conns` 底栏选中一条活动连接，按 `c` 可录制该连接后续 15 秒的原始报文；在 PID 页主表选中 PID 后按 `c`，录制该 PID 后续关联的连接。再按 `c` 提前结束，按 `q` 也会关闭文件。默认写到 `$XDG_STATE_HOME/socktrail/captures/`；没有设置绝对路径的 `XDG_STATE_HOME` 时使用 `~/.local/state/socktrail/captures/`。可用 `--capture-dir /path/to/dir` 修改，需要临时文件时可指定 `/tmp` 下的私有目录；文件权限为 `0600`，目录新建时为 `0700`，大小最多 64 MiB。状态页 `!` 和退出提示给出 PCAPNG 的绝对路径，可用 `tcpdump -nnr <文件>` 或 Wireshark 打开。

文件保存**实际捕获到的原始帧**，录制期间抓包环保留完整帧（最长 64 KiB；平时每帧只留前 16 KiB 多一点，按 `c` 时已在环里的少数帧仍是这个长度，文件记下了它们的原始长度，Wireshark 会显示为截断），明文应用数据可能包含在内；只有按 `c` 后才创建。单连接录制选择一个采集接口，可能漏掉走另一接口的反向报文；PID 录制覆盖所有已选接口，同一报文跨接口可在文件内重复出现。PID 和域名注释来自录制时已关联的证据，晚到事件不会回填。录制期间仍需关注状态页的采集丢包。

问题出现时再按 `c` 往往已经错过。用 `--record-before 10s` 启动时，程序一直在内存里保留最近 10 秒的帧（总量最多 32 MiB，超出时先丢最旧的），按 `c` 后文件先写入其中属于所选连接或 PID 的帧，再接着录后续 15 秒：

```sh
sudo ./socktrail --interface eth0 --record-before 10s
```

这些历史帧按平时的长度截断（前 16 KiB 多一点），归属按帧到达时所在的流判断；PID 录制时按按下 `c` 那一刻的进程关联挑选。开启后每个帧都要复制一份，高负载下会多占 CPU 和最多 32 MiB 内存，所以默认关闭；它只用于交互界面，不能和 `--duration` 一起使用。

## 按进程、服务过滤

只关心某些进程时，启动时指定，界面、文本快照和 JSON 都只显示它们、它们参与的连接和它们的 socket 字节：

```sh
sudo ./socktrail --process nginx            # 按进程名，可用通配符，如 'python*'
sudo ./socktrail --pid 1234                 # 这个进程和它所有的子孙进程
sudo ./socktrail --cgroup nginx.service     # cgroup 路径里某一级的名字，可用通配符，如 'docker-*'
sudo ./socktrail --cgroup /system.slice     # cgroup 路径前缀：所有系统服务
sudo ./socktrail --process curl --pid 1234 --duration 30s --output json
```

- 几个条件可以同时给，满足任意一个就算选中；同一参数可用逗号分隔多个值，也可重复指定。
- 进程名是内核里的任务名，最多 15 字节：超过 15 字节的名字（如 `systemd-resolved`）按前 15 字节比较。任务名可以被进程自己修改，需要可靠地限定时用 `--cgroup` 或 `--pid`。
- `--pid` 按父子关系判断：子孙进程在进程开始收发网络数据时，从内核事件取得它的父进程，再从 `/proc` 补齐中间没有网络活动的祖先。中间某个进程在这之前就已退出时，链条会断开。
- `--cgroup` 带 `/` 时是路径前缀，按目录边界比较（`/system.slice/nginx` 不匹配 `nginx.service`）；不带 `/` 时和路径里任意一级目录名比较。
- 过滤只影响显示：抓包和事件照常全量处理，因为报文要先和进程对上才知道属于谁。没有进程的连接（转发流量、还没从 socket 表补上进程的连接）和入站扫描汇总因此不显示。顶部标出 `ONLY process=…`。

## 页面与接口选择

默认进入整机 PID 页，显示当前网络命名空间的进程 socket 收发量与跨接口识别的连接、Host/SNI。按 `5` 打开服务页：按进程所在的 systemd 服务或容器（cgroup 路径里最内层的 `.service` 或 `.scope`）分组，行上的收发量是组内进程的 socket 字节之和；按 `g` 在三种分组间切换：服务、完整的 cgroup 路径、进程树（一个进程和它在同一服务里的子孙进程，如 nginx 的主进程和 worker，或终端里的 shell 和它启动的命令）。各页底栏的连接表列完全相同。第一列 `I/O PID` 是在这条连接上有收发的进程，`PID RX`、`PID TX` 是这些进程的 socket 字节：
- PID 页只算选中的进程，服务页只算组内的进程，其他页算所有进程。
- 父进程接受连接后交给子进程收发时（如 sshd），连接两端的 PID 仍是父进程，`I/O PID` 显示实际收发的子进程。

第二列 `IFACE` 是抓到这条连接的网卡，主表的 `IFACE` 汇总一行里所有连接的网卡，超过两张时显示为 `+N`。服务页的 `process` 标签列出组内的进程，按父子关系缩进；各页的进程表都有 `PPID` 列，进程详情有 `CGROUP` 行。顶栏从左到右依次是：
- 当前范围：`OVERVIEW` 表示多网卡合并视图，和 HTTP `Host` 域名无关；单网卡视图下显示网卡名。
- 各页的按键，当前页高亮。
- 竖线右侧是切换范围的按键，只列出当前有效的：合并视图下是 `i per interface`，按 `i` 进入当前网卡的单网卡视图；单网卡视图下是 `a overview` 和 `i next interface`，`a` 回到合并视图，`i` 换下一张网卡。

范围和页面互相独立：按 `a` 只换范围、不换页，所以在合并视图的 PID 页里按 `a` 看不到变化。按 `1`—`4` 切换 PID、来源 IP、目标 IP、协议，按 `d` 看域名（HTTP Host、TCP/QUIC SNI、代理目标、OpenSSL 进程 SNI、DNS 提示）。`0` 打开网卡诊断总览，选中网卡按 `Enter` 进入该网卡详情。

不指定 `--interface` 时，程序在当前网络命名空间内选择最多 8 张处于 UP 且 RUNNING 状态的接口：先按名称选择 `/sys/class/net/<name>/device` 下有设备入口的物理网卡，再用 loopback、宿主网桥、隧道等主机级虚拟接口补足；默认跳过容器 veth、Docker 子网桥和 VM tap。超过 8 张时会在标准错误输出提示未选中的名称，已选的 8 张继续采集。自动选择只决定从哪里采集报文，不要求在主页面选网卡。相同五元组和 TCP 代次的跨接口观测在整机页合为一条连接，只取一个采集点的 IP 字节，优先保留已识别的 Host/SNI。

NAT 改写过的连接按 conntrack 给出的原始元组合并，从一个接口进、另一个接口出的连接方向标为 `forwarded`；conntrack 结果回来之前（通常不到一秒）两侧会各显示一行。代理、隧道改写的地址仍可能留下多个观测流，所以整机页的 IP 字节是观测值，不能作为精确整机总量。`--interface` 可重复指定、用逗号分隔，也支持带引号的 glob 模式，例如 `--interface 'veth*,br-*,docker*,vnet*,tap*'`；显式指定没有网卡数量上限，模式没有匹配时会报错。用 `ip -br link` 查看名称。交互界面按 `1` PID、`2` 来源 IP、`3` 目标 IP、`4` 协议、`d` 域名切换；多接口时按 `i` 切换接口。

显式选择超过 8 张网卡时，启动前会列出匹配名单和抓包环的最低内存占用，并要求确认。默认在独立的 systemd scope 中设置 512 MiB 总内存上限；普通用户使用自己的 systemd 用户管理器。如果抓包环加上 128 MiB 余量已接近上限，或上限超过系统当前可用内存的一半，会在启动前报错。无交互运行需加 `--yes`。可以用 `--memory-limit=1GiB` 调整上限，或用 `--memory-limit=none` 明确关闭；关闭后仍需确认或加 `--yes`。受限模式需要 `systemd-run` 和 cgroup v2，无法建立限制时不会自动改为无保护运行。达到上限时内核可能终止 socktrail，录制文件也可能不完整。

详情区默认约占半屏，提供 `conns` 和 `process` 两个标签。界面用终端主题的颜色标出选中行、连接状态和告警，含义见[界面设计](ui-design.md#配色)；设置环境变量 `NO_COLOR` 可以关闭颜色。窗口变宽时主表会展开，底栏的连接表和进程表按内容定宽；窗口变窄时保留完整列数据；用 `←/→` 或 `h/l` 横向滚动当前焦点的表格。可以用鼠标点击顶部视图、主表行、底部标签及连接；点击主表、连接表或进程表的任意列标题按该列排序，再点同一列切换升降序，当前方向标在标题旁。滚轮滚动当前列表，Shift+滚轮或水平滚轮横向滚动鼠标所在表格，拖动横向分隔线调整详情区高度。`Enter` 切换主表和底栏焦点，`Tab` 切换底栏标签，`/` 过滤，`s` 恢复主表总字节/总速率排序并切换两者，`?` 帮助，`!` 状态，`q` 退出。输入过滤词时 `q` 是普通字符，`Enter` 确认、`Esc` 清除；`Ctrl-C` 任何时候都退出。终端断开时程序会正常退出，并关闭进行中的录制；用 `nohup` 运行快照时挂断信号仍被忽略。

终端需支持 SGR 鼠标报告；退出时程序关闭鼠标报告并恢复终端。

## 进程详情

查看单个进程时，按 `1` 进入 PID 页，用 `/` 输入完整 PID 并回车；也可直接点击该 PID 行。默认的 `conns` 底栏列出该 PID 关联的 TCP/UDP 连接，包含来源、目标、协议、状态、Host/SNI 和连接 IP 字节；选中连接后显示**该 PID**在此连接上的 socket RX/TX。按 `Enter` 聚焦底栏后可用方向键逐条查看，也可以用鼠标点击或滚轮切换连接。PageUp/PageDown 会在当前聚焦的主列表或连接列表中翻页。

切到 `process` 标签可看进程启动时间、父 PID、可执行文件、工作目录、命令行和环境变量；多个进程用方向键或点击列表选择，环境变量用 PageUp/PageDown 或鼠标滚轮滚动。启动信息来自 `/proc`，只有进程仍在运行且启动标识匹配时才可读取；权限不足或进程退出会显示原因。环境变量显示的是 `/proc/<pid>/environ` 提供的启动时快照，可能包含凭据，仅显示在终端，不写入日志。PID 汇总可能包含未匹配到已采集连接的 socket I/O，因此连接观测 IP 字节不能直接与 PID socket 字节相加或要求相等。

交互界面把进程显示为 `PID 进程名`，例如 `1224 tailscaled`。同一 PID 在观测期内被复用时，历史行会显示 `#1`、`#2` 以便区分；内部仍以 PID 和进程启动标识分别统计。启动日期可在 `process` 详情页查看。非交互式快照保留完整 `PID@启动纳秒`，便于核对原始身份。启动时间与 `/proc/<pid>/stat` 同一基准（开机后经过的时间，挂起期间也计入），并按内核时钟节拍（通常 10 ms）取整，这样 eBPF 事件和 socket 表找到的同一进程归为一行。

## 限时快照

可以运行限时文本快照，方便留存和对照抓包：

```sh
sudo ./socktrail --interface lo --duration 15s
sudo ./socktrail --duration 15s
sudo ./socktrail --interface lo --duration 15s --port 443
```

时长从探针加载完、开始抓包时算起。快照按字节列出前 `--limit` 条连接（默认 30），已关闭的连接保留 1 分钟、其余 5 分钟没有报文后过期，不再列出，只计入过期数。

## JSON 快照

`--output json` 把同一份快照写成 JSON，只能和 `--duration` 一起用；标准输出只有这一个文档，便于 `jq` 处理或前后对比：

```sh
sudo ./socktrail --interface eth0 --duration 30s --output json > snapshot.json
jq '.reports[0].flows[] | select(.evidence.sni) | [.source, .target, .evidence.sni, .client.name] | @tsv' -r snapshot.json
```

字段名是接口的一部分：以后只会增加字段；删改已有字段时 `version` 加一。时间用 RFC 3339，字节都是整数，没有值的字段省略。

| 字段 | 内容 |
| --- | --- |
| `version`、`netns`、`interfaces` | 格式版本（目前为 1）、网络命名空间 inode、采集的接口 |
| `filter` | 给了 `--process`、`--pid` 或 `--cgroup` 时的过滤条件；有过滤时下面各项只含选中的进程 |
| `probes.pid` | PID 探针的 `received`、`kernel_lost`、`dropped`、`invalid` |
| `probes.openssl`、`probes.socket_stream` | 各自的 `status` 行和同样的计数；OpenSSL 探针不统计 `kernel_lost`，恒为 0 |
| `probes.nat` | `status`、`lookups`、`translated`、`queue_full`、`failed`、`last_error` |
| `reports[]` | 自动选接口时一份 `scope` 为 `OVERVIEW` 的整机报告，否则每个接口一份 |
| `reports[].*` | `ip_packets`、`ip_bytes`、`capture_delivered`、`capture_dropped`、`truncated_packets`、`expired_flows`（只有单接口报告统计）、`packets_without_flow`、`pid_index_dropped`、`parse_failures`、`https_coverage` |
| `reports[].flows[]` | 按字节排序的前 `--limit` 条连接，字段见下表 |
| `reports[].domains[]` | 域名页的行：`label`、`connections`、`rx_bytes`、`tx_bytes`、`http_requests`、`unknown_pid` |
| `reports[].inbound_attempts[]` | 被拒或无应答的入站尝试：`source`、`ports`、`refused`、`unanswered` |
| `processes[]` | PID socket I/O：`pid`、`start_ns`、`name`、`ppid`、`cgroup`、`service`、`rx_bytes`、`tx_bytes`，前 `--limit` 个 |
| `services[]` | 按服务汇总：`service`、`cgroup`、`processes`（进程数）、`connections`、`rx_bytes`、`tx_bytes`，全部列出 |

`flows[]` 的字段：

| 字段 | 内容 |
| --- | --- |
| `protocol`、`app`、`state`、`direction` | 与文本表格的 PROTO、APP、STATE、DIR 相同 |
| `interfaces` | 抓到这条连接的采集接口，与文本表格和界面的 IFACE 相同；网桥和它的成员口会同时出现 |
| `source`、`target`、`initiator_unknown` | 发起方与接收方；TCP 的发起方不确定时 `initiator_unknown` 为 true，两端为观测到的原始顺序 |
| `rx_bytes`、`tx_bytes`、`packets`、`first_seen`、`last_seen` | 采集点的 IP 字节与报文数 |
| `syn_rtt_us`、`rtt_us`、`rtt_source` | 抓到的握手时延，以及界面上显示的 RTT 和来源（`kernel` 或 `SYN`），单位微秒 |
| `retransmits`、`retransmit_source` | 重传数和来源（`kernel` 或 `capture`），只对 TCP 给出 |
| `kernel_tcp[]` | 每个本机端 socket 的内核状态：`local`（本端地址）、`rtt_us`、`rttvar_us`、`cwnd`、`data_segs_out`、`retransmits` |
| `client`、`server` | 两端的进程：`pid`、`start_ns`、`name`、`ppid`、`cgroup`、`service`；`pid` 为 -1 表示多个进程有歧义 |
| `name`、`detail` | 连接名称（如 `TLS example.com`）和证据说明 |
| `evidence` | 域名证据：`kind`、`hosts`、`grpc`、`sni`、`no_sni`、`ech`、`alpn`、`proxy`、`proxy_via`、`proxy_client`、`dns`、`no_handshake`、`parse_error`、`tls_version`、`server_alpn`、`certificate`、`alert` |
| `openssl_pids`、`domain_conflict`、`nat` | OpenSSL 探针报告过 SNI 的进程、进程 SNI 与报文冲突、NAT 改写 |
