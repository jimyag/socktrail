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

这组权限可运行核心抓包、socket 探针和 NAT 查询，但不保证能读取其他用户的 `/proc` 信息或挂载 OpenSSL 用户态探针；失败原因可在 `!` 状态页查看。需要完整进程信息或 OpenSSL 探针时使用 `sudo`。`--version` 不需要这些权限。

## 连接录制

在 `conns` 底栏选中一条活动连接，按 `c` 可录制该连接后续 15 秒的原始报文；在 PID 页主表选中 PID 后按 `c`，录制该 PID 后续关联的连接。再按 `c` 提前结束，按 `q` 也会关闭文件。默认写到当前目录的 `socktrail-captures/`，可用 `--capture-dir /path/to/dir` 修改；文件权限为 `0600`，目录新建时为 `0700`，大小最多 64 MiB。状态页 `!` 和退出提示给出 PCAPNG 的绝对路径，可用 `tcpdump -nnr <文件>` 或 Wireshark 打开。

文件保存**实际捕获到的原始帧**，录制期间抓包环保留完整帧（最长 64 KiB；平时每帧只留前 16 KiB 多一点，按 `c` 时已在环里的少数帧仍是这个长度，文件记下了它们的原始长度，Wireshark 会显示为截断），明文应用数据可能包含在内；只有按 `c` 后才创建。单连接录制选择一个采集接口，可能漏掉走另一接口的反向报文；PID 录制覆盖所有已选接口，同一报文跨接口可在文件内重复出现。PID 和域名注释来自录制时已关联的证据，晚到事件不会回填。录制期间仍需关注状态页的采集丢包。

## 页面与接口选择

默认进入整机 PID 页，显示当前网络命名空间的进程 socket 收发量与跨接口识别的连接、Host/SNI。顶部的 `a OVERVIEW` 表示按 `a` 回到多网卡合并视图；`OVERVIEW` 是界面范围，和 HTTP `Host` 域名无关。按 `1`—`4` 切换 PID、来源 IP、目标 IP、协议，按 `d` 看域名（HTTP Host、TCP/QUIC SNI、代理目标、OpenSSL 进程 SNI、DNS 提示）。`0` 打开网卡诊断总览；选中网卡按 `Enter` 进入该网卡详情。需要排查采集路径时可按 `i` 逐张切换。

不指定 `--interface` 时，程序自动选择当前网络命名空间内最多 8 个处于 UP 且 RUNNING 状态的宿主接口，包括 loopback、物理接口和隧道接口；跳过名称以 `veth`、`br-`、`docker`、`vnet`、`ovs-` 开头的常见容器/虚拟机子接口。超过 8 个候选时会报错，要求显式选择，不会悄悄漏抓。自动选择只决定从哪里采集报文，不要求在主页面选网卡。相同五元组和 TCP 代次的跨接口观测在整机页合为一条连接，只取一个采集点的 IP 字节，优先保留已识别的 Host/SNI。

NAT 改写过的连接按 conntrack 给出的原始元组合并，从一个接口进、另一个接口出的连接方向标为 `forwarded`；conntrack 结果回来之前（通常不到一秒）两侧会各显示一行。代理、隧道改写的地址仍可能留下多个观测流，所以整机页的 IP 字节是观测值，不能作为精确整机总量。`--interface` 可重复指定最多 8 个接口，也可用逗号分隔；显式指定可选择自动模式跳过的接口。用 `ip -br link` 查看名称。交互界面按 `1` PID、`2` 来源 IP、`3` 目标 IP、`4` 协议、`d` 域名切换；多接口时按 `i` 切换接口。

详情区默认约占半屏，提供 `conns` 和 `process` 两个标签。窗口变宽时表格会展开，变窄时保留完整列数据；用 `←/→` 或 `h/l` 横向滚动当前焦点的表格。可以用鼠标点击顶部视图、主表行、底部标签及连接；点击主表、连接表或进程表的任意列标题按该列排序，再点同一列切换升降序，当前方向标在标题旁。滚轮滚动当前列表，Shift+滚轮或水平滚轮横向滚动鼠标所在表格，拖动横向分隔线调整详情区高度。`Enter` 切换主表和底栏焦点，`Tab` 切换底栏标签，`/` 过滤，`s` 恢复主表总字节/总速率排序并切换两者，`?` 帮助，`!` 状态，`q` 退出。输入过滤词时 `q` 是普通字符，`Enter` 确认、`Esc` 清除；`Ctrl-C` 任何时候都退出。终端断开时程序会正常退出，并关闭进行中的录制；用 `nohup` 运行快照时挂断信号仍被忽略。

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
