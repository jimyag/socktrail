# MessagePack 与 Unix socket 流式输出

从 [实现原理](architecture.md) 进入。这里说明在现有 NDJSON 流式输出之上增加 MessagePack 编码和 Unix domain socket 传输的设计。

## 目标与非目标

**目标**：让 socktrail 成为一个可被订阅的流式数据源。消费方（监控 agent、另一个诊断工具、自己的 TUI 前端）通过 Unix domain socket 连接，按 MessagePack 连续解码连接变化，并能据此完成两件事：按进程统计流量、按进程查出它参与的所有连接。

**非目标**（本期不做）：

- 不做后台 daemon 化、不做 systemd socket activation。进程生命周期仍由用户或外层 unit 文件管理。
- 不改动交互界面、文本报告和 JSON 快照的既有行为。
- 不做服务端主动连接客户端（socktrail 始终是监听方）。
- 不做按客户端独立过滤。所有订阅者收到同一份流，范围由启动参数决定。

## 参数设计

新增两个参数，正交组合：

| 参数 | 取值 | 说明 |
|---|---|---|
| `--output` | 增加 `msgpack` | 编码格式：`text`、`json`、`ndjson`、`msgpack` |
| `--socket` | 路径 | 输出到 Unix domain socket，替代标准输出。只对 `ndjson` 和 `msgpack` 有效 |
| `--socket-mode` | 八进制权限位，默认 `0600` | socket 文件的权限。消费方在别的账号时需要 `0660` 加一个共享组 |

用法：

```sh
# 监听 UDS，MessagePack 编码，供外部订阅
sudo socktrail --output msgpack --socket /run/socktrail.sock --duration 1h

# MessagePack 写给标准输出，管道给消费方
sudo socktrail --output msgpack --duration 30s | consumer

# 保持原有行为不变
sudo socktrail --output ndjson > changes.ndjson
```

校验规则（加在 `internal/app/app_linux.go` 现有的 `--output` 校验处）：

- `--socket` 非空时 `--output` 必须是 `ndjson` 或 `msgpack`，否则报错
- `--socket` 与 `--log-file` 天然互斥：后者要求 `--output text`，前者要求流式输出
- `--read` 的互斥列表里，`--output ndjson` 之外加上 `msgpack`
- `--socket` 隐含无界面，与 `--output ndjson` 一致：`*duration == 0 && *output != "ndjson"` 判断改为同时排除 `msgpack`
- `--socket` 为相对路径时不做特殊处理，报错交由 `net.Listen` 给出

## 数据流与并发模型

现有 NDJSON 在主循环里同步 `Encode` 到标准输出。改成 UDS 后有一个硬约束：**慢客户端不能阻塞主循环**。主循环每次停顿都直接变成抓包丢包，[实现原理](architecture.md) 的环大小与丢包实测都建立在这个前提上。

所以编码和传输拆成两件事：

```text
采集主循环
  │  hostState.lastChanges / displayed
  │  ① 同步序列化（json 或 msgpack）→ []byte
  ▼
hub.broadcast(frame)
  ├─► client A  chan []byte（有界，cap 1024）──► 独立 goroutine 写 conn
  ├─► client B  chan []byte ──────────────────► 独立 goroutine 写 conn
  └─► ...
```

**① 必须在主循环里同步完成序列化**，不能把 `jsonFlow` 结构体异步投递给写协程。原因是 `jsonFlowFor` 返回的行里存在引用共享内部状态的字段：

- `row.Drops = f.Drops.reasons` 直接引用流上的 map（`internal/app/report_json_linux.go`）
- `row.Evidence = &e` 是 `f.Domain.Evidence()` 的返回值副本，安全
- `row.SourceGeo/TargetGeo = geo.Lookup(...)` 每次 `new(Location)`，安全

`Drops` 这一处足以造成数据竞争。序列化后再投递 `[]byte` 是唯一不需要逐个排查字段共享情况的做法，也让 `-race` 检查有意义。

**② 投递是非阻塞的**。channel 满表示客户端读得太慢：

- 缓冲吸收抖动（1024 帧，约 1–2 MiB）
- 持续满则**断开该客户端**，不做静默丢弃

断开而不是丢帧，是为了不让客户端在不知情的情况下拿到不完整数据。客户端重连后按协议收到 hello 加全量快照，天然恢复一致。代价是持续慢的客户端会重连抖动，这是可接受的显式失败。

握手（hello、全量快照和一份 stats）拼成一个缓冲入队，只占一个槽位。快照最多有 `maxFlows` 行，远多于槽位；逐帧入队时，写协程还没取走第一帧队列就满了，连接数过千的主机上每个新客户端都会在握手中途被断开，重连也一样。

**③ 没有客户端时跳过序列化**。`hub.clients` 为空时主循环不编码，只做 `hostState.update`。这让"只是开着采集等人连"不付出编码开销。

客户端集合只由主循环访问，所以不需要锁：`accept` 在独立 goroutine 里跑，把新连接放进有界的 `joining` channel，主循环每个 tick 用 `hub.adopt()` 取走。广播时把帧复制一次给所有客户端共享，因为编解码器复用同一个 buffer；复制只做一次，不是每个客户端一次。

## 帧协议

`--socket` 模式下，连接建立后是连续的 MessagePack 对象，无额外长度前缀（MessagePack 自带长度信息）。每个对象是一个带 `kind` 的帧：

```go
type streamFrame struct {
    Kind  string         `json:"kind"`            // hello, flow or stats
    Hello *streamHello   `json:"hello,omitempty"`
    Flow  *jsonFlow      `json:"flow,omitempty"`
    Stats *streamSummary `json:"stats,omitempty"`
}
```

用统一 envelope 而不是裸 `jsonFlow`，是因为订阅流里不止连接变化一种对象：订阅者要按进程统计流量，就必须拿到周期汇总帧（见下）。用 `kind` 判别比"尝试解码再看字段是否存在"更直接。`jsonFlow` 本身的字段和 JSON 快照的 `flows[]` 完全一致，只是外面包了一层 `flow`。

**envelope 跟传输绑定，不跟编码绑定**：带 `--socket` 就是订阅协议，用 envelope；不带就是行流，每行一个裸 `jsonFlow`（ndjson 和 msgpack 都一样）。标准输出的格式一个字没改，所以现有 `jq` 用法和 NDJSON 消费方不受影响。代价是不带 `--socket` 的流拿不到 `stats` 帧，也就无法按进程统计流量；订阅协议从 `--socket` 开始。

### 帧序列

```text
连接建立
  → hello       版本、采集范围、探针状态
  → flow 帧们    当前视图中的连接，每条 changes: ["snapshot"]
  → stats        一份汇总，让订阅者立刻有 process_io
  → flow 帧      之后是增量变化，changes 为 new/name/state/process/drops/end/refresh
  → stats        每 --refresh（默认 60 秒）重复一次
```

快照没有单独的 `kind`：它就是一串 `flow` 帧，用 `changes: ["snapshot"]` 标出来。这样只解 `flow` 的消费方不用认识第三种帧类型就能处理历史。视图里还留着刚结束的连接，它们的快照行带 `end`。

快照、增量和 refresh 用同一个选择条件：进程范围加 `--filter`。快照里多出一条增量不会覆盖的连接，订阅者就会一直持有它，等不到更新，也等不到 `end`。

顺序保证：客户端连上后由主循环在下一个 tick 处理，先发 hello 和当时全量快照，再发该 tick 及之后的增量，不存在"快照与增量之间的变化丢失"。

```go
// 每个连接的第 1 帧。
type streamHello struct {
    Version    int        `json:"version"` // 1
    Mode       string     `json:"mode"`    // always "live"
    Interfaces []string   `json:"interfaces"`
    Filter     string     `json:"filter,omitempty"`
    Probes     jsonProbes `json:"probes"`
    Started    time.Time  `json:"started"`
}
```

### flow 帧的语义

`flow` 帧里的 `rx_bytes`、`tx_bytes` 和 `io[].rx_bytes`、`io[].tx_bytes` 都是**累计值**，不是自上次以来的增量。消费方必须按 `id` 覆盖，不能累加。`end` 非空的帧是连接的最终快照，之后不会再变。连接 ID 只在本次运行内稳定，客户端重连后不保证延续。

### stats 帧

订阅者要按进程统计流量，只有 `flow` 帧里的 `io[]` 是不够的。`io[]` 是"这条连接上这个进程实际收发的字节"，而进程的 socket I/O 总量还包括没有匹配到任何流的字节（`internal/app/app_linux.go` 的 `collectSocketIO`）：

```text
pidIO（进程全量 socket I/O，不受接口和 --port 限制）
  ├─ 匹配到某条流 → 计入该流的 io[]
  ├─ 端口不匹配、流不存在超 2 秒、流不收事件 → ioUnmatched
  └─ 进程索引满 → ioUnindexed

另有：进程 5 分钟无 I/O 后明细回收，累计字节保留在 expiredPIDIO
```

所以 `Σ(所有流的 io[]) ≤ pidIO 总量`，差额就是 `ioUnmatched`。这些差额值原本只在文本报告里打印（`printPIDIO` 的 `expired PID detail` 行），JSON 快照的 `processes[]` 里没有，流里的 `flow` 帧也没有。按[数据口径](../user/measurement.md)"缺口必须可见"的约定，订阅者能拿到它，否则自己算出的进程流量会系统性少算而毫不知情。

```go
// 周期汇总帧。
type streamSummary struct {
    At               time.Time       `json:"at"`
    IPPackets        uint64          `json:"ip_packets"`
    IPBytes          uint64          `json:"ip_bytes"`
    ProcessIO        []jsonProcessIO `json:"process_io"`         // 全部进程，不受 --limit
    IOUnmatchedBytes uint64          `json:"io_unmatched_bytes"` // 没能关联到所选流的 socket I/O
    IOUnindexed      streamIOBytes   `json:"io_unindexed"`
    ExpiredPIDIO     streamIOBytes   `json:"expired_pid_io"`
    ExpiredPIDCount  uint64          `json:"expired_pid_count"`
    Probes           jsonProbes      `json:"probes"`
}

// 分方向的字节数。这些是 socket I/O 字节，与 IP 报文字节是两种口径。
type streamIOBytes struct {
    RXBytes uint64 `json:"rx_bytes"`
    TXBytes uint64 `json:"tx_bytes"`
}
```

`process_io` 是 `processesJSON` 去掉 `--limit` 的结果，字段与 JSON 快照的 `processes[]` 相同，元素内部的 `rx_bytes`/`tx_bytes` 就是 `pidIO` 的全量值。有了它，订阅者不必自己维护全量状态也能拿到权威的按进程流量。

`stats` 与 `flow` 的口径差异必须保留：`streamIOBytes` 和 `process_io` 是 socket I/O 字节，`ip_bytes`、`ip_packets` 是采集点的 IP 字节，两者不相加。这与[数据口径](../user/measurement.md)的约定一致，`io_unmatched_bytes` 等字段只用于说明进程统计的缺口，不参与任何总量。

`probes` 来自与 JSON 快照同一个 `probesJSON`，所以订阅者对数据可信度的判断和 `--output json` 一致。

### 消费方如何完成两件事

**按进程统计流量**：取最近一个 `stats` 帧的 `process_io`，按 `(pid, start_ns)` 聚合 —— 进程身份是 PID 加启动时间，PID 会复用，只用 `pid` 做键会把新旧进程混在一起。输出时要带上 `io_unmatched_bytes`、`io_unindexed`、`expired_pid_io` 说明缺口。不能用 `flow` 帧里的 `io[]` 聚合成"进程总流量"，那会少算。

**按进程查连接**：遍历 `flow` 帧时按 `client`、`server`、`io[]` 里的 `(pid, start_ns)` 建反向索引。注意三点：

- `client`/`server` 是建连和接受的进程，`io[]` 才是实际收发的进程。fd 传给别的进程后，两者不是同一个 PID，按进程查连接要三个来源都看。
- 只有"已经关联上进程的连接"才在流里；进程做了 socket I/O 但没匹配上任何流的，只体现在 `stats` 帧的 `process_io` 里，查不到对应连接。
- `snapshot` 帧给出连接起点，之后的 `flow` 帧是累计值覆盖，消费方要自己维护 `id` 到最新状态的映射，并决定 `end` 后保留多久。

## 编码一致性

MessagePack 与 JSON 使用同一组结构体、同一份字段名。实现方式：

```go
enc := msgpack.NewEncoder(w)
enc.SetCustomStructTag("json") // 没有 msgpack tag 时回退到 json tag
```

`SetCustomStructTag` 让 `jsonFlow`、`jsonReport`、`domain.Evidence`、`geoip.Location` 等结构体零改动复用。但有两处已知差异，必须处理。

### 差异一：`omitzero` 不被识别

`vmihailenco/msgpack/v5` 目前只识别 `msgpack:",omitempty"`，不识别 Go 1.24 的 `omitzero`（相关 PR #392 尚未合并）。项目里有 5 处使用 `omitzero`：

| 结构体.字段 | 类型 | 位置 |
|---|---|---|
| `jsonFlow.ID` | `uint64` | `report_json_linux.go` |
| `jsonFlow.ConnectLatencyUS` | `uint32` | 同上 |
| `jsonDNS.RTTMicros` | `int64` | 同上 |
| `jsonDNSQuery.RTTMicros` | `int64` | 同上 |
| `jsonDNSQuery.Answered` | `bool` | 同上 |

后果：库忽略未知 tag 选项，这些字段的零值会被显式编码，而 JSON 侧会省略。对这几处而言 `omitzero` 与 `omitempty` 语义等价（都是标量类型），所以**给这 5 个字段补一个显式 msgpack tag** 即可对齐，不需要改 JSON 侧：

```go
ID uint64 `json:"id,omitzero" msgpack:"id,omitempty"`
```

以后新增 `omitzero` 字段也要这样补。`TestOmitzeroFieldsHaveMsgpackTags` 遍历帧和快照能带的所有类型，漏补时直接失败；零值行的对比测试只覆盖顶层字段，发现不了嵌套类型里的遗漏。

### 差异二：`time.Time` 的编码（实测确认走路线 A）

库把 `time.Time` 编码为 MessagePack timestamp extension（ext type -1，按精度选 timestamp32/64/96），而 JSON 侧是 RFC3339Nano 字符串。实测 `time.Unix(1700000000, 0).UTC()`：msgpack 帧里是 `d6 ff 6553f100`，解码回 `time.Time`，绝对时间与 JSON 侧一致。

选路线 A。字段名和绝对时间两边一致，消费方用 MessagePack 库就能拿到 `time.Time`。另一种做法是引入 `type compactTime time.Time`，实现 `EncodeMsgpack` 编成 RFC3339Nano 字符串、同时实现 `MarshalJSON`/`UnmarshalJSON` 保持 JSON 输出不变，替换 `jsonFlow`、`jsonFailure`、`jsonDNSQuery` 里的时间字段。那只是让两种编码字节可比，代价是每个时间字段多一层类型和自定义编解码，收益为零。

`TestMsgpackEncodesTimesAsTimestamps` 锁住这个行为。

## 生命周期与错误处理

**socket 文件**

- 路径不存在：直接 `net.Listen("unix", path)`
- 路径存在且是 socket：先尝试 `net.Dial("unix", path)`。连得上说明已有进程在监听，报错退出并提示路径；只有连接被拒绝（`ECONNREFUSED`）才说明是上次进程被强杀留下的 stale 文件，`os.Remove` 后重新监听。其他错误一律报错退出、不删除：没有权限连接时对面可能正有服务在监听，datagram socket（如 journald 的）拒绝 stream 连接却仍在使用，删掉它们会让那个服务失去入口
- 路径存在但不是 socket：报错退出，不删除。那可能是用户自己的文件，删掉无法恢复
- 创建后 `os.Chmod(path, mode)`，默认 `0600`。数据含域名、PID 和流量计数，所以默认只给属主；而 socktrail 通常以 root 运行，消费方在别的账号时就用 `--socket-mode 0660` 加一个共享组，不要放开给所有人
- 退出时（`--duration` 到时、Ctrl-C、SIGTERM、SIGHUP）关闭监听并删除 socket 文件

**客户端异常**

- 单个客户端写失败（对端 `close`）：只关掉该连接，从 hub 移除，不影响其他客户端和采集
- 客户端列表为空：清理后回到"不编码"状态
- 协议无握手超时、无认证。依赖文件系统权限做访问控制

**与现有信号处理的关系**

现有的 `signal.NotifyContext` 已经覆盖 `SIGINT`、`SIGTERM`、`SIGHUP`，socket 关闭挂在同一个 `defer` 链上，不需要新增信号逻辑。

## 测试

- 编码一致性：`internal/app/stream_codec_linux_test.go` 把同一行分别按 JSON 和 MessagePack 编码，解回 `map[string]any` 后逐层比较键集合，并锁住零值省略和时间编码。
- socket 与订阅：`internal/app/stream_socket_linux_test.go` 覆盖 stale 文件替换、不删除可能仍在使用的 socket、慢客户端断开，以及超过客户端缓冲的握手；`stream_summary_linux_test.go` 覆盖 stats 帧的进程汇总和握手帧顺序。
- 端到端：CI 的 root job 运行 `test/smoke.sh`，用 `test/streamcheck` 解码标准输出的裸行流，并订阅一个带 `--filter` 的 socket，检查握手顺序、`process_io`，以及快照行都在过滤范围内。`streamcheck` 只用通用的 `map[string]any` 解码，也可以当作不依赖 socktrail 类型的消费方示例。

## 明确不做的取舍

- **不做逐帧 gap 通知**。慢客户端的处理是断开，不是丢弃后补一个"缺了 N 帧"的通知，断开加重连已经保证不静默丢数据。进程流量的缺口由周期性 `stats` 帧暴露，那是口径缺口，与单个客户端丢帧是两回事。
- **不给标准输出加 envelope**。它已发布，改行结构会破坏现有 `jq` 用法和消费方；订阅协议从 `--socket` 开始，与编码无关。
- **不做 per-client 过滤**。要在同一台机器上按不同条件订阅，起两个进程。
- **不做 HTTP/WebSocket 传输**。UDS 覆盖本机消费场景，跨机需求不在本期。
- **不改 `--log-file` 的编码**。它是给人和 `jq` 看的变化日志，保持 NDJSON。

## 参考

- [vmihailenco/msgpack](https://pkg.go.dev/github.com/vmihailenco/msgpack/v5)：`SetCustomStructTag` 与 struct tag 选项。
- [MessagePack 规范](https://github.com/msgpack/msgpack/blob/master/spec.md)：timestamp extension type 定义。
- [实现原理](architecture.md)：主循环停顿与丢包的关系、流表容量与状态页可见性约定。
