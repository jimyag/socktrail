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
  → flow 帧们    当前所有进行中连接，每条 changes: ["snapshot"]
  → stats        一份汇总，让订阅者立刻有 process_io
  → flow 帧      之后是增量变化，changes 为 new/name/state/process/drops/end/refresh
  → stats        每 --refresh（默认 60 秒）重复一次
```

快照没有单独的 `kind`：它就是一串 `flow` 帧，用 `changes: ["snapshot"]` 标出来。这样只解 `flow` 的消费方不用认识第三种帧类型就能处理历史。

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

### 差异二：`time.Time` 的编码（实测确认走路线 A）

库把 `time.Time` 编码为 MessagePack timestamp extension（ext type -1，按精度选 timestamp32/64/96），而 JSON 侧是 RFC3339Nano 字符串。实测 `time.Unix(1700000000, 0).UTC()`：msgpack 帧里是 `d6 ff 6553f100`，解码回 `time.Time`，绝对时间与 JSON 侧一致。

选路线 A。字段名和绝对时间两边一致，消费方用 MessagePack 库就能拿到 `time.Time`。另一种做法是引入 `type compactTime time.Time`，实现 `EncodeMsgpack` 编成 RFC3339Nano 字符串、同时实现 `MarshalJSON`/`UnmarshalJSON` 保持 JSON 输出不变，替换 `jsonFlow`、`jsonFailure`、`jsonDNSQuery` 里的时间字段。那只是让两种编码字节可比，代价是每个时间字段多一层类型和自定义编解码，收益为零。

`TestMsgpackEncodesTimesAsTimestamps` 锁住这个行为。

## 生命周期与错误处理

**socket 文件**

- 路径不存在：直接 `net.Listen("unix", path)`
- 路径存在且是 socket：先尝试 `net.Dial("unix", path)`。连得上说明已有实例在监听，报错退出并提示路径；连不上说明是上次进程被强杀留下的 stale 文件，`os.Remove` 后重新监听
- 路径存在但不是 socket：报错退出，不删除。那可能是用户自己的文件，删掉无法恢复
- 创建后 `os.Chmod(path, mode)`，默认 `0600`。数据含域名、PID 和流量计数，所以默认只给属主；而 socktrail 通常以 root 运行，消费方在别的账号时就用 `--socket-mode 0660` 加一个共享组，不要放开给所有人
- 退出时（`--duration` 到时、Ctrl-C、SIGTERM、SIGHUP）关闭监听并删除 socket 文件

**客户端异常**

- 单个客户端写失败（对端 `close`）：只关掉该连接，从 hub 移除，不影响其他客户端和采集
- 客户端列表为空：清理后回到"不编码"状态
- 协议无握手超时、无认证。依赖文件系统权限做访问控制

**与现有信号处理的关系**

现有的 `signal.NotifyContext` 已经覆盖 `SIGINT`、`SIGTERM`、`SIGHUP`，socket 关闭挂在同一个 `defer` 链上，不需要新增信号逻辑。

## 代码改动清单

| 文件 | 改动 |
|---|---|
| `internal/app/stream_socket_linux.go` | **已完成**。`streamHub`、`streamClient`、监听与 stale 文件处理、`adopt`/`broadcast`/`close`、`streamSink` |
| `internal/app/stream_codec_linux.go` | **已完成**。`streamCodec`（json 或 msgpack 编码一行，返回 `[]byte`）、`streamingOutput` |
| `internal/app/app_linux.go` | flag 定义与校验；流式输出改走 `streamSink`；TUI 开启条件排除 `msgpack`；新客户端握手与全量快照、周期性 `stats` 帧 |
| `internal/app/report_json_linux.go` | 5 个字段补 `msgpack:"...,omitempty"` tag；`processesJSON` 抽出不限 `--limit` 的变体；抽出 `probesJSON` 供快照和 hello 共用 |
| `go.mod` | 加 `github.com/vmihailenco/msgpack/v5` |
| `internal/app/stream_codec_linux_test.go` | **新增**。编码一致性与帧定界测试 |
| `internal/app/completion.go`、`internal/app/manual.go` | `--output` 的补全值和手册描述加上 `msgpack`，`--socket` 补全路径 |
| `test/streamcheck/main.go` | **新增**。不依赖 socktrail 类型的帧解码器，供端到端检查用 |
| `test/smoke.sh`、`.github/workflows/check.yaml` | root job 里并行验证标准输出裸行流和 socket 订阅协议 |

第 1 阶段只动上面这些；`stream_socket_linux.go` 和 hub 属于第 2 阶段。

`*json.Encoder` 和 `*msgpack.Encoder` 的 `Encode(v any) error` 签名相同，但 UDS 模式要拿到字节而不是写 writer，所以统一走 `bytes.Buffer`：

```go
type streamCodec struct {
    json    *json.Encoder
    msgpack *msgpack.Encoder
    buf     bytes.Buffer
}

func (c *streamCodec) encode(v any) ([]byte, error) {
    c.buf.Reset()
    if c.msgpack != nil {
        if err := c.msgpack.Encode(v); err != nil {
            return nil, err
        }
    } else if err := c.json.Encode(v); err != nil { // json.Encoder appends '\n'
        return nil, err
    }
    return c.buf.Bytes(), nil
}
```

标准输出和 `--log-file` 模式写 `codec.encode` 的字节；UDS 模式把字节交给 hub。

## 验证方案

**编码层**（`internal/app/stream_codec_linux_test.go`）

1. `TestMsgpackMatchesJSONFields`：`jsonFlow` 填满所有嵌套类型（GeoIP、kernel_tcp、client/server/container、io、evidence、DNS、drops），两边编码后解码回 `map[string]any`，递归断言每一层的键集合一致。文件里的 `MsgpackFlow()` 构造器供其余测试复用。
2. `TestMsgpackMatchesJSONSnapshotFields`：`jsonSnapshot` 的 reports、processes、services、failures、listeners、drops 同样比较。
3. `TestMsgpackOmitsZeroFieldsLikeJSON`：零值行的 `id`、`connect_latency_us` 在 msgpack 侧也必须缺席，锁住 `omitzero` 与显式 `msgpack:"...,omitempty"` 的对齐。
4. `TestMsgpackEncodesTimesAsTimestamps`：json 侧是字符串，msgpack 侧解回 `time.Time` 且绝对时间相等。
5. `TestStreamFramesDecodeInSequence`：连续写多帧后，msgpack 和 ndjson 都能逐帧解回，验证定界。

**传输层**（`internal/app/stream_socket_linux_test.go`）

6. `TestListenStreamSocketReplacesStaleSocket`：预置一个没有监听者的 socket 文件，断言启动时被替换。
7. `TestListenStreamSocketRefusesNonSocketPath`：预置普通文件，断言报错且文件内容不变。
8. `TestListenStreamSocketRefusesLiveSocket`：已有实例监听时，第二个断言报错。
9. `TestStreamHubDeliversFramesToClients`：真 socket 连接、`adopt`、广播，客户端读回帧；同时断言 socket 权限为 0600，并在广播后改写原 buffer，验证客户端已收到的内容不受影响。
10. `TestStreamHubDropsSlowClient`：客户端接一个没人读的管道，灌入超过缓冲的帧数，断言广播不阻塞且该客户端被注销。
11. `TestStreamSinkSkipsEncodingWithoutClients`：sink 带一个 nil 编解码器，无客户端时写入不 panic，证明编解码器根本没被碰到。

**订阅层**（`internal/app/stream_summary_linux_test.go`）

12. `TestStreamSummaryCoversBytesMissingFromFlows`：一个进程既有匹配到流的 I/O（100 B）、又有没有对应流的 I/O（50 B）。断言流的 `io[]` 只有 100 B，而 `process_io` 是 150 B、`ioUnmatchedBytes` 是 50 B。这条测试锁住 stats 帧存在的理由：从 `io[]` 聚合进程流量会系统性少算。
13. `TestStreamSummaryListsEveryProcess`：`processesJSON` 按 `--limit` 截断，`allProcessesJSON` 不截断，共 3 个进程时后者必须给出 3 行。
14. `TestStreamGreetSendsHandshakeBeforeIncrements`：真 socket 上按顺序解出 hello、flow、stats 三个帧，断言每个 `kind` 正确、`flow` 帧确实包着 `jsonFlow`。

**端到端**（`test/smoke.sh`，CI 的 root job 以 root 调用；解码器是 `test/streamcheck`）

15. `--output msgpack` 与 JSON 快照的采集并行跑一次，`streamcheck pipe` 逐条解码标准输出的行，断言每行有 `protocol`、`source`、`target`，且不带 `kind`（标准输出必须是裸行）。
16. 另起一次采集开 `--socket`，`streamcheck socket` 连上去，断言第 1 帧是 hello、能读到一个 `changes: ["snapshot"]` 的行、以及一个带 `process_io` 的 `stats` 帧。

`streamcheck` 用泛型 `map[string]any` 解码，不引用 socktrail 的类型，所以它同时演示了任意语言的消费方该怎么做。

**不需要权限就能核对的接线**

```sh
socktrail --output bogus                          # usage 里列出 msgpack
socktrail --output msgpack --read x.pcapng        # 报与 --read 互斥
socktrail --output text --socket /tmp/s.sock      # 报 --socket 需要流式 --output
socktrail --socket-mode 0999 --output msgpack     # 报权限位非法
socktrail --man | grep msgpack                    # 手册提到 msgpack
socktrail --completion bash | grep msgpack        # 补全值里有 msgpack
socktrail --completion bash | grep socket         # 补全值里有 socket
```

`--output msgpack` 的端到端抓包要能加载 eBPF 探针的内核。开发机上只能核对到 flag 校验、编码层和 socket 层：该机内核 7.2 超出上游已验证的范围（到 7.0），`udpv6_recvmsg` 的探针加载被内核拒绝，采集起不来。这与本次改动无关。第 15、16 条因此在 CI 的 root job 里执行。`streamcheck` 的两个模式另外用假帧序列单独验证过：正确的序列通过，缺 `process_io` 的 `stats` 帧和带 envelope 的裸行都被拒绝。

## 分阶段实施

每阶段独立可验证，可以单独提交：

1. **编码层（已完成）**：`--output msgpack` 写标准输出，含上面第 1–5 条测试。此时已可用于管道消费，不涉及并发改动。
2. **传输层（已完成）**：`--socket` + `streamHub` 广播，含第 6–11 条测试。这一步流里只有连接变化帧，没有 `kind` 外壳。
3. **订阅语义（已完成）**：envelope、hello、新客户端全量快照、周期性 `stats` 帧，含第 12–14 条测试。
4. **文档（已完成）**：`docs/user/usage.md` 增加一节，`README.zh-CN.md` 与 `README.md` 的特性列表各加一条。
5. **端到端（已完成）**：`test/streamcheck` 加 `test/smoke.sh` 与 CI root job，含第 15、16 条。

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
