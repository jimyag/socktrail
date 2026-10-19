<h1 align="center">socktrail</h1>

<p align="center">
  <strong>See Linux network traffic, connections, processes, and visible domains in one terminal.</strong>
</p>

<p align="center">
  <a href="https://github.com/jimyag/socktrail/actions/workflows/check.yaml"><img src="https://img.shields.io/github/actions/workflow/status/jimyag/socktrail/check.yaml?branch=main&amp;label=CI" alt="CI status"></a>
  <a href="https://github.com/jimyag/socktrail/actions/workflows/kernels.yaml"><img src="https://img.shields.io/github/actions/workflow/status/jimyag/socktrail/kernels.yaml?branch=main&amp;label=Kernel%20matrix" alt="Kernel matrix status"></a>
  <a href="https://github.com/jimyag/socktrail/releases/latest"><img src="https://img.shields.io/github/v/release/jimyag/socktrail?label=Latest%20release" alt="Latest release version"></a>
</p>

<p align="center">
  <a href="#why-socktrail">Why socktrail</a> ·
  <a href="#features">Features</a> ·
  <a href="#screenshots">Screenshots</a> ·
  <a href="#build-and-run">Build and Run</a> ·
  <a href="#documentation">Documentation</a>
</p>

<p align="center">
  <strong>English</strong> · <a href="README.zh-CN.md">简体中文</a>
</p>

---

socktrail is a Linux terminal application for inspecting live network traffic. It captures packets from selected interfaces with AF_PACKET and uses eBPF socket probes and the kernel socket table to associate local traffic with processes. The interface shows connections, IP traffic, application protocols, and domain names found in observable HTTP, TLS, QUIC, proxy, and DNS data.

It is a prototype. It has been tested on a Linux 6.8 host; probe loading and loopback traffic are also checked in virtual machines on x86-64 kernels from 5.10 to 7.0, including CentOS Stream 9 and 10, and on arm64 kernels 6.4 and 6.8; CI runs the root tests on amd64 and arm64 runners. NAT, Docker bridge/host networking, and explicit cross-namespace capture were tested locally, including a kind CoreDNS Pod; protocol detection was checked against more than ten real services, including Kafka, SQL Server, and gRPC. To attribute bridge-container processes, select their network namespace with `--netns`; see the [measurement rules](docs/user/measurement.md#docker-网络) and [validation record](docs/archive/validation.md).

## Why socktrail

Packets, processes, and domain evidence answer different questions. socktrail brings them into one view while keeping packet bytes separate from socket I/O bytes. It can help you find which process owns a connection, where traffic goes, which interface saw it, and whether a visible Host or SNI identifies the destination.

## Features

- Capture IPv4, IPv6, ARP, and other Ethernet traffic. Automatic selection uses up to eight interfaces; explicit `--interface` selection has no count limit and can include loopback and tun interfaces.
- Capture selected network namespaces with repeatable `--netns` (path, name, `pid:PID`, or `container:ID`); interface labels identify their namespace.
- Group TCP, UDP, ICMP, and other flows; show application protocol hints, connection state, RTT, congestion window, retransmissions, and sampled TCP bottleneck hints (kernel values for local sockets, like `ss -ti`), DNS response time, and ICMP errors.
- Opt into kernel packet drop reason counts with `--drops`; the status screen and JSON snapshot show the totals, and matching connections show their own counts.
- Associate local TCP/UDP sockets with processes and show socket RX/TX separately from captured IP bytes.
- Group processes by systemd service or container, cgroup, process tree, executable basename, or user, and show only chosen processes with `--process`, `--pid` (with descendants), `--cgroup`, or `--container`.
- Show local Docker container and Compose service names, plus Kubernetes Pod names when kubelet log links are available; unreadable metadata falls back to the short container ID.
- Use conntrack data to merge observed flows across NAT address changes when a mapping is available.
- Compute the JA4 fingerprint of each TLS and QUIC ClientHello, which identifies the client TLS library and settings; filter on it with `ja4:`.
- Extract visible HTTP Host, TLS and QUIC SNI, proxy targets, and DNS name hints. Encrypted HTTP request names and real ECH inner names are not available from packet capture.
- Inspect PID, source IP, destination IP, protocol, domain, and per-interface views in the terminal.
- Record the next 15 seconds of packets for a selected connection or PID to a PCAPNG file on demand, optionally starting with the frames of the seconds before.
- Keep default flags in `~/.config/socktrail/config`, generate bash, zsh, or fish completion with `--completion`, and read the full manual with `socktrail --man | man -l -`. `socktrail -h` lists every filter key, and `Tab` completes keys and values on the `/` filter prompt.
- Print a timed snapshot as a text report or a JSON document.
- Stream connection changes as NDJSON and inspect recent changes in the `6 LOG` view.
- Serve that stream on a Unix domain socket for local subscribers, as MessagePack frames: a handshake, a full snapshot, then changes plus a periodic per-process socket I/O summary.
- Inspect listening TCP/UDP ports, owning processes, accept queues, and failed attempts in `7 PORTS`.
- Diagnose failed outbound TCP connects by process, target, and kernel error; inspect connect latency for successful and failed attempts.
- Optionally enrich a selected connection with offline DB-IP Lite country and ASN data.

## Screenshots

These screenshots show socktrail processing synthetic traffic in isolated Linux network namespaces. The `10.20.0.0/24` network is private; the public IPs shown were assigned locally inside the demo namespace, and the `.demo.example` domains are synthetic. No personal traffic or external connections are shown.

### PID

![PID view with processes and connection details](docs/assets/screenshots/pid.png)

### Source IP

![Source IP view with private demo addresses](docs/assets/screenshots/source-ip.png)

### Destination IP

![Destination IP view with demo traffic and GeoIP data](docs/assets/screenshots/destination-ip.png)

### Protocol

![Protocol view with HTTP, TLS, DNS, ICMP, and ARP groups](docs/assets/screenshots/protocol.png)

### Process groups

![Process groups by executable name](docs/assets/screenshots/service.png)

### Domains

![Domain view with HTTP and TLS names](docs/assets/screenshots/domains.png)

### Interfaces

![Interface diagnostics for demo0 and loopback](docs/assets/screenshots/interfaces.png)

## Build and Run

Running socktrail requires Linux and a kernel with BTF, fentry, and BPF ring buffer support: 5.10 or later on x86-64, and 6.4 or later on arm64, where fentry depends on ftrace direct calls. Building from source requires Go 1.27. The eBPF object files are included, so a normal build does not require clang. Run with privileges sufficient for packet capture and eBPF loading; `sudo` is the simplest option.

Prebuilt Linux amd64 and arm64 binaries are available as uncompressed files on [GitHub Releases](https://github.com/jimyag/socktrail/releases). To download, verify, and install the latest release to `/usr/local/bin`:

```sh
curl -fsSL https://raw.githubusercontent.com/jimyag/socktrail/main/install.sh | sh
```

The installer asks for `sudo` if the destination is not writable. For releases after v0.0.1, it also verifies the build provenance attestation when GitHub CLI 2.49 or later is installed and signed in; otherwise it checks only the SHA-256 checksum. Run the installed binary with `sudo socktrail`, or follow the [file capability setup](docs/user/usage.md#不使用-sudo-运行).

### 以 systemd 服务运行

要让 socktrail 作为常驻采集进程、供本机其他程序订阅，可以把它装成 systemd 服务：

```sh
task build
./install-service.sh
```

`install-service.sh` 会把二进制装到 `/usr/local/bin/socktrail`，把 `packaging/socktrail.service` 装到 `/etc/systemd/system`，并启用、启动服务。脚本按自身所在目录定位二进制和 unit，因此在任何工作目录下调用都可以；已安装的服务正在运行时它不擅自重启，只在输出里提示下一步。unit 不用交互界面，而是通过 `/run/socktrail/collector.sock`（权限 `0660`，组 root）持续输出 MessagePack 帧，所以消费方不需要抓包权限，也不必自己拉起或看管 socktrail。日常管理：

```sh
systemctl status socktrail.service
journalctl -u socktrail.service
sudo systemctl restart socktrail.service
```

unit 以 root 运行，带抓包和 eBPF 所需的能力，另加 `CAP_SYS_ADMIN` 以启用 OpenSSL、kTLS 探针和 `--netns`，并用 `LimitMEMLOCK=infinity` 允许提高 eBPF memlock rlimit。改 socket 路径、权限、刷新间隔或采集范围时用 drop-in，不要直接改 unit 文件：

```sh
sudo systemctl edit socktrail.service
```

`--socket-kinds` 是采集端（发布端）的参数，作用于该 socket 上的所有订阅者，不是消费端的过滤条件。只做按进程流量汇总的订阅者可以用它让该 socket 不发布任何 flow 帧：

```sh
sudo socktrail --output msgpack --socket /tmp/socktrail-stats.sock --socket-kinds stats
```

上面的例子用一个独立采集进程和另一个 socket 路径，避免与已安装服务的 `/run/socktrail/collector.sock` 冲突：socktrail 默认单实例运行，这条命令不能和已安装的服务同时使用（确实要并发时加 `--allow-multiple`，那时各实例会各自加载全套 eBPF 程序）。已安装的常驻服务要改采集范围或 socket 参数时，用 `sudo systemctl edit socktrail.service`，不要再启第二个实例。

For a source build, `task` (or `task build`) creates a static binary with the Git version and build time, and `task install` installs it to `/usr/local/bin/socktrail` with the file capabilities needed for packet capture and eBPF. Run `task install` as your normal user; it invokes `sudo` only for installation. Then run `socktrail` without `sudo` for core capture. Use `sudo socktrail` when you need all probes, including OpenSSL process SNI and kernel TLS on hosts that restrict module BTF access.

From the repository root, `go install .` installs the binary to your Go binary directory. It does not set Linux file capabilities.

```sh
CGO_ENABLED=0 go build -o socktrail .
sudo ./socktrail
sudo ./socktrail --interface lo
sudo ./socktrail --interface lo --interface eth0
sudo ./socktrail --interface eth0 --duration 30s --output json
sudo ./socktrail --netns container:0123456789ab --interface eth0
sudo ./socktrail --netns pid:1 --netns pid:12345 --interface lo
./socktrail --read /path/to/socktrail-capture.pcapng
./socktrail --download-geoip-db
./socktrail --version
```

Without `--interface`, socktrail selects up to eight active interfaces: physical interfaces first, then loopback, tunnels, and host bridges. Container veth links, Docker bridges, and VM tap links require an explicit `--interface`; it accepts repeated names, comma-separated names, and glob patterns such as `'veth*,br-*,vnet*'`. Explicit selection has no interface-count limit. Use `ip -br link` to find interface names.

Only one socktrail runs at a time by default: a second process exits before creating any capture resource, with `another socktrail is already running; use --allow-multiple to run more than one`. The guard is an `flock` on `/tmp/socktrail.lock`, released by the kernel when the process exits, including a crash or `SIGKILL`. Pass `--allow-multiple` for a legitimate concurrent run, such as capturing different interfaces or namespaces; it skips the lock entirely, and each run then loads its own full set of eBPF programs.

For CPU and Go heap profiling, add `--pprof 127.0.0.1:6060`, then collect profiles from `/debug/pprof/`. It is off by default and accepts only loopback IP addresses; use an SSH tunnel for remote access. See the [profiling commands and memory accounting limits](docs/user/usage.md#cpu-与内存分析).

Add `--ebpf-stats` to also expose this instance's kernel BPF execution counters, CPU rates and program/map memory estimates at `/debug/ebpf?seconds=5`. This temporarily enables system-wide BPF runtime accounting and requires Linux 5.8+ and sufficient privileges; it is off by default.
`--netns` selects one or more network namespaces; without it, only the current namespace is captured. Each `--interface` pattern is resolved inside every selected namespace and must match there. The target's interface label is prefixed with its namespace name. `container:ID` finds a visible process by a hexadecimal container ID prefix of at least 12 characters.
Replace the example ID and PID with those of the target container or Pod process.
`--interface lo` captures loopback connections only, even with multiple `--netns` targets. For Pod ingress or egress, select its `eth0` and check the actual capture interfaces on the `0` screen or in JSON `interfaces`. With `--drops`, the global drop totals cover every interface in the selected namespaces, including interfaces outside the packet capture selection.

Explicit capture on more than eight interfaces shows the matches and asks for confirmation. It starts in a systemd scope with a 512 MiB memory limit by default. Use `--yes` for non-interactive runs, `--memory-limit=1GiB` to change the limit, or `--memory-limit=none` to opt out of it. A protected run fails before capture if systemd is unavailable.

To run without `sudo`, install the binary with Linux file capabilities. Network capabilities alone do not cover the eBPF probes; see the [capability setup and limitations](docs/user/usage.md#不使用-sudo-运行).

Press `1`–`4` for PID, source IP, destination IP, and protocol views; `5` for process groups, where `b` switches between service, cgroup, process tree, executable basename, and user; `6` for the LOG view (`b` switches change groups); `7` for listening ports; `d` for domains; `0` for interface diagnostics; `?` for help; and `q` to quit. Press `g` to show or hide GeoIP for both endpoints, or to download the databases from inside the TUI when missing. Select a connection or PID and press `c` to start or stop a PCAPNG recording; start with `--record-before 10s` to include the ten seconds before the key press. Recordings go to `$XDG_STATE_HOME/socktrail/captures` (usually `~/.local/state/socktrail/captures`) by default and may contain plaintext application data. Use `--capture-dir /tmp/...` for temporary files.

Run `socktrail --download-geoip-db` as your normal user to install optional [DB-IP Lite](https://db-ip.com/db/lite.php) country and ASN databases in `$XDG_DATA_HOME/socktrail/geoip` (usually `~/.local/share/socktrail/geoip`). Capture never downloads automatically and still works without them; pressing `g` in the TUI offers an explicit download. When enabled, the connection table shows country flag, ASN number, and a short organization name separately for source and target public IPs. The selected connection detail and JSON snapshots retain full names; `--geoip-dir` selects another database directory. DB-IP Lite is licensed under CC BY 4.0.

## Documentation

The [documentation index](docs/README.md) groups the Chinese user guides, implementation notes, and historical validation record. See also the [简体中文 README](README.zh-CN.md).

## Development

```sh
go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.14.0 run ./...
go test -race ./...
CGO_ENABLED=0 go build .
```

GitHub Actions also checks Go formatting on pushes to `main` and pull requests, runs the probe and capture tests as root on amd64 and arm64 runners, takes a snapshot of test traffic with `test/smoke.sh`, and checks that the committed eBPF objects match their sources. The [kernel matrix](.github/workflows/kernels.yaml) boots each distribution kernel of `test/vm/kernels.txt` in QEMU with `test/vm/run.sh`, one job per kernel, weekly and whenever the probes change; run it locally with `test/vm/run.sh amd64` or `test/vm/run.sh arm64`, optionally followed by kernel names.

## Release

Pushing a `v*` tag runs the checks, then GoReleaser publishes static Linux amd64 and arm64 binaries plus `checksums.txt` to [GitHub Releases](https://github.com/jimyag/socktrail/releases), and the workflow attests their build provenance; check a downloaded binary with `gh attestation verify socktrail_linux_amd64 --repo jimyag/socktrail`. Release notes list commits since the previous tag. `socktrail --version` prints the tag, build time, and Go version. Run `goreleaser release --snapshot --clean` to check the release build locally.
