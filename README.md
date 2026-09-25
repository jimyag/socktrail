<h1 align="center">socktrail</h1>

<p align="center">
  <strong>See Linux network traffic, connections, processes, and visible domains in one terminal.</strong>
</p>

<p align="center">
  <a href="https://github.com/jimyag/socktrail/actions/workflows/check.yaml"><img src="https://github.com/jimyag/socktrail/actions/workflows/check.yaml/badge.svg" alt="Check"></a>
  <a href="https://github.com/jimyag/socktrail/actions/workflows/kernels.yaml"><img src="https://github.com/jimyag/socktrail/actions/workflows/kernels.yaml/badge.svg" alt="Kernels"></a>
  <a href="https://github.com/jimyag/socktrail/actions/workflows/release.yaml"><img src="https://github.com/jimyag/socktrail/actions/workflows/release.yaml/badge.svg" alt="Release"></a>
</p>

<p align="center">
  <a href="#why-socktrail">Why socktrail</a> ·
  <a href="#features">Features</a> ·
  <a href="#build-and-run">Build and Run</a> ·
  <a href="#documentation">Documentation</a>
</p>

<p align="center">
  <strong>English</strong> · <a href="README.zh-CN.md">简体中文</a>
</p>

---

socktrail is a Linux terminal application for inspecting live network traffic. It captures packets from selected interfaces with AF_PACKET and uses eBPF socket probes and the kernel socket table to associate local traffic with processes. The interface shows connections, IP traffic, application protocols, and domain names found in observable HTTP, TLS, QUIC, proxy, and DNS data.

It is a prototype. It has been tested on a Linux 6.8 host; probe loading and loopback traffic are also checked in virtual machines on x86-64 kernels from 5.10 to 7.0, including CentOS Stream 9 and 10, and on arm64 kernels 6.4 and 6.8; CI runs the root tests on amd64 and arm64 runners. Container networking has not been validated. See the [validation record](docs/validation.md) and [detailed Chinese guide](README.zh-CN.md) for measurement rules and known limits.

## Why socktrail

Packets, processes, and domain evidence answer different questions. socktrail brings them into one view while keeping packet bytes separate from socket I/O bytes. It can help you find which process owns a connection, where traffic goes, which interface saw it, and whether a visible Host or SNI identifies the destination.

## Features

- Capture IPv4, IPv6, ARP, and other Ethernet traffic across up to eight selected interfaces, including loopback and tun interfaces.
- Group TCP, UDP, ICMP, and other flows; show application protocol hints, connection state, RTT, congestion window and retransmissions (the kernel's values for local sockets, like `ss -ti`), DNS response time, and ICMP errors.
- Associate local TCP/UDP sockets with processes and show socket RX/TX separately from captured IP bytes.
- Group processes by systemd service or container, by cgroup, or by process tree, and show only chosen processes with `--process`, `--pid` (with descendants), or `--cgroup`.
- Use conntrack data to merge observed flows across NAT address changes when a mapping is available.
- Extract visible HTTP Host, TLS and QUIC SNI, proxy targets, and DNS name hints. Encrypted HTTP request names and real ECH inner names are not available from packet capture.
- Inspect PID, source IP, destination IP, protocol, domain, and per-interface views in the terminal.
- Record the next 15 seconds of packets for a selected connection or PID to a PCAPNG file on demand, optionally starting with the frames of the seconds before.
- Print a timed snapshot as a text report or a JSON document.

## Build and Run

Running socktrail requires Linux and a kernel with BTF, fentry, and BPF ring buffer support: 5.10 or later on x86-64, and 6.4 or later on arm64, where fentry depends on ftrace direct calls. Building from source requires Go 1.27. The eBPF object files are included, so a normal build does not require clang. Run with privileges sufficient for packet capture and eBPF loading; `sudo` is the simplest option.

Prebuilt Linux amd64 and arm64 binaries are available as uncompressed files on [GitHub Releases](https://github.com/jimyag/socktrail/releases). To download, verify, and install the latest release to `/usr/local/bin`:

```sh
curl -fsSL https://raw.githubusercontent.com/jimyag/socktrail/main/install.sh | sh
```

The installer asks for `sudo` if the destination is not writable. For releases after v0.0.1, it also verifies the build provenance attestation when GitHub CLI 2.49 or later is installed and signed in; otherwise it checks only the SHA-256 checksum. Run the installed binary with `sudo socktrail`, or follow the [file capability setup](docs/usage.md#不使用-sudo-运行).

```sh
CGO_ENABLED=0 go build -o socktrail ./cmd/socktrail
sudo ./socktrail
sudo ./socktrail --interface lo
sudo ./socktrail --interface lo --interface eth0
sudo ./socktrail --interface eth0 --duration 30s --output json
./socktrail --version
```

Without `--interface`, socktrail selects up to eight active interfaces: physical interfaces first, then loopback, tunnels, and host bridges. Container veth links, Docker bridges, and VM tap links require an explicit `--interface`; it accepts repeated names, comma-separated names, and glob patterns such as `'veth*,br-*,vnet*'`. Explicit selection has no interface-count limit. Use `ip -br link` to find interface names.

To run without `sudo`, install the binary with Linux file capabilities. Network capabilities alone do not cover the eBPF probes; see the [capability setup and limitations](docs/usage.md#不使用-sudo-运行).

Press `1`–`4` for PID, source IP, destination IP, and protocol views; `5` for services, where `g` switches between service, cgroup, and process tree groups; `d` for domains; `0` for interface diagnostics; `?` for help; and `q` to quit. Select a connection or PID and press `c` to start or stop a PCAPNG recording; start with `--record-before 10s` to include the ten seconds before the key press. Recordings are written to `socktrail-captures/` by default and may contain plaintext application data.

## Documentation

| Document | Contents |
| --- | --- |
| [简体中文 README](README.zh-CN.md) | Chinese overview and documentation index |
| [Usage](docs/usage.md) | Build, controls, process details, and PCAPNG recording (Chinese) |
| [Implementation](docs/architecture.md) | Capture, eBPF, process association, NAT, and packet handling (Chinese) |
| [Parsing](docs/parsing.md) | HTTP, TLS, QUIC, proxies, DNS, and domain evidence (Chinese) |
| [Measurements](docs/measurement.md) | Byte accounting, connection direction, diagnostics, and limits (Chinese) |
| [Validation record](docs/validation.md) | Tested kernels, scenarios, and remaining gaps (Chinese) |
| [UI guide](docs/ui-design.md) | Screen layout and interaction (Chinese) |
| [Roadmap](docs/roadmap.md) | Planned release, CI, feature, resource, and validation work (Chinese) |

## Development

```sh
go vet ./...
go test -race ./...
CGO_ENABLED=0 go build ./cmd/socktrail
```

GitHub Actions also checks Go formatting on pushes to `main` and pull requests, runs the probe and capture tests as root on amd64 and arm64 runners, takes a snapshot of test traffic with `test/smoke.sh`, and checks that the committed eBPF objects match their sources. The [kernel matrix](.github/workflows/kernels.yaml) boots each distribution kernel of `test/vm/kernels.txt` in QEMU with `test/vm/run.sh`, one job per kernel, weekly and whenever the probes change; run it locally with `test/vm/run.sh amd64` or `test/vm/run.sh arm64`, optionally followed by kernel names.

## Release

Pushing a `v*` tag runs the checks, then GoReleaser publishes static Linux amd64 and arm64 binaries plus `checksums.txt` to [GitHub Releases](https://github.com/jimyag/socktrail/releases), and the workflow attests their build provenance; check a downloaded binary with `gh attestation verify socktrail_linux_amd64 --repo jimyag/socktrail`. `socktrail --version` prints the tag, build time, and Go version. Run `goreleaser release --snapshot --clean` to check the release build locally.
