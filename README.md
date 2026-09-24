<h1 align="center">socktrail</h1>

<p align="center">
  <strong>See Linux network traffic, connections, processes, and visible domains in one terminal.</strong>
</p>

<p align="center">
  <a href="https://github.com/jimyag/socktrail/actions/workflows/check.yaml"><img src="https://github.com/jimyag/socktrail/actions/workflows/check.yaml/badge.svg" alt="Check"></a>
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

It is a prototype. It has been tested on a Linux 6.8 host; probe loading and loopback traffic have also been checked on several kernels from 5.10 to 7.0 in virtual machines. Container networking and arm64 have not been validated. See the [validation record](docs/validation.md) and [detailed Chinese guide](README.zh-CN.md) for measurement rules and known limits.

## Why socktrail

Packets, processes, and domain evidence answer different questions. socktrail brings them into one view while keeping packet bytes separate from socket I/O bytes. It can help you find which process owns a connection, where traffic goes, which interface saw it, and whether a visible Host or SNI identifies the destination.

## Features

- Capture IPv4, IPv6, ARP, and other Ethernet traffic across up to eight selected interfaces, including loopback and tun interfaces.
- Group TCP, UDP, ICMP, and other flows; show application protocol hints, connection state, SYN RTT, retransmission hints, and ICMP errors.
- Associate local TCP/UDP sockets with processes and show socket RX/TX separately from captured IP bytes.
- Use conntrack data to merge observed flows across NAT address changes when a mapping is available.
- Extract visible HTTP Host, TLS and QUIC SNI, proxy targets, and DNS name hints. Encrypted HTTP request names and real ECH inner names are not available from packet capture.
- Inspect PID, source IP, destination IP, protocol, domain, and per-interface views in the terminal.
- Record the next 15 seconds of packets for a selected connection or PID to a PCAPNG file on demand.

## Build and Run

Running socktrail requires Linux and a kernel with BTF, fentry, and BPF ring buffer support. Building from source requires Go 1.27. The eBPF object files are included, so a normal build does not require clang. Run with privileges sufficient for packet capture and eBPF loading; `sudo` is the simplest option.

After the first release, prebuilt Linux binaries will be available from [GitHub Releases](https://github.com/jimyag/socktrail/releases).

```sh
CGO_ENABLED=0 go build -o socktrail ./cmd/socktrail
sudo ./socktrail
sudo ./socktrail --interface lo
sudo ./socktrail --interface lo --interface eth0
./socktrail --version
```

Without `--interface`, socktrail selects up to eight active host interfaces. Use `ip -br link` to find interface names. `--interface` also accepts comma-separated names.

To run without `sudo`, install the binary with Linux file capabilities. Network capabilities alone do not cover the eBPF probes; see the [capability setup and limitations](docs/usage.md#不使用-sudo-运行).

Press `1`–`4` for PID, source IP, destination IP, and protocol views; `d` for domains; `0` for interface diagnostics; `?` for help; and `q` to quit. Select a connection or PID and press `c` to start or stop a PCAPNG recording. Recordings are written to `socktrail-captures/` by default and may contain plaintext application data.

## Documentation

| Document | Contents |
| --- | --- |
| [简体中文 README](README.zh-CN.md) | Chinese overview and documentation index |
| [Usage](docs/usage.md) | Build, controls, process details, and PCAPNG recording (Chinese) |
| [Implementation](docs/architecture.md) | Capture, eBPF, process association, NAT, and packet handling (Chinese) |
| [Parsing](docs/parsing.md) | HTTP, TLS, QUIC, proxies, DNS, and domain evidence (Chinese) |
| [Measurements](docs/measurement.md) | Byte accounting, connection direction, diagnostics, and limits (Chinese) |
| [Validation record](docs/validation.md) | Tested kernels, scenarios, and remaining gaps (Chinese) |
| [Development notes](docs/development.md) | Design and implementation details (Chinese) |
| [UI guide](docs/ui-design.md) | Screen layout and interaction (Chinese) |

## Development

```sh
go vet ./...
go test -race ./...
CGO_ENABLED=0 go build ./cmd/socktrail
```

GitHub Actions also checks Go formatting on pushes to `main` and pull requests.

## Release

Pushing a `v*` tag runs the checks, then GoReleaser publishes static Linux amd64 and arm64 binaries plus `checksums.txt` to [GitHub Releases](https://github.com/jimyag/socktrail/releases). `socktrail --version` prints the tag, build time, and Go version. Run `goreleaser release --snapshot --clean` to check the release build locally. arm64 builds have not yet been tested at runtime.
