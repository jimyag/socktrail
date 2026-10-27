module github.com/jimyag/socktrail

go 1.27

toolchain go1.27.3

require (
	github.com/charmbracelet/x/ansi v0.11.9
	github.com/cilium/ebpf v0.22.0
	github.com/jimmicro/version v1.1.0
	github.com/oschwald/geoip2-golang/v2 v2.5.0
	github.com/vmihailenco/msgpack/v5 v5.4.1
	golang.org/x/net v0.62.0
	golang.org/x/sys v0.49.0
	golang.org/x/term v0.47.0
)

require (
	github.com/clipperhouse/displaywidth v0.11.0 // indirect
	github.com/clipperhouse/uax29/v2 v2.7.0 // indirect
	github.com/lucasb-eyer/go-colorful v1.4.1 // indirect
	github.com/mattn/go-runewidth v0.0.31 // indirect
	github.com/oschwald/maxminddb-golang/v2 v2.8.0 // indirect
	github.com/vmihailenco/tagparser/v2 v2.0.0 // indirect
)

tool github.com/cilium/ebpf/cmd/bpf2go
