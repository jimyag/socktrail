package tlsprobe

import (
	"net/netip"
	"sync/atomic"
)

type Event struct {
	PID      int
	StartNS  uint64
	NetNS    uint64
	Local    netip.AddrPort
	Remote   netip.AddrPort
	Hostname string
	Source   string
	Process  string
}

type Statistics struct {
	Received atomic.Uint64
	Invalid  atomic.Uint64
	Dropped  atomic.Uint64
}
