package probe

import (
	"net/netip"
	"sync/atomic"
)

// Event is a local socket operation observed in the selected network namespace.
type Event struct {
	Protocol  uint8
	Family    int
	Role      string
	Operation string
	AppBytes  uint64
	PID       int
	StartNS   uint64
	Process   string
	NetNS     uint64
	Local     netip.AddrPort
	Remote    netip.AddrPort
}

type Statistics struct {
	Received   atomic.Uint64
	KernelLost atomic.Uint64
	Dropped    atomic.Uint64
	Invalid    atomic.Uint64
}
