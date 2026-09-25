package probe

import (
	"net/netip"
	"sync/atomic"
	"time"
)

// Event is a local socket operation observed in the selected network namespace.
type Event struct {
	Protocol  uint8
	Family    int
	Role      string
	Operation string // connect, accept, send, recv or retransmit. A retransmit has no process.
	AppBytes  uint64
	PID       int
	StartNS   uint64
	Process   string
	// The process's parent and cgroup v2 ID (the inode of its cgroup
	// directory) at the time of the event.
	ParentPID      int
	ParentStartNS  uint64
	CgroupID       uint64
	NetNS          uint64
	Local          netip.AddrPort
	Remote         netip.AddrPort
	TCP            TCPInfo // TCP events only.
	Result         int32   // connect_result: errno, zero for success, -1 for application abort.
	ConnectLatency uint32  // connect_result: time from SYN_SENT in microseconds.
}

// TCPInfo is a TCP socket's state after a call, as ss -ti shows it.
type TCPInfo struct {
	RTT, RTTVar time.Duration // Smoothed round-trip time and its mean deviation.
	Cwnd        uint32        // Congestion window, in segments.
	SegsOut     uint32        // Data segments sent.
	Retransmits uint32        // Segments retransmitted, in total.
}

type Statistics struct {
	Received      atomic.Uint64
	ConnectEvents atomic.Uint64
	ConnectStatus string
	KernelLost    atomic.Uint64
	Dropped       atomic.Uint64
	Invalid       atomic.Uint64
}
