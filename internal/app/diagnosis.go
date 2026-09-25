package app

import (
	"fmt"
	"syscall"
)

// Rules are ordered by the strength of their evidence. One connection gets
// one diagnosis so a precise kernel drop reason wins over a broad symptom.
var diagnosisRules = []struct {
	match   func(*flow) bool
	explain func(*flow) string
}{
	{func(f *flow) bool { return dropCount(f, "NETFILTER_DROP") > 0 }, func(f *flow) string {
		return fmt.Sprintf("Netfilter dropped %d packets; inspect local firewall rules", dropCount(f, "NETFILTER_DROP"))
	}},
	{func(f *flow) bool { return dropCount(f, "NO_SOCKET") > 0 }, func(f *flow) string {
		return fmt.Sprintf("No matching local socket for %d packets; check the listener and destination port", dropCount(f, "NO_SOCKET"))
	}},
	{func(f *flow) bool { return dropCount(f, "SOCKET_RCVBUFF") > 0 }, func(f *flow) string {
		return fmt.Sprintf("Receive buffer dropped %d packets; check the reader and socket buffer size", dropCount(f, "SOCKET_RCVBUFF"))
	}},
	{func(f *flow) bool { return hasTCPLimit(f, "peer window") }, func(*flow) string {
		return "Peer receive window limited sending; check how quickly the peer reads"
	}},
	{func(f *flow) bool { return hasTCPLimit(f, "send buffer") }, func(*flow) string {
		return "Local send buffer limited sending; check SO_SNDBUF and tcp_wmem"
	}},
	{func(f *flow) bool { return hasTCPLimit(f, "application") }, func(*flow) string {
		return "Application limited the sending rate; check its write rate"
	}},
	{func(f *flow) bool { return hasTCPLimit(f, "network") }, func(*flow) string {
		return "Retransmissions or RTT variation suggest network trouble; inspect the path"
	}},
	{func(f *flow) bool { return f.Health.ConnectResult == int32(syscall.ECONNREFUSED) }, func(*flow) string {
		return "Connection refused; check the destination listener and firewall reject rules"
	}},
	{func(f *flow) bool { return f.Health.ConnectResult == int32(syscall.ETIMEDOUT) }, func(*flow) string {
		return "Connection timed out; check routing and firewall rules along the path"
	}},
}

func diagnosis(f *flow) string {
	for _, rule := range diagnosisRules {
		if rule.match(f) {
			return rule.explain(f)
		}
	}
	return ""
}

func dropCount(f *flow, reason string) uint64 {
	if f.Drops == nil {
		return 0
	}
	return f.Drops.reasons[reason]
}

func hasTCPLimit(f *flow, limit string) bool {
	for _, side := range kernelSides(f) {
		if tcpLimit(f.Health.Kernel[side]) == limit {
			return true
		}
	}
	return false
}
