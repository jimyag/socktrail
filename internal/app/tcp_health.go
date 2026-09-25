package app

import (
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/jimyag/socktrail/internal/capture"
	"github.com/jimyag/socktrail/internal/probe"
)

const maxTrackedTCPSegments = 128

type sequenceRange struct{ start, end uint32 }

func (r sequenceRange) overlaps(other sequenceRange) bool {
	//nolint:gosec // G115: TCP sequence arithmetic intentionally wraps in its 32-bit wire space.
	return int32(r.start-other.end) < 0 && int32(other.start-r.end) < 0
}

type tcpHealth struct {
	SynRTT         time.Duration
	Retransmits    uint64 // Overlapping captured segments: a guess from the capture point.
	ConnectResult  int32  // errno from the kernel; zero for a successful or aborted connect.
	ConnectLatency uint32 // Time from SYN_SENT to the result, in microseconds.
	// Each local end's socket as the kernel last reported it, indexed like
	// the key's A and B; zero for an end that is not a local socket.
	Kernel      [2]probe.TCPInfo
	synAt       time.Time
	synFrom     netip.AddrPort
	synSeq      uint32
	synSeen     [2]bool
	synSeqByDir [2]uint32
	seen        [2][]sequenceRange
}

// observeKernel records a local end's socket state from a TCP event. The
// counters only grow; events from different CPUs may arrive out of order.
func (h *tcpHealth) observeKernel(side int, info probe.TCPInfo) {
	k := &h.Kernel[side]
	retransmits, segments := max(k.Retransmits, info.Retransmits), max(k.SegsOut, info.SegsOut)
	*k = info
	k.Retransmits, k.SegsOut = retransmits, segments
}

// kernelSides returns the flow's ends with kernel state, the initiator's
// first: its round trip is the one a client sees.
func kernelSides(f *flow) []int {
	first := 0
	if f.Initiator.IsValid() && f.Initiator == f.Key.B {
		first = 1
	}
	var sides []int
	for _, side := range []int{first, 1 - first} {
		if f.Health.Kernel[side] != (probe.TCPInfo{}) {
			sides = append(sides, side)
		}
	}
	return sides
}

// retransmits returns the retransmissions to show and their source. A flow
// with a local socket has the kernel's own count, zero until the kernel
// reports one; a flow only passing through has the capture's guess.
func retransmits(f *flow) (uint64, string) {
	kernel := f.Health.Kernel
	if len(kernelSides(f)) > 0 || f.Client.PID > 0 || f.Server.PID > 0 {
		return uint64(kernel[0].Retransmits) + uint64(kernel[1].Retransmits), "kernel"
	}
	return f.Health.Retransmits, "capture"
}

// flowRTT returns the round-trip time to show and its source: a local
// socket's smoothed RTT from the kernel, which follows the whole connection,
// or else the capture's one handshake sample.
func flowRTT(f *flow) (time.Duration, string) {
	for _, side := range kernelSides(f) {
		if rtt := f.Health.Kernel[side].RTT; rtt > 0 {
			return rtt, "kernel"
		}
	}
	if f.Health.SynRTT > 0 {
		return f.Health.SynRTT, "SYN"
	}
	return 0, ""
}

// kernelDetail describes each local end's socket as ss -ti would.
func kernelDetail(f *flow) string {
	var parts []string
	for _, side := range kernelSides(f) {
		k, end := f.Health.Kernel[side], f.Key.A
		if side == 1 {
			end = f.Key.B
		}
		part := fmt.Sprintf("%s rtt %s±%s cwnd %d sent %d retrans %d", end, formatSYNRTT(k.RTT), formatSYNRTT(k.RTTVar), k.Cwnd, k.SegsOut, k.Retransmits)
		if k.SegsOut > 0 {
			part += fmt.Sprintf(" (%.2f%%)", float64(k.Retransmits)*100/float64(k.SegsOut))
		}
		parts = append(parts, part)
	}
	return strings.Join(parts, "; ")
}

func formatSYNRTT(value time.Duration) string {
	if value <= 0 {
		return "-"
	}
	return value.Round(time.Microsecond).String()
}

func (h *tcpHealth) observe(p capture.Packet, loopback bool) {
	if p.Protocol != 6 {
		return
	}
	now := p.CapturedAt
	if now.IsZero() {
		now = time.Now()
	}
	retransmitted := false
	index := 0
	if p.Source.Compare(p.Destination) > 0 {
		index = 1
	}
	if p.SYN && !p.ACK {
		if h.synSeen[index] && h.synSeqByDir[index] == p.TCPSeq {
			retransmitted = true
		} else {
			h.synSeen[index], h.synSeqByDir[index] = true, p.TCPSeq
		}
	}
	if p.SYN && !p.ACK && p.Outgoing && !loopback {
		if h.synAt.IsZero() || h.synSeq != p.TCPSeq || h.synFrom != p.Source {
			h.synAt, h.synSeq, h.synFrom = now, p.TCPSeq, p.Source
		}
	}
	if p.SYN && p.ACK && !p.Outgoing && !h.synAt.IsZero() && h.SynRTT == 0 && p.Destination == h.synFrom && p.TCPAck == h.synSeq+1 && now.After(h.synAt) {
		h.SynRTT = now.Sub(h.synAt)
	}
	if len(p.Payload) > 0 && !p.PayloadTruncated && !p.Truncated {
		start := p.TCPSeq
		if p.SYN {
			start++
		}
		//nolint:gosec // G115: TCP sequence arithmetic intentionally wraps in its 32-bit wire space.
		span := sequenceRange{start: start, end: start + uint32(len(p.Payload))}
		//nolint:modernize // This packet hot path avoids a callback in the overlap scan.
		for _, prior := range h.seen[index] {
			if span.overlaps(prior) {
				retransmitted = true
				break
			}
		}
		if len(h.seen[index]) == maxTrackedTCPSegments {
			copy(h.seen[index], h.seen[index][1:])
			h.seen[index][len(h.seen[index])-1] = span
		} else {
			h.seen[index] = append(h.seen[index], span)
		}
	}
	if retransmitted {
		h.Retransmits++
	}
}
