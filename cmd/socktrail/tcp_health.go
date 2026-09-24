package main

import (
	"net/netip"
	"time"

	"github.com/jimyag/socktrail/internal/capture"
)

const maxTrackedTCPSegments = 128

type sequenceRange struct{ start, end uint32 }

func (r sequenceRange) overlaps(other sequenceRange) bool {
	return int32(r.start-other.end) < 0 && int32(other.start-r.end) < 0
}

type tcpHealth struct {
	SynRTT      time.Duration
	Retransmits uint64
	synAt       time.Time
	synFrom     netip.AddrPort
	synSeq      uint32
	synSeen     [2]bool
	synSeqByDir [2]uint32
	seen        [2][]sequenceRange
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
		span := sequenceRange{start: start, end: start + uint32(len(p.Payload))}
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
