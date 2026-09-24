package main

import (
	"fmt"
	"net/netip"
	"time"

	"github.com/jimyag/socktrail/internal/capture"
	"github.com/jimyag/socktrail/internal/probe"
)

// ponytail: outstanding echo requests reset past 64, losing RTT samples for a
// flood; per-sequence expiry if long unanswered bursts need exact RTTs.
const maxPendingEchoes = 64

// icmpState summarizes one ICMP flow. Echo requests and replies share a flow
// per identifier, so a ping flood stays one entry instead of one per packet;
// other messages share a flow per type and code between two hosts.
type icmpState struct {
	Requests, Replies uint64
	LastSeq           uint16
	RTT, MinRTT       time.Duration
	pending           map[uint16]time.Time
	Value             uint32
	Target            netip.Addr
	QuotedProtocol    uint8
	Quoted            [2]netip.AddrPort
}

func echoRequest(p capture.Packet) bool {
	return p.ICMPHasEcho && (p.Protocol == 1 && p.ICMPType == 8 || p.Protocol == 58 && p.ICMPType == 128)
}

// echoKey names a local ping: the pinged address and the echo identifier.
type echoKey struct {
	peer     netip.Addr
	id       uint16
	protocol uint8
}

// echoOwner joins the process that sent a ping with the flow its requests
// formed. Either may be seen first: the probe fires as the request is sent.
type echoOwner struct {
	process participant
	flow    *flow
	seen    time.Time
}

const echoOwnerIdle = time.Minute

// echoOwnerFor returns the entry for key and whether it may be stored.
func (c *collector) echoOwnerFor(key echoKey) (echoOwner, bool) {
	if c.echoOwners == nil {
		c.echoOwners = make(map[echoKey]echoOwner)
	}
	owner, known := c.echoOwners[key]
	return owner, known || len(c.echoOwners) < c.maxFlows
}

// echoSent records the process behind an echo request sent from this host.
func (c *collector) echoSent(e probe.Event) {
	key := echoKey{e.Remote.Addr(), e.Local.Port(), e.Protocol}
	owner, ok := c.echoOwnerFor(key)
	if !ok {
		return
	}
	owner.process, owner.seen = participant{PID: e.PID, StartNS: e.StartNS, Name: e.Process}, time.Now()
	if owner.flow != nil {
		owner.flow.Client = owner.process
	}
	c.echoOwners[key] = owner
}

// echoFlow links an outgoing echo request's flow to the process that sent it.
func (c *collector) echoFlow(f *flow, p capture.Packet, at time.Time) {
	key := echoKey{p.Destination.Addr(), p.ICMPID, p.Protocol}
	owner, ok := c.echoOwnerFor(key)
	if !ok {
		return
	}
	owner.flow, owner.seen = f, at
	if owner.process.PID != 0 {
		f.Client = owner.process
	}
	c.echoOwners[key] = owner
}

func (c *collector) direction(p capture.Packet) string {
	switch {
	case c.loopback:
		return "local"
	case p.Outgoing:
		return "outbound"
	}
	return "inbound"
}

// icmp updates a flow's ICMP summary. An error also marks the TCP or UDP flow
// it quotes, such as an inbound datagram answered with port-unreachable.
func (c *collector) icmp(f *flow, p capture.Packet) {
	at := p.CapturedAt
	if at.IsZero() {
		at = time.Now()
	}
	s := &f.ICMP
	if p.ICMPHasEcho {
		s.LastSeq = p.ICMPSeq
		if !echoRequest(p) {
			s.Replies++
			if sent, ok := s.pending[p.ICMPSeq]; ok {
				delete(s.pending, p.ICMPSeq)
				s.RTT = at.Sub(sent)
				if s.MinRTT == 0 || s.RTT < s.MinRTT {
					s.MinRTT = s.RTT
				}
			}
			return
		}
		if s.Requests == 0 {
			// The first request, not a reply seen first, names the pinging side.
			f.Initiator, f.Target, f.Direction = p.Source, p.Destination, c.direction(p)
		}
		if p.Outgoing {
			c.echoFlow(f, p, at)
		}
		s.Requests++
		if s.pending == nil || len(s.pending) >= maxPendingEchoes {
			s.pending = make(map[uint16]time.Time)
		}
		s.pending[p.ICMPSeq] = at
		return
	}
	if p.ICMPValue != 0 {
		s.Value = p.ICMPValue
	}
	if p.ICMPTarget.IsValid() {
		s.Target = p.ICMPTarget
	}
	if p.QuotedProtocol == 0 {
		return
	}
	s.QuotedProtocol, s.Quoted = p.QuotedProtocol, [2]netip.AddrPort{p.QuotedSource, p.QuotedDestination}
	if referenced := c.flows[keyFor(p.QuotedSource, p.QuotedDestination, p.QuotedProtocol)]; referenced != nil {
		unreachable := p.Protocol == 1 && p.ICMPType == 3 || p.Protocol == 58 && p.ICMPType == 1
		if unreachable && referenced.ICMPError == "" && referenced.Key.Protocol == 17 && p.Source.Addr() == referenced.Target.Addr() {
			c.noteAttempt(referenced, true, at) // The target refused a datagram, as a UDP scan finds out.
		}
		referenced.ICMPError = icmpName(p.Protocol, p.ICMPType, p.ICMPCode)
	}
}

var (
	icmpUnreachable = []string{"net-unreachable", "host-unreachable", "protocol-unreachable", "port-unreachable",
		"frag-needed", "source-route-failed", "net-unknown", "host-unknown", "source-host-isolated",
		"net-prohibited", "host-prohibited", "net-tos-unreachable", "host-tos-unreachable", "admin-prohibited"}
	icmp6Unreachable = []string{"no-route", "admin-prohibited", "beyond-scope", "address-unreachable",
		"port-unreachable", "source-policy-failed", "reject-route"}
	icmpNames = map[uint8]string{0: "echo", 8: "echo", 4: "source-quench", 5: "redirect", 9: "router-advertisement",
		10: "router-solicitation", 11: "ttl-exceeded", 12: "parameter-problem", 13: "timestamp", 14: "timestamp"}
	icmp6Names = map[uint8]string{2: "packet-too-big", 3: "hop-limit-exceeded", 4: "parameter-problem", 128: "echo",
		129: "echo", 130: "mld-query", 131: "mld-report", 132: "mld-done", 133: "router-solicitation",
		134: "router-advertisement", 135: "neighbor-solicitation", 136: "neighbor-advertisement", 137: "redirect",
		143: "mld-report"}
)

// icmpName is a short label for an ICMP or ICMPv6 type and code.
func icmpName(protocol, kind, code uint8) string {
	unreachable, names, unreachableType := icmpUnreachable, icmpNames, uint8(3)
	if protocol == 58 {
		unreachable, names, unreachableType = icmp6Unreachable, icmp6Names, 1
	}
	switch {
	case kind == unreachableType && int(code) < len(unreachable):
		return unreachable[code]
	case kind == unreachableType:
		return fmt.Sprintf("unreachable code=%d", code)
	case (protocol == 1 && kind == 11 || protocol == 58 && kind == 3) && code == 1:
		return "reassembly-timeout"
	case names[kind] != "":
		return names[kind]
	}
	return fmt.Sprintf("type=%d code=%d", kind, code)
}

// icmpDescription names an ICMP flow for the connection table.
func icmpDescription(f *flow) string {
	s := f.ICMP
	if f.Key.ICMPEcho {
		text := fmt.Sprintf("echo id=%d requests=%d replies=%d seq=%d", f.Key.ICMPID, s.Requests, s.Replies, s.LastSeq)
		if s.RTT > 0 {
			text += fmt.Sprintf(" rtt=%s min=%s", formatSYNRTT(s.RTT), formatSYNRTT(s.MinRTT))
		}
		return text
	}
	text := icmpName(f.Key.Protocol, f.Key.ICMPType, f.Key.ICMPCode)
	if s.Value != 0 {
		text += fmt.Sprintf(" mtu=%d", s.Value)
	}
	if s.Target.IsValid() {
		text += " " + s.Target.String()
	}
	if s.QuotedProtocol != 0 {
		text += fmt.Sprintf(" for %s %s→%s", protocolName(s.QuotedProtocol), formatFlowEndpoint(s.Quoted[0], s.QuotedProtocol), formatFlowEndpoint(s.Quoted[1], s.QuotedProtocol))
	}
	return text
}

// flowState is the STATE column: the TCP state plus any ICMP error the flow
// received, which is the only state a UDP flow has.
func flowState(f *flow) string {
	switch {
	case f.ICMPError == "":
		return f.TCPState
	case f.TCPState == "":
		return f.ICMPError
	}
	return f.TCPState + ", " + f.ICMPError
}
