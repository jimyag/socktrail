package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"maps"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/jimyag/socktrail/internal/appproto"
	"github.com/jimyag/socktrail/internal/capture"
	"github.com/jimyag/socktrail/internal/domain"
	"github.com/jimyag/socktrail/internal/probe"
	"github.com/jimyag/socktrail/internal/quicinitial"
	"github.com/jimyag/socktrail/internal/sockstream"
	"github.com/jimyag/socktrail/internal/tlsprobe"
)

type flowKey struct {
	A, B      netip.AddrPort
	Protocol  uint8
	EtherType uint16 // Non-zero for frames without an IP header.
	ICMPType  uint8
	ICMPCode  uint8
	ICMPID    uint16
	ICMPEcho  bool
}

func keyFor(a, b netip.AddrPort, protocol uint8) flowKey {
	if a.Compare(b) > 0 {
		a, b = b, a
	}
	return flowKey{A: a, B: b, Protocol: protocol}
}

func packetKey(p capture.Packet) flowKey {
	key := keyFor(p.Source, p.Destination, p.Protocol)
	key.EtherType = p.EtherType
	if p.EtherType == 0 && (p.Protocol == 1 || p.Protocol == 58) {
		if p.ICMPHasEcho {
			// Requests and replies of one ping session share a flow.
			key.ICMPID, key.ICMPEcho = p.ICMPID, true
		} else {
			key.ICMPType, key.ICMPCode = p.ICMPType, p.ICMPCode
		}
	}
	return key
}

type participant struct {
	PID     int
	StartNS uint64
	Name    string
}

type processID struct {
	PID     int
	StartNS uint64
}

func (p participant) id() processID { return processID{PID: p.PID, StartNS: p.StartNS} }

type ioBytes struct{ RX, TX uint64 }
type processIO struct {
	Name string
	ioBytes
}

type pendingIOSample struct {
	Process   processID
	Operation string
	Bytes     uint64
	Seen      time.Time
}

const maxPendingIOSamples = 4096

type roles struct {
	Client, Server participant
	AOwner, BOwner participant // UDP ownership follows endpoints, not send/recv direction.
}

func (r roles) owner(endpoint netip.AddrPort, key flowKey) participant {
	if endpoint == key.A {
		return r.AOwner
	}
	if endpoint == key.B {
		return r.BOwner
	}
	return participant{}
}

type wildcardKey struct {
	Remote    netip.AddrPort
	LocalPort uint16
	Protocol  uint8
	Role      string
}

func mergeParticipant(old, next participant) participant {
	if old.PID == 0 || old.id() == next.id() {
		return next
	}
	return participant{PID: -1, Name: "ambiguous"}
}

type flow struct {
	Key              flowKey
	Initiator        netip.AddrPort
	Target           netip.AddrPort
	Direction        string
	First, Last      time.Time
	RX, TX           uint64
	Packets          uint64
	Client, Server   participant
	IO               map[processID]ioBytes
	TruncatedPackets uint64
	Domain           *domain.Stream // Strongest of the evidence below; see chooseDomain.
	WireDomain       *domain.Stream // TCP client stream: HTTP, TLS or proxy tunnel.
	WireClient       netip.AddrPort // Endpoint whose bytes WireDomain parses.
	Preexisting      bool           // Open before capture began, so its handshake was never visible.
	SocketDomain     *domain.Stream // The same client bytes read at the socket layer.
	QUICDomain       *domain.Stream
	ProcessDomain    *domain.Stream
	DNSDomain        *domain.Stream
	TLSActors        map[processID]participant
	DomainConflict   bool
	QUIC             *quicinitial.Tracker
	ICMP             icmpState
	ICMPError        string // Latest ICMP error that quoted this flow's packets.
	ARP              arpState
	AppProtocol      string
	AppSource        string
	Health           tcpHealth
	SYNSeq           uint32
	SYNSeen          bool
	TCPState         string
	FinA, FinB       bool
	Closed           bool
	ClientWildcard   *wildcardKey
	ServerWildcard   *wildcardKey
}

type collector struct {
	flows           map[flowKey]*flow
	dns             *domain.DNSCache // Shared by all interfaces: answers on lo name flows elsewhere.
	pendingTLS      map[flowKey]pendingTLSEvent
	pendingSocket   map[flowKey]pendingSocket
	fragments       map[fragmentKey]fragmentHeader
	echoOwners      map[echoKey]echoOwner
	retired         []*flow
	roles           map[flowKey]roles
	wildcards       map[wildcardKey]participant
	roleSeen        map[flowKey]time.Time
	wildcardSeen    map[wildcardKey]time.Time
	maxFlows        int
	filterPort      uint16
	loopback        bool
	debugPID        bool
	pidIO           map[processID]processIO
	rxBytes         uint64
	txBytes         uint64
	pidSeen         map[processID]time.Time
	expiredPIDIO    ioBytes
	expiredPIDCount uint64
	pendingIO       map[flowKey][]pendingIOSample
	pendingIOCount  int
	ioUnmatched     uint64
	ioUnindexed     ioBytes
	packets         uint64
	bytes           uint64
	droppedFlow     uint64
	droppedRole     uint64
	truncated       uint64
	kernelReceived  uint64
	kernelDropped   uint64
	expiredFlows    uint64
	expiredRX       uint64
	expiredTX       uint64
	expiredDomainRX uint64
	expiredDomainTX uint64
	unindexedRX     uint64
	unindexedTX     uint64
}

type pendingTLSEvent struct {
	event tlsprobe.Event
	seen  time.Time
}

type interfaceFlags []string

func (f *interfaceFlags) String() string { return strings.Join(*f, ",") }

func (f *interfaceFlags) Set(value string) error {
	for name := range strings.SplitSeq(value, ",") {
		name = strings.TrimSpace(name)
		if name == "" {
			return fmt.Errorf("empty interface name")
		}
		if slices.Contains(*f, name) {
			return fmt.Errorf("duplicate interface %q", name)
		}
		*f = append(*f, name)
	}
	return nil
}

func (c *collector) acceptPort(a, b netip.AddrPort) bool {
	return c.filterPort == 0 || a.Port() == c.filterPort || b.Port() == c.filterPort
}

type fragmentKey struct {
	source, destination netip.Addr
	protocol            uint8
	id                  uint32
}

// fragmentHeader holds what only the first fragment of a datagram carries:
// the ports, or the ICMP fields that key an ICMP flow.
type fragmentHeader struct {
	source, destination uint16
	hasPorts            bool
	icmpType, icmpCode  uint8
	icmpID              uint16
	icmpEcho            bool
	seen                time.Time
}

const (
	maxFragments = 4096
	fragmentTTL  = 30 * time.Second
)

// joinFragment gives a later IP fragment the header fields its first fragment
// carried, so every fragment of a datagram counts toward the same flow.
func (c *collector) joinFragment(p *capture.Packet) {
	if !p.Fragmented {
		return
	}
	key := fragmentKey{p.Source.Addr(), p.Destination.Addr(), p.Protocol, p.FragmentID}
	if p.FragmentOffset == 0 {
		if (p.HasPorts || p.Protocol == 1 || p.Protocol == 58) && len(c.fragments) < maxFragments {
			if c.fragments == nil {
				c.fragments = make(map[fragmentKey]fragmentHeader)
			}
			c.fragments[key] = fragmentHeader{p.Source.Port(), p.Destination.Port(), p.HasPorts, p.ICMPType, p.ICMPCode, p.ICMPID, p.ICMPHasEcho, time.Now()}
		}
		return
	}
	if h, ok := c.fragments[key]; ok {
		p.Source = netip.AddrPortFrom(p.Source.Addr(), h.source)
		p.Destination = netip.AddrPortFrom(p.Destination.Addr(), h.destination)
		p.HasPorts = h.hasPorts
		p.ICMPType, p.ICMPCode, p.ICMPID, p.ICMPHasEcho = h.icmpType, h.icmpCode, h.icmpID, h.icmpEcho
	}
}

func (c *collector) packet(p capture.Packet) {
	c.joinFragment(&p)
	if c.dns != nil && p.Protocol == 17 && p.Source.Port() == 53 {
		// Name hints also serve flows on other interfaces and ports.
		c.dns.Observe(p.Payload, time.Now())
	}
	if !c.acceptPort(p.Source, p.Destination) {
		return
	}
	c.packets++
	c.bytes += uint64(p.IPBytes)
	if p.Outgoing {
		c.txBytes += uint64(p.IPBytes)
	} else {
		c.rxBytes += uint64(p.IPBytes)
	}
	key := packetKey(p)
	f := c.flows[key]
	priorGeneration := f != nil && p.Protocol == 6 && p.SYN && !p.ACK && (!f.SYNSeen || f.SYNSeq != p.TCPSeq)
	if priorGeneration {
		c.flushPendingKey(key)
		c.retired = append(c.retired, f)
		delete(c.flows, key)
		f = nil
	}
	if f == nil {
		if len(c.flows)+len(c.retired) >= c.maxFlows {
			c.droppedFlow++
			if p.Outgoing {
				c.unindexedTX += uint64(p.IPBytes)
			} else {
				c.unindexedRX += uint64(p.IPBytes)
			}
			return
		}
		f = &flow{Key: key, Direction: "unknown", First: time.Now()}
		if p.Protocol == 6 {
			f.TCPState = "midstream"
		}
		// A role recorded before an inbound SYN belongs to an older connection
		// on the same tuple, unless no older flow existed and the role is
		// fresh: then the accept event was read before the packets behind it.
		inboundSYN := p.Protocol == 6 && p.SYN && !p.ACK && !p.Outgoing
		if r, ok := c.roles[key]; ok && (!inboundSYN || !priorGeneration && time.Since(c.roleSeen[key]) < 2*time.Second) {
			if p.Protocol == 17 {
				f.Client, f.Server = r.owner(p.Source, key), r.owner(p.Destination, key)
			} else {
				f.Client, f.Server = r.Client, r.Server
			}
		}
		c.flows[key] = f
		if p.Protocol == 17 || p.Protocol == 6 && p.SYN && !p.ACK {
			c.attachPendingIO(key, f)
		}
	}
	f.Last = time.Now()
	f.Health.observe(p, c.loopback)
	f.Packets++
	if p.Outgoing {
		f.TX += uint64(p.IPBytes)
	} else {
		f.RX += uint64(p.IPBytes)
	}
	if p.Truncated {
		f.TruncatedPackets++
		c.truncated++
	}
	if p.Protocol == 6 && p.SYN && !p.ACK {
		f.SYNSeen, f.SYNSeq = true, p.TCPSeq
		f.TCPState = "syn"
		f.Initiator, f.Target = p.Source, p.Destination
		if f.WireDomain == nil {
			f.WireDomain, f.WireClient = domain.New(p.TCPSeq+1), p.Source
		}
		if c.loopback {
			f.Direction = "local"
		} else if p.Outgoing {
			f.Direction = "outbound"
		} else {
			f.Direction = "inbound"
		}
	} else if p.Protocol != 6 && !f.Initiator.IsValid() && p.Source.IsValid() {
		// Connectionless protocols have no established initiator. These are the
		// endpoints and interface direction of the first observed datagram.
		f.Initiator, f.Target = p.Source, p.Destination
		if c.loopback {
			f.Direction = "local"
		} else if p.Outgoing {
			f.Direction = "first-packet-out"
		} else {
			f.Direction = "first-packet-in"
		}
	}
	switch {
	case p.EtherType == 0x0806:
		f.ARP.observe(p)
	case p.EtherType == 0 && (p.Protocol == 1 || p.Protocol == 58) && p.FragmentOffset == 0:
		c.icmp(f, p) // A later fragment adds bytes, not another message.
	}
	if p.Protocol == 6 && p.ACK && f.SYNSeen && f.TCPState == "syn" {
		f.TCPState = "established"
	}
	if p.Protocol == 6 && f.WireDomain == nil && domain.StartsClientMessage(p.Payload) {
		// The SYN was not captured: capture began mid-handshake or the SYN
		// crossed another interface. A ClientHello or request line still
		// marks the client and the start of its stream.
		f.WireDomain, f.WireClient = domain.New(p.TCPSeq), p.Source
		if !f.Initiator.IsValid() {
			f.Initiator, f.Target, f.Direction = p.Source, p.Destination, c.direction(p)
		}
	}
	if p.Protocol == 6 && f.WireDomain != nil && p.Source == f.WireClient {
		seq := p.TCPSeq
		if p.SYN {
			seq++
		}
		f.WireDomain.AddSegment(seq, p.Payload, p.PayloadLen)
	}
	if f.AppProtocol == "" && len(p.Payload) > 0 {
		var observed appproto.Detection
		if p.Protocol == 6 {
			observed = appproto.TCP(p.Payload, p.Source.Port(), p.Destination.Port())
		} else if p.Protocol == 17 {
			observed = appproto.UDP(p.Payload, p.Source.Port(), p.Destination.Port())
		}
		f.AppProtocol, f.AppSource = observed.Name, observed.Source
	}
	if p.Protocol == 17 && f.AppProtocol == "QUIC" && len(p.Payload) > 0 {
		if f.QUIC == nil {
			f.QUIC = new(quicinitial.Tracker)
			f.QUICDomain = domain.NewUnknownQUIC("")
		}
		if p.Truncated || p.PayloadTruncated {
			f.QUIC.Fail("QUIC packet capture truncated")
		}
		hello, clientInitial, err := f.QUIC.Add(p.Payload, p.CapturedAt)
		if clientInitial {
			f.Initiator, f.Target = p.Source, p.Destination
			if c.loopback {
				f.Direction = "local"
			} else if p.Outgoing {
				f.Direction = "outbound"
			} else {
				f.Direction = "inbound"
			}
		}
		if err != nil {
			f.QUICDomain = domain.NewUnknownQUIC(err.Error())
		} else if hello != nil {
			if f.QUICDomain, err = domain.NewQUICClientHello(hello); err != nil {
				f.QUICDomain = domain.NewUnknownQUIC(err.Error())
			}
			f.AppSource = "authenticated QUIC Initial ClientHello"
		}
		if f.QUIC.Failure() != "" && f.QUICDomain.Evidence().ParseError == "" {
			f.QUICDomain = domain.NewUnknownQUIC(f.QUIC.Failure())
		}
	}
	if f.WireDomain != nil {
		e := f.WireDomain.Evidence()
		via := ""
		if e.ProxyVia != "" {
			via = " via " + e.ProxyVia
		}
		switch e.Kind {
		case "http":
			f.AppProtocol, f.AppSource = "HTTP", "HTTP request header"+via
		case "tls":
			f.AppProtocol, f.AppSource = "TLS", "ClientHello"+via
		case "proxy":
			f.AppProtocol, f.AppSource = "SOCKS5", "proxy request"
			if e.ProxyVia == "CONNECT" {
				f.AppProtocol = "HTTP CONNECT"
			}
		}
	}
	pendingKey := key
	if p.Protocol == 17 && p.Outgoing && len(c.pendingSocket) > 0 {
		if _, exact := c.pendingSocket[key]; !exact {
			// Evidence from an unconnected UDP socket names only the local port.
			pendingKey = keyFor(netip.AddrPortFrom(unspecified(p.Source.Addr()), p.Source.Port()), p.Destination, 17)
		}
	}
	if pending, ok := c.pendingSocket[pendingKey]; ok {
		delete(c.pendingSocket, pendingKey)
		if time.Since(pending.seen) <= pendingSocketTTL {
			attachSocketDomain(f, pending.stream)
		}
	}
	if p.Protocol == 6 || p.Protocol == 17 {
		chooseDomain(f)
	}
	if pending, ok := c.pendingTLS[key]; ok {
		delete(c.pendingTLS, key)
		if time.Since(pending.seen) <= 2*time.Second {
			c.applyTLSEvent(f, pending.event)
		}
	}
	if p.Protocol == 6 {
		switch {
		case p.RST:
			f.TCPState, f.Closed = "reset", true
		case p.FIN:
			if p.Source == f.Key.A {
				f.FinA = true
			} else {
				f.FinB = true
			}
			if f.FinA && f.FinB {
				f.TCPState, f.Closed = "closed", true
			} else {
				f.TCPState = "closing"
			}
		}
	}
}

func named(s *domain.Stream) bool { return s != nil && s.Evidence().Named() }

// clientBytes returns the parse of the client's own bytes: the captured
// packets when they named the connection, otherwise the socket-layer copy,
// which sees the same bytes regardless of interface, segmentation or proxy.
func clientBytes(f *flow) *domain.Stream {
	wire := f.WireDomain
	if f.QUICDomain != nil {
		wire = f.QUICDomain
	}
	switch {
	case named(wire):
		return wire
	case named(f.SocketDomain):
		return f.SocketDomain
	case wire != nil && wire.Evidence().Listed():
		return wire
	case f.SocketDomain != nil:
		return f.SocketDomain
	}
	return wire
}

// chooseDomain picks the strongest name evidence: the client's Host, SNI or
// proxy target, then the OpenSSL process SNI, then a DNS answer for the peer.
// An ECH-offering ClientHello may carry only a provider's public name, so a
// process-observed SNI outranks it without a conflict.
func chooseDomain(f *flow) {
	wire := clientBytes(f)
	process := named(f.ProcessDomain)
	switch {
	case named(wire) && !(process && wire.Evidence().ECH):
		if process && f.ProcessDomain.Evidence().Group() != wire.Evidence().Group() {
			f.DomainConflict = true
		}
		f.Domain = wire
	case process:
		f.Domain = f.ProcessDomain
	case named(f.DNSDomain):
		f.Domain = f.DNSDomain
	case wire != nil && wire.Evidence().Listed():
		f.Domain = wire
	case f.ProcessDomain != nil:
		f.Domain = f.ProcessDomain
	case f.Key.Protocol == 6 && f.AppProtocol == "TLS":
		if f.Domain == nil || !f.Domain.Evidence().NoHandshake {
			reason := ""
			if wire != nil {
				reason = wire.Evidence().ParseError
			}
			f.Domain = domain.NewMissedTLSHandshake(reason)
		}
	default:
		f.Domain = wire
	}
}

func (c *collector) tlsEvent(e tlsprobe.Event) bool {
	key := keyFor(e.Local, e.Remote, 6)
	if !c.acceptPort(e.Local, e.Remote) {
		return false
	}
	f := c.flows[key]
	if f == nil {
		if len(c.pendingTLS) < 1024 {
			if c.pendingTLS == nil {
				c.pendingTLS = make(map[flowKey]pendingTLSEvent)
			}
			c.pendingTLS[key] = pendingTLSEvent{event: e, seen: time.Now()}
		}
		return false
	}
	if f.Closed {
		return false
	}
	return c.applyTLSEvent(f, e)
}

func (c *collector) applyTLSEvent(f *flow, e tlsprobe.Event) bool {
	if f.ProcessDomain != nil && f.ProcessDomain.Evidence().SNI != e.Hostname {
		f.DomainConflict = true
		return false
	}
	// The kernel probe supplies the socket tuple. Keep the source distinct from
	// on-wire SNI, and never replace an observed HTTP Host or clear SNI.
	if f.ProcessDomain == nil {
		f.ProcessDomain = domain.NewOpenSSLSNI(e.Hostname)
	}
	if e.PID > 0 && len(f.TLSActors) < 8 {
		if f.TLSActors == nil {
			f.TLSActors = make(map[processID]participant)
		}
		actor := participant{PID: e.PID, StartNS: e.StartNS, Name: e.Process}
		f.TLSActors[actor.id()] = actor
	}
	chooseDomain(f)
	if f.Domain == f.ProcessDomain {
		f.AppProtocol, f.AppSource = "TLS", e.Source
	}
	return true
}

func (c *collector) allFlows() []*flow {
	flows := make([]*flow, 0, len(c.flows)+len(c.retired))
	for _, f := range c.flows {
		flows = append(flows, f)
	}
	return append(flows, c.retired...)
}

func addFlowIO(f *flow, id processID, operation string, bytes uint64) {
	if f.IO == nil {
		f.IO = make(map[processID]ioBytes)
	}
	entry := f.IO[id]
	if operation == "send" {
		entry.TX += bytes
	} else {
		entry.RX += bytes
	}
	f.IO[id] = entry
}

func (c *collector) flushPendingKey(key flowKey) {
	for _, sample := range c.pendingIO[key] {
		c.ioUnmatched += sample.Bytes
		c.pendingIOCount--
	}
	delete(c.pendingIO, key)
}

func (c *collector) attachPendingIO(key flowKey, f *flow) {
	for _, sample := range c.pendingIO[key] {
		if time.Since(sample.Seen) <= 2*time.Second {
			addFlowIO(f, sample.Process, sample.Operation, sample.Bytes)
		} else {
			c.ioUnmatched += sample.Bytes
		}
		c.pendingIOCount--
	}
	delete(c.pendingIO, key)
}

func (c *collector) expirePendingIO(now time.Time, flushAll bool) {
	for key, samples := range c.pendingIO {
		kept := samples[:0]
		for _, sample := range samples {
			if flushAll || now.Sub(sample.Seen) > 2*time.Second {
				c.ioUnmatched += sample.Bytes
				c.pendingIOCount--
			} else {
				kept = append(kept, sample)
			}
		}
		if len(kept) == 0 {
			delete(c.pendingIO, key)
		} else {
			c.pendingIO[key] = kept
		}
	}
}

func (c *collector) event(e probe.Event) {
	if c.debugPID {
		fmt.Fprintf(os.Stderr, "PID event: proto=%d op=%s app-bytes=%d local=%s remote=%s pid=%d netns=%d\n", e.Protocol, e.Operation, e.AppBytes, e.Local, e.Remote, e.PID, e.NetNS)
	}
	portMatch := c.acceptPort(e.Local, e.Remote)
	if !portMatch && e.AppBytes == 0 {
		return
	}
	if e.Protocol == 1 || e.Protocol == 58 {
		c.echoSent(e)
		return
	}
	p := participant{PID: e.PID, StartNS: e.StartNS, Name: e.Process}
	if e.AppBytes > 0 {
		if c.pidIO == nil {
			c.pidIO = make(map[processID]processIO)
		}
		id := p.id()
		total, exists := c.pidIO[id]
		if !exists && c.maxFlows > 0 && len(c.pidIO) >= c.maxFlows {
			if e.Operation == "send" {
				c.ioUnindexed.TX += e.AppBytes
			} else {
				c.ioUnindexed.RX += e.AppBytes
			}
			return
		}
		if total.Name == "" {
			total.Name = p.Name
		}
		if e.Operation == "send" {
			total.TX += e.AppBytes
		} else {
			total.RX += e.AppBytes
		}
		c.pidIO[id] = total
		if c.pidSeen == nil {
			c.pidSeen = make(map[processID]time.Time)
		}
		c.pidSeen[id] = time.Now()
		key := keyFor(e.Local, e.Remote, e.Protocol)
		if !portMatch {
			c.ioUnmatched += e.AppBytes
		} else if f := c.flows[key]; f != nil && !f.Closed {
			addFlowIO(f, id, e.Operation, e.AppBytes)
		} else if c.flows[key] == nil && c.pendingIOCount < maxPendingIOSamples {
			if c.pendingIO == nil {
				c.pendingIO = make(map[flowKey][]pendingIOSample)
			}
			c.pendingIO[key] = append(c.pendingIO[key], pendingIOSample{Process: id, Operation: e.Operation, Bytes: e.AppBytes, Seen: time.Now()})
			c.pendingIOCount++
		} else {
			c.ioUnmatched += e.AppBytes
		}
	}
	if e.Protocol == 6 && (e.Operation == "send" || e.Operation == "recv") {
		// I/O belongs to the executing PID, which need not be the process that
		// connected or accepted this socket. Keep those roles separate.
		return
	}
	if !portMatch {
		return
	}
	if e.Protocol == 17 && e.Local.Addr().IsUnspecified() {
		key := wildcardKey{Remote: e.Remote, LocalPort: e.Local.Port(), Protocol: 17, Role: e.Role}
		if len(c.wildcards) >= c.maxFlows && c.wildcards[key] == (participant{}) {
			c.droppedRole++
			return
		}
		c.wildcards[key] = mergeParticipant(c.wildcards[key], p)
		c.wildcardSeen[key] = time.Now()
		return
	}
	key := keyFor(e.Local, e.Remote, e.Protocol)
	r := c.roles[key]
	if e.Protocol == 17 {
		if e.Local == key.A {
			r.AOwner = mergeParticipant(r.AOwner, p)
		} else if e.Local == key.B {
			r.BOwner = mergeParticipant(r.BOwner, p)
		}
	} else if e.Role == "out" {
		r = roles{Client: p}
	} else {
		r.Server = p
	}
	if len(c.roles) < c.maxFlows || c.roles[key] != (roles{}) {
		c.roles[key] = r
		c.roleSeen[key] = time.Now()
	} else {
		c.droppedRole++
	}
	if f := c.flows[key]; f != nil && !f.Closed {
		if e.Protocol == 6 {
			known := f.Client
			if e.Role == "in" {
				known = f.Server
			}
			if known.PID > 0 && known.id() != p.id() {
				return // Another socket generation may have reused this tuple.
			}
		}
		if e.Protocol == 17 {
			f.Client, f.Server = r.owner(f.Initiator, key), r.owner(f.Target, key)
		} else if e.Role == "out" {
			f.Client = r.Client
		} else {
			f.Server = r.Server
		}
		if e.Protocol == 17 {
			f.ClientWildcard, f.ServerWildcard = nil, nil
		} else if e.Role == "out" {
			f.ClientWildcard = nil
		} else {
			f.ServerWildcard = nil
		}
		if f.Direction == "unknown" && e.Protocol == 6 {
			if c.loopback {
				f.Direction = "local"
			} else {
				f.Direction = map[string]string{"out": "outbound", "in": "inbound"}[e.Role]
			}
		}
		if e.Protocol == 6 && !f.Initiator.IsValid() {
			if e.Role == "out" {
				f.Initiator, f.Target = e.Local, e.Remote
			} else {
				f.Initiator, f.Target = e.Remote, e.Local
			}
		}
	}
}

func (c *collector) expire(now time.Time) {
	c.expirePendingIO(now, false)
	for key, event := range c.pendingTLS {
		if now.Sub(event.seen) > 2*time.Second {
			delete(c.pendingTLS, key)
		}
	}
	for key, pending := range c.pendingSocket {
		if now.Sub(pending.seen) > pendingSocketTTL {
			delete(c.pendingSocket, key)
		}
	}
	for key, ports := range c.fragments {
		if now.Sub(ports.seen) > fragmentTTL {
			delete(c.fragments, key)
		}
	}
	maps.DeleteFunc(c.echoOwners, func(_ echoKey, owner echoOwner) bool { return now.Sub(owner.seen) > echoOwnerIdle })
	expiredIDs := make(map[processID]struct{})
	for id, seen := range c.pidSeen {
		if now.Sub(seen) > 5*time.Minute {
			old := c.pidIO[id]
			c.expiredPIDIO.RX += old.RX
			c.expiredPIDIO.TX += old.TX
			c.expiredPIDCount++
			delete(c.pidIO, id)
			delete(c.pidSeen, id)
			expiredIDs[id] = struct{}{}
		}
	}
	if len(expiredIDs) > 0 {
		for _, f := range c.allFlows() {
			for id := range f.IO {
				if _, expired := expiredIDs[id]; expired {
					delete(f.IO, id)
				}
			}
		}
	}
	expireFlow := func(f *flow) {
		c.expiredFlows++
		c.expiredRX += f.RX
		c.expiredTX += f.TX
		if f.Domain != nil && f.Domain.Evidence().Listed() {
			c.expiredDomainRX += f.RX
			c.expiredDomainTX += f.TX
		}
	}
	for key, f := range c.flows {
		if f.WireDomain != nil {
			f.WireDomain.Tick(now)
		}
		if f.QUIC != nil {
			f.QUIC.Tick(now)
			if f.QUIC.Failure() != "" && f.QUICDomain != nil && f.QUICDomain.Evidence().ParseError == "" {
				f.QUICDomain = domain.NewUnknownQUIC(f.QUIC.Failure())
				chooseDomain(f)
			}
		}
		ttl := 5 * time.Minute
		if f.Closed {
			ttl = time.Minute
		}
		if now.Sub(f.Last) <= ttl {
			continue
		}
		expireFlow(f)
		delete(c.flows, key)
	}
	retained := c.retired[:0]
	for _, f := range c.retired {
		if f.WireDomain != nil {
			f.WireDomain.Tick(now)
		}
		ttl := 5 * time.Minute
		if f.Closed {
			ttl = time.Minute
		}
		if now.Sub(f.Last) > ttl {
			expireFlow(f)
		} else {
			retained = append(retained, f)
		}
	}
	c.retired = retained
	for key, seen := range c.roleSeen {
		if now.Sub(seen) > time.Minute {
			delete(c.roles, key)
			delete(c.roleSeen, key)
		}
	}
	for key, seen := range c.wildcardSeen {
		if now.Sub(seen) > time.Minute {
			delete(c.wildcards, key)
			delete(c.wildcardSeen, key)
		}
	}
}

// dnsPeers returns the endpoints whose DNS names can describe a flow: the
// target when the initiator is known, otherwise either endpoint.
func dnsPeers(f *flow) []netip.AddrPort {
	if f.Initiator.IsValid() {
		return []netip.AddrPort{f.Target}
	}
	return []netip.AddrPort{f.Key.A, f.Key.B}
}

// attachDNSHints names flows that have no Host or SNI after a recent DNS
// answer for their peer. The hint stays a separate source and never replaces
// wire or process evidence.
func (c *collector) attachDNSHints() {
	if c.dns == nil {
		return
	}
	for _, f := range c.allFlows() {
		if f.DNSDomain != nil || named(f.Domain) || f.Key.Protocol != 6 && f.Key.Protocol != 17 {
			continue
		}
		if f.Key.Protocol == 17 && f.AppProtocol != "" && f.AppProtocol != "QUIC" {
			continue // DNS, NTP and similar datagrams name no web destination.
		}
		// Only a connection seen from its start must have resolved before it began.
		allowLater := !f.SYNSeen && f.QUIC == nil
		for _, peer := range dnsPeers(f) {
			if name := c.dns.Lookup(peer.Addr(), f.First, allowLater); name != "" {
				f.DNSDomain = domain.NewDNSHint(name)
				chooseDomain(f)
				break
			}
		}
	}
}

func (c *collector) reconcileWildcards() {
	for key, p := range c.wildcards {
		var candidates []*flow
		for _, f := range c.flows {
			if f.Key.Protocol != key.Protocol {
				continue
			}
			a, b := f.Key.A, f.Key.B
			if (a == key.Remote && b.Port() == key.LocalPort) || (b == key.Remote && a.Port() == key.LocalPort) {
				candidates = append(candidates, f)
			}
		}
		if len(candidates) > 1 {
			for _, f := range candidates {
				if f.ClientWildcard != nil && *f.ClientWildcard == key {
					f.Client = participant{PID: -1, Name: "ambiguous"}
					f.ClientWildcard = nil
				}
				if f.ServerWildcard != nil && *f.ServerWildcard == key {
					f.Server = participant{PID: -1, Name: "ambiguous"}
					f.ServerWildcard = nil
				}
			}
			continue
		}
		if len(candidates) != 1 || p.PID < 1 {
			continue
		}
		matched := candidates[0]
		if key.Remote == matched.Initiator {
			if matched.Server.PID == 0 || matched.ServerWildcard != nil {
				matched.Server = mergeParticipant(matched.Server, p)
				matched.ServerWildcard = &key
			}
		} else if key.Remote == matched.Target {
			if matched.Client.PID == 0 || matched.ClientWildcard != nil {
				matched.Client = mergeParticipant(matched.Client, p)
				matched.ClientWildcard = &key
			}
		}
	}
}

func run() error {
	var interfaceNames interfaceFlags
	flag.Var(&interfaceNames, "interface", "network interface to observe (repeat or comma-separate, max 8; default: active host interfaces)")
	duration := flag.Duration("duration", 0, "stop after this duration (default: until Ctrl-C)")
	limit := flag.Int("limit", 30, "number of flows to print")
	port := flag.Uint("port", 0, "only index wire flows containing this port; PID socket I/O remains netns-wide")
	debugPID := flag.Bool("debug-pid-events", false, "print raw PID association events to stderr")
	opensslProbe := flag.Bool("openssl-probe", true, "observe SNI in local processes using the system OpenSSL library (default: on)")
	socketSniff := flag.Bool("socket-sniff", true, "read the first 16 KiB each local TCP socket sends and receives, and the QUIC Initials UDP sockets send, to name connections whose handshake packets are not captured (default: on)")
	captureDir := flag.String("capture-dir", "socktrail-captures", "directory for on-demand 15-second PCAPNG recordings")
	flag.Parse()
	autoInterfaces := len(interfaceNames) == 0
	if *port > 65535 || *limit < 1 {
		return fmt.Errorf("usage: socktrail [--interface <name>] [--duration 15s] [--port 443] [--limit 30]")
	}
	var err error
	interfaceNames, err = resolveInterfaces(interfaceNames)
	if err != nil {
		return err
	}
	if *duration == 0 && *debugPID {
		return fmt.Errorf("--debug-pid-events requires --duration to keep the interactive screen readable")
	}
	info, err := os.Stat("/proc/self/ns/net")
	if err != nil {
		return fmt.Errorf("read network namespace: %w", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("read network namespace inode: unexpected stat type")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancelRun := context.WithCancel(ctx)
	defer cancelRun()
	probeCtx, cancelProbe := context.WithCancel(ctx)
	defer cancelProbe()
	events, probeDone, probeStats, err := probe.StartEmbedded(probeCtx, stat.Ino, uint16(*port))
	if err != nil {
		return err
	}
	var tlsEvents <-chan tlsprobe.Event
	var tlsDone <-chan error
	var tlsStats *tlsprobe.Statistics
	tlsStatus := "OpenSSL process probe disabled"
	if *opensslProbe {
		var path string
		tlsEvents, tlsDone, tlsStats, path, err = tlsprobe.Start(probeCtx, stat.Ino)
		if err != nil {
			tlsStatus = "OpenSSL process probe unavailable: " + err.Error()
		} else {
			tlsStatus = "OpenSSL process SNI probe active: " + path
		}
	}
	var streamChunks <-chan sockstream.Chunk
	var streamDone <-chan error
	var streamStats *sockstream.Statistics
	streamStatus := "socket stream capture disabled"
	if *socketSniff {
		streamChunks, streamDone, streamStats, err = sockstream.Start(probeCtx, stat.Ino, uint16(*port))
		if err != nil {
			streamStatus = "socket stream capture unavailable: " + err.Error()
		} else {
			streamStatus = "socket stream capture active: first 16 KiB per TCP socket direction, QUIC long-header datagrams per UDP socket"
		}
	}
	streams := make(socketStreams)
	sockets := &socketInventory{procRoot: "/proc"}
	sockets.load()
	sockets.atStart = sockets.sockets
	fds := make(map[string]int, len(interfaceNames))
	for _, name := range interfaceNames {
		fd, err := capture.Open(name)
		if err != nil {
			return err
		}
		fds[name] = fd
		defer syscall.Close(fd)
	}
	packets := make(chan capture.Packet, 8192)
	packetErrors := make(chan error, len(interfaceNames))
	var recordFrames atomic.Bool
	var captureWG sync.WaitGroup
	for _, name := range interfaceNames {
		fd := fds[name]
		captureWG.Go(func() { capture.Run(ctx, fd, name, &recordFrames, packets, packetErrors) })
	}
	go func() {
		captureWG.Wait()
		close(packets)
	}()
	collectors := make(map[string]*collector, len(interfaceNames))
	dnsHints := new(domain.DNSCache)
	for i, name := range interfaceNames {
		collectors[name] = &collector{flows: make(map[flowKey]*flow), dns: dnsHints, roles: make(map[flowKey]roles), wildcards: make(map[wildcardKey]participant), roleSeen: make(map[flowKey]time.Time), wildcardSeen: make(map[wildcardKey]time.Time), pidIO: make(map[processID]processIO), pidSeen: make(map[processID]time.Time), maxFlows: 20_000, filterPort: uint16(*port), loopback: name == "lo", debugPID: *debugPID && i == 0}
	}
	host, _, members := hostCollector(interfaceNames, collectors)
	var hostState hostViewState
	hostState.update(host, members)
	var ui *terminalUI
	if *duration == 0 {
		ui, err = openUI(interfaceNames, stat.Ino, collectors)
		if err != nil {
			return err
		}
		defer ui.close()
		ui.tlsProbeStatus = tlsStatus
		ui.tlsProbeStats = tlsStats
		ui.streamStatus, ui.streamStats = streamStatus, streamStats
		ui.render(host, 0, 0, 0)
	} else {
		if autoInterfaces {
			fmt.Printf("socktrail OVERVIEW snapshot: %d capture interfaces, netns=%d; PID socket I/O for whole netns\n", len(interfaceNames), stat.Ino)
		} else {
			fmt.Printf("socktrail capture snapshot: interfaces=%s netns=%d; IP observations per interface, PID socket I/O for whole netns\n", strings.Join(interfaceNames, ","), stat.Ino)
		}
		fmt.Println(tlsStatus)
		fmt.Println(streamStatus)
	}
	currentCollector := func() *collector {
		if ui.hostScope && ui.mode != viewInterfaces {
			return host
		}
		return collectors[ui.interfaceName]
	}
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	tickCh := ticker.C
	var keys <-chan uiInput
	if ui != nil {
		keys = ui.keys
	}
	var recording *captureSession
	defer func() {
		if recording != nil {
			recording.Close()
		}
	}()
	stopRecording := func(reason string) {
		if recording == nil {
			return
		}
		recordFrames.Store(false)
		closeErr := recording.Close()
		if ui != nil {
			ui.capturePath = recording.path
			ui.captureStatus = fmt.Sprintf("saved %s (%d packets, %s)", filepath.Base(recording.path), recording.writer.Packets, reason)
			if closeErr != nil {
				ui.captureStatus = "PCAPNG close failed: " + closeErr.Error()
			}
		}
		recording = nil
	}
	if *duration > 0 {
		// The window starts once capture runs: an older kernel's verifier can
		// take seconds to load the probes.
		time.AfterFunc(*duration, cancelRun)
	}
	stopCh := ctx.Done()
	for packets != nil || events != nil || tlsEvents != nil || streamChunks != nil {
		select {
		case <-tickCh:
			if recording != nil && !time.Now().Before(recording.until) {
				stopRecording("15s complete")
			}
			dnsHints.Expire(time.Now())
			streams.expire(time.Now())
			for _, name := range interfaceNames {
				c := collectors[name]
				c.expire(time.Now())
				c.reconcileWildcards()
				c.attachDNSHints()
				stats, err := capture.SocketStatistics(fds[name])
				if err != nil {
					return err
				}
				c.kernelReceived += uint64(stats.Received)
				c.kernelDropped += uint64(stats.Dropped)
			}
			if time.Since(sockets.read) >= socketTableInterval {
				sockets.refresh(collectors, time.Now())
			}
			if ui != nil && !ui.closed {
				ui.sampleAll(collectors, time.Now())
				var sources map[*flow]*flow
				oldHost := host
				host, sources, members = hostCollector(interfaceNames, collectors)
				replacements := hostState.update(host, members)
				for _, previous := range oldHost.allFlows() {
					delete(ui.rates, previous)
				}
				for merged, source := range sources {
					ui.rates[replacements[merged]] = ui.rates[source]
				}
				ui.render(currentCollector(), probeStats.Received.Load(), probeStats.KernelLost.Load(), probeStats.Dropped.Load())
			}
		case input := <-keys:
			if ui.handleInput(input, currentCollector()) {
				stopRecording("stopped on exit")
				ui.close()
				keys = nil
				cancelRun()
				continue
			}
			if ui.captureToggle {
				ui.captureToggle = false
				if recording != nil {
					stopRecording("stopped by user")
				} else {
					selected, selectedPID := ui.selectedFlowRef, processID{}
					if ui.mode == viewPID && !ui.focusBottom {
						rows := ui.rows(currentCollector(), viewPID)
						if ui.selected < len(rows) {
							selectedPID = rows[ui.selected].pidID
						}
						selected = nil
					}
					var err error
					recording, err = startCapture(*captureDir, interfaceNames, selected, selectedPID, collectors)
					if err != nil {
						ui.captureStatus = "capture: " + err.Error()
					} else {
						ui.capturePath = recording.path
						ui.captureStatus = fmt.Sprintf("recording %s for 15s; c stops", recording.label)
						recordFrames.Store(true)
					}
				}
			}
			ui.render(currentCollector(), probeStats.Received.Load(), probeStats.KernelLost.Load(), probeStats.Dropped.Load())
		case p, ok := <-packets:
			if !ok {
				packets = nil
				continue
			}
			collector := collectors[p.Interface]
			collector.packet(p)
			if recording != nil {
				if err := recording.Write(p, collector.flows[packetKey(p)]); err != nil {
					stopRecording(err.Error())
				}
			}
		case e, ok := <-events:
			if !ok {
				events = nil
				continue
			}
			e.StartNS = tickStartNS(e.StartNS)
			for _, name := range interfaceNames {
				collectors[name].event(e)
			}
		case e, ok := <-tlsEvents:
			if !ok {
				tlsEvents = nil
				continue
			}
			e.StartNS = tickStartNS(e.StartNS)
			for _, name := range interfaceNames {
				collectors[name].tlsEvent(e)
			}
		case chunk, ok := <-streamChunks:
			if !ok {
				streamChunks = nil
				continue
			}
			if stream := streams.add(chunk, time.Now()); stream != nil {
				for _, name := range interfaceNames {
					collectors[name].socketEvidence(stream)
				}
			}
		case err := <-streamDone:
			if err != nil {
				streamStatus = "socket stream capture stopped: " + err.Error()
				if ui != nil {
					ui.streamStatus = streamStatus
				}
			}
			streamDone = nil
		case err := <-packetErrors:
			return err
		case err := <-probeDone:
			if err != nil {
				return err
			}
			probeDone = nil
		case err := <-tlsDone:
			if err != nil {
				tlsStatus = "OpenSSL process probe stopped: " + err.Error()
				if ui != nil {
					ui.tlsProbeStatus = tlsStatus
				}
			}
			tlsDone = nil
		case <-stopCh:
			stopRecording("stopped")
			stopCh = nil
			tickCh = nil
			keys = nil
		}
	}
	if *duration > 0 && tlsStats != nil {
		fmt.Printf("OpenSSL SNI events %d invalid %d dropped %d\n", tlsStats.Received.Load(), tlsStats.Invalid.Load(), tlsStats.Dropped.Load())
	}
	if *duration > 0 && streamStats != nil {
		fmt.Printf("Socket stream chunks %d kernel-lost %d dropped %d invalid %d\n", streamStats.Received.Load(), streamStats.KernelLost.Load(), streamStats.Dropped.Load(), streamStats.Invalid.Load())
	}
	sockets.refresh(collectors, time.Now())
	for _, name := range interfaceNames {
		c := collectors[name]
		c.reconcileWildcards()
		c.attachDNSHints()
		c.expirePendingIO(time.Now(), true)
		packetStats, err := capture.SocketStatistics(fds[name])
		if err != nil {
			return err
		}
		c.kernelReceived += uint64(packetStats.Received)
		c.kernelDropped += uint64(packetStats.Dropped)
	}
	if ui != nil {
		ui.close()
		if ui.capturePath != "" {
			fmt.Printf("PCAPNG: %s (%s)\n", ui.capturePath, ui.captureStatus)
		}
		if autoInterfaces {
			var dropped uint64
			for _, name := range interfaceNames {
				dropped += collectors[name].kernelDropped
			}
			fmt.Printf("socktrail stopped: %d capture interfaces, AF_PACKET dropped %d\n", len(interfaceNames), dropped)
		} else {
			for _, name := range interfaceNames {
				c := collectors[name]
				fmt.Printf("socktrail stopped %s: %d IP packets, %d IP bytes, capture drops %d\n", name, c.packets, c.bytes, c.kernelDropped)
			}
		}
		fmt.Printf("PID ring lost %d\n", probeStats.KernelLost.Load())
	} else {
		if autoInterfaces {
			host, _, members = hostCollector(interfaceNames, collectors)
			hostState.update(host, members)
			printReport(*host, "OVERVIEW", *limit, probeStats)
		} else {
			for _, name := range interfaceNames {
				printReport(*collectors[name], name, *limit, probeStats)
			}
		}
		printPIDIO(collectors[interfaceNames[0]], *limit)
	}
	return nil
}

func printReport(c collector, interfaceName string, limit int, probeStats *probe.Statistics) {
	flows := c.allFlows()
	slices.SortFunc(flows, func(a, b *flow) int {
		if a.RX+a.TX > b.RX+b.TX {
			return -1
		}
		if a.RX+a.TX < b.RX+b.TX {
			return 1
		}
		return 0
	})
	if interfaceName == "OVERVIEW" {
		fmt.Printf("\nOVERVIEW: %d observed flows; IP bytes below use one capture point per flow, not an exact whole-host total; NAT can produce separate tuples\n", len(flows))
	} else {
		fmt.Printf("\n%s: %d IP packets, %d IP bytes, %d retained flows, %d expired flows, %d packets without flow index\n", interfaceName, c.packets, c.bytes, len(flows), c.expiredFlows, c.droppedFlow)
	}
	if c.expiredRX+c.expiredTX+c.unindexedRX+c.unindexedTX > 0 {
		fmt.Printf("detail unavailable: expired RX=%d TX=%d; unindexed RX=%d TX=%d\n", c.expiredRX, c.expiredTX, c.unindexedRX, c.unindexedTX)
	}
	fmt.Printf("capture status: AF_PACKET delivered=%d dropped=%d, truncated IP packets=%d; PID events=%d ring-lost=%d queue-dropped=%d invalid=%d index-dropped=%d\n", c.kernelReceived, c.kernelDropped, c.truncated, probeStats.Received.Load(), probeStats.KernelLost.Load(), probeStats.Dropped.Load(), probeStats.Invalid.Load(), c.droppedRole)
	if interfaceName == "OVERVIEW" {
		fmt.Printf("PID socket I/O: %dB without PID index; separate from observed IP bytes\n", c.ioUnindexed.RX+c.ioUnindexed.TX)
	} else {
		fmt.Printf("PID socket I/O: %dB without selected interface/port flow, %dB without PID index; separate from IP packet bytes\n", c.ioUnmatched, c.ioUnindexed.RX+c.ioUnindexed.TX)
	}
	if c.loopback {
		fmt.Println("lo: duplicate receive copies omitted; TX/RX columns reflect capture direction, not two local sockets")
	}
	fmt.Println("PROTO APP            STATE       DIR              SOURCE                  TARGET                  RX B      TX B      SYN RTT    RETX    ORIGIN ENDPOINT PID  TARGET ENDPOINT PID  DETAIL")
	for _, f := range flows[:min(limit, len(flows))] {
		proto := flowProtocol(f)
		src, dst := displayedEndpoints(f)
		detail := flowName(f)
		if f.Domain != nil {
			if explanation := f.Domain.Evidence().Detail(); explanation != "" {
				detail += " (" + explanation + ")"
			}
		}
		if len(f.TLSActors) > 0 {
			ids := slices.SortedFunc(maps.Keys(f.TLSActors), func(a, b processID) int { return a.PID - b.PID })
			for _, id := range ids {
				detail += fmt.Sprintf(" OpenSSL-PID=%d", id.PID)
			}
		}
		if f.DomainConflict {
			detail += " DOMAIN-CONFLICT"
		}
		fmt.Printf("%-6s %-14s %-11s %-16s %-23s %-23s %-9d %-9d %-10s %-7d %-20s %-20s %s\n", proto, f.AppProtocol, flowState(f), f.Direction, src, dst, f.RX, f.TX, formatSYNRTT(f.Health.SynRTT), f.Health.Retransmits, formatPID(f.Client), formatPID(f.Server), detail)
	}
	fmt.Println("PID identity = PID@process-start-ns; TCP endpoints are initiator/acceptor, UDP endpoints follow the first datagram. First-packet direction is inferred. ? means unknown TCP initiator. ICMP PIDs cover echo requests sent from this host.")
	if interfaceName == "OVERVIEW" {
		fmt.Println("Domain IP bytes are single-point observations; NAT-transformed paths may still appear as separate connections.")
	}
	printDomains(flows)
	if interfaceName == "OVERVIEW" && c.expiredDomainRX+c.expiredDomainTX > 0 {
		fmt.Printf("expired domain detail (single-point observed IP bytes): RX=%d TX=%d\n", c.expiredDomainRX, c.expiredDomainTX)
	}
}

func printPIDIO(c *collector, limit int) {
	totals := c.pidIO
	ids := make([]processID, 0, len(totals))
	for id := range totals {
		ids = append(ids, id)
	}
	slices.SortFunc(ids, func(a, b processID) int {
		av := totals[a].RX + totals[a].TX
		bv := totals[b].RX + totals[b].TX
		if av > bv {
			return -1
		}
		if av < bv {
			return 1
		}
		return 0
	})
	fmt.Println("\nPID socket I/O (application bytes, independent of IP packet totals):")
	if c.expiredPIDCount > 0 || c.ioUnindexed.RX+c.ioUnindexed.TX > 0 {
		fmt.Printf("expired PID detail: %d identities, RX=%d TX=%d; unindexed RX=%d TX=%d\n", c.expiredPIDCount, c.expiredPIDIO.RX, c.expiredPIDIO.TX, c.ioUnindexed.RX, c.ioUnindexed.TX)
	}
	fmt.Println("PID@START                    PROCESS          RX B       TX B")
	for _, id := range ids[:min(limit, len(ids))] {
		v := totals[id]
		fmt.Printf("%-28s %-16s %-10d %d\n", fmt.Sprintf("%d@%d", id.PID, id.StartNS), v.Name, v.RX, v.TX)
	}
}

type domainTotals struct {
	Connections uint64
	RX, TX      uint64
	Requests    uint64
	UnknownPID  uint64
}

func printDomains(flows []*flow) {
	totals := make(map[string]*domainTotals)
	var pageBytes uint64
	for _, f := range flows {
		if f.Domain == nil || !f.Domain.Evidence().Listed() {
			continue
		}
		e := f.Domain.Evidence()
		row := totals[e.Label()]
		if row == nil {
			row = new(domainTotals)
			totals[e.Label()] = row
		}
		row.Connections++
		row.RX += f.RX
		row.TX += f.TX
		if f.Client.PID == 0 && f.Server.PID == 0 {
			row.UnknownPID++
		}
		for _, count := range e.Hosts {
			row.Requests += count
		}
		pageBytes += f.RX + f.TX
	}
	fmt.Printf("\nDomain summary (HTTP Host, TLS/QUIC SNI, PROXY target, OpenSSL SNI, DNS answer hint): %d IP bytes on %d recognized connections (subset of capture)\n", pageBytes, countDomainConnections(totals))
	fmt.Println(httpsCoverage(flows))
	fmt.Println("SOURCE DOMAIN                                   CONNS RX B      TX B      HTTP HOST COUNT  PID UNKNOWN")
	keys := slices.Collect(maps.Keys(totals))
	slices.SortFunc(keys, func(a, b string) int {
		av := totals[a].RX + totals[a].TX
		bv := totals[b].RX + totals[b].TX
		if av > bv {
			return -1
		}
		if av < bv {
			return 1
		}
		return 0
	})
	for _, key := range keys {
		row := totals[key]
		fmt.Printf("%-47s %-5d %-9d %-9d %-16d %d\n", key, row.Connections, row.RX, row.TX, row.Requests, row.UnknownPID)
	}
}

func countDomainConnections(totals map[string]*domainTotals) uint64 {
	var count uint64
	for _, row := range totals {
		count += row.Connections
	}
	return count
}

func formatPID(p participant) string {
	if p.PID < 0 {
		return "ambiguous"
	}
	if p.PID == 0 {
		return "unknown"
	}
	return fmt.Sprintf("%d@%d(%s)", p.PID, p.StartNS, p.Name)
}

func main() {
	if err := run(); err != nil && !errors.Is(err, context.Canceled) {
		fmt.Fprintln(os.Stderr, "socktrail:", err)
		os.Exit(1)
	}
}
