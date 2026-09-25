package app

import (
	"cmp"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"maps"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	_ "github.com/jimmicro/version"

	"github.com/jimyag/socktrail/internal/appproto"
	"github.com/jimyag/socktrail/internal/capture"
	"github.com/jimyag/socktrail/internal/conntrack"
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
	Interfaces       interfaceSet   // Capture interfaces that observed this flow.
	SocketDomain     *domain.Stream // The same client bytes read at the socket layer.
	QUICDomain       *domain.Stream
	ProcessDomain    *domain.Stream
	DNSDomain        *domain.Stream
	TLSActors        map[processID]participant
	DomainConflict   bool
	QUIC             *quicinitial.Tracker
	ICMP             *icmpState // ICMP flows only; allocated with their first message, as are the next.
	ICMPError        string     // Latest ICMP error that quoted this flow's packets.
	ARP              *arpState
	DNS              *dnsState  // DNS, mDNS and LLMNR flows.
	SSH              *[2]string // SSH identification strings of the initiator and the target.
	AppProtocol      string
	AppSource        string
	Health           tcpHealth
	SYNSeq           uint32
	SYNSeen          bool
	SynAck           bool // The target answered the SYN; an RST before it refused the attempt.
	TCPState         string
	FinA, FinB       bool
	Closed           bool
	ClientWildcard   *wildcardKey
	ServerWildcard   *wildcardKey
	NAT              *natEntry // Set when a NAT rewrote the connection's tuple.
}

type collector struct {
	flows           map[flowKey]*flow
	dns             *domain.DNSCache // Shared by all interfaces: answers on lo name flows elsewhere.
	nat             *natTable        // Shared by all interfaces: a gateway's LAN and WAN flows are one connection.
	pendingTLS      map[flowKey]pendingTLSEvent
	pendingSocket   map[flowKey]pendingSocket
	fragments       map[fragmentKey]fragmentHeader
	echoOwners      map[echoKey]echoOwner
	attempts        map[netip.Addr]*attemptSummary // Inbound attempts without a connection, per source.
	retired         []*flow
	roles           map[flowKey]roles
	wildcards       map[wildcardKey]participant
	roleSeen        map[flowKey]time.Time
	wildcardSeen    map[wildcardKey]time.Time
	maxFlows        int
	filterPort      uint16
	loopback        bool
	interfaceIndex  int // Its position in captureInterfaces.
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
	if c.dns != nil && p.Source.Port() == 53 {
		// Name hints also serve flows on other interfaces and ports.
		if p.Protocol == 17 {
			c.dns.Observe(p.Payload, time.Now())
		} else if p.Protocol == 6 && len(p.Payload) > 2 && int(binary.BigEndian.Uint16(p.Payload)) == len(p.Payload)-2 {
			c.dns.Observe(p.Payload[2:], time.Now()) // A whole DNS-over-TCP answer in one segment.
		}
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
			c.evict(time.Now())
		}
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
		f.Interfaces.add(c.interfaceIndex)
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
		c.natFlow(f, p.Protocol, p.Source, p.Destination)
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
		if f.ARP == nil {
			f.ARP = new(arpState)
		}
		f.ARP.observe(p)
	case p.EtherType == 0 && (p.Protocol == 1 || p.Protocol == 58) && p.FragmentOffset == 0:
		c.icmp(f, p) // A later fragment adds bytes, not another message.
	}
	if p.Protocol == 6 && p.SYN && p.ACK && p.Source == f.Target {
		f.SynAck = true
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
	if p.Protocol == 6 && f.WireDomain != nil {
		seq := p.TCPSeq
		if p.SYN {
			seq++
		}
		if p.Source == f.WireClient {
			f.WireDomain.AddSegment(seq, p.Payload, p.PayloadLen)
		} else {
			f.WireDomain.AddServer(seq, p.Payload, p.PayloadLen)
		}
		f.WireDomain.Alert(p.Payload, p.Source != f.WireClient)
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
	if len(p.Payload) > 0 {
		switch f.AppProtocol {
		case "DNS", "mDNS", "LLMNR":
			if f.DNS == nil {
				f.DNS = new(dnsState)
			}
			f.DNS.observe(p)
		case "SSH":
			f.sshBanner(p)
		}
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
		case "http2":
			f.AppProtocol, f.AppSource = "HTTP/2", "HTTP/2 HEADERS"+via
			if e.GRPC {
				f.AppProtocol = "gRPC"
			}
		case "tls":
			f.AppProtocol, f.AppSource = "TLS", "ClientHello"+via
		case "proxy":
			f.AppProtocol, f.AppSource = e.ProxyVia, "proxy request"
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
			if !f.Closed && f.SYNSeen && !f.SynAck && p.Source == f.Target {
				c.noteAttempt(f, true, p.CapturedAt) // The target refused the connection.
			}
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
	if !f.takesEvents(time.Now()) {
		return false
	}
	return c.applyTLSEvent(f, e)
}

// lateEventWindow is how long a closed flow still takes its socket's
// events. Events trail their packets by up to the PID ring's 100 ms drain
// interval, so a short connection often closes before its connect and I/O
// events arrive; a later connection on the same tuple would need a new SYN
// within this window to be confused with it.
const lateEventWindow = 2 * time.Second

func (f *flow) takesEvents(now time.Time) bool {
	return !f.Closed || now.Sub(f.Last) < lateEventWindow
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
	e.Local, e.Remote = c.natSocket(e.Local, e.Remote, e.Protocol)
	if e.Protocol == 6 && e.TCP != (probe.TCPInfo{}) {
		if f := c.flows[keyFor(e.Local, e.Remote, 6)]; f != nil {
			side := 0
			if e.Local == f.Key.B {
				side = 1
			}
			f.Health.observeKernel(side, e.TCP)
		}
	}
	if e.Operation == "retransmit" {
		return // No process and no bytes: only the socket's state.
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
		} else if f := c.flows[key]; f != nil && f.takesEvents(time.Now()) {
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
	if f := c.flows[key]; f != nil && f.takesEvents(time.Now()) {
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
	maps.DeleteFunc(c.attempts, func(_ netip.Addr, a *attemptSummary) bool { return now.Sub(a.Last) > attemptIdle })
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
	for key, f := range c.flows {
		if f.WireDomain != nil {
			f.WireDomain.Tick(now)
		}
		if f.NAT != nil && f.Last.After(f.NAT.seen) {
			f.NAT.seen = f.Last // A NAT entry lives as long as its flows.
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
		c.expireFlow(f, now)
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
			c.expireFlow(f, now)
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

func Run() error {
	var interfaceNames interfaceFlags
	flag.Var(&interfaceNames, "interface", "network interfaces to observe (repeat or comma-separate names or glob patterns; default: up to 8, physical first)")
	duration := flag.Duration("duration", 0, "stop after this duration (default: until Ctrl-C)")
	limit := flag.Int("limit", 30, "number of flows to print")
	port := flag.Uint("port", 0, "only index wire flows containing this port; PID socket I/O remains netns-wide")
	debugPID := flag.Bool("debug-pid-events", false, "print raw PID association events to stderr")
	opensslProbe := flag.Bool("openssl-probe", true, "observe SNI in local processes using the system OpenSSL library (default: on)")
	socketSniff := flag.Bool("socket-sniff", true, "read the first 16 KiB each local TCP socket sends and receives, and the QUIC Initials UDP sockets send, to name connections whose handshake packets are not captured (default: on)")
	captureDir := flag.String("capture-dir", "", "directory for on-demand PCAPNG recordings (default: XDG state directory)")
	output := flag.String("output", "text", "snapshot format with --duration: text or json")
	recordBefore := flag.Duration("record-before", 0, "start each recording with the frames of this long before c was pressed; copies every frame, keeping at most 32 MiB (default: off)")
	memoryLimit := flag.String("memory-limit", "auto", "large capture memory limit: auto (512MiB for over 8 interfaces), none, or a size such as 1GiB")
	yes := flag.Bool("yes", false, "confirm capture on more than 8 interfaces without a prompt")
	var filter processFilter
	flag.Var(&filter.names, "process", "show only these processes: names or globs, comma-separated; the kernel keeps 15 bytes of a name")
	flag.Var(&filter.pids, "pid", "show only these processes and all their descendants: PIDs, comma-separated")
	flag.Var(&filter.cgroups, "cgroup", "show only processes in these cgroups: a path prefix such as /system.slice, or a glob on one directory such as nginx.service or 'docker-*'")
	flag.Parse()
	autoInterfaces := len(interfaceNames) == 0
	if *port > 65535 || *limit < 1 || *output != "text" && *output != "json" || *recordBefore < 0 {
		return fmt.Errorf("usage: socktrail [--interface <name>] [--duration 15s] [--port 443] [--limit 30] [--output text|json] [--record-before 10s]")
	}
	if *output == "json" && *duration == 0 {
		return fmt.Errorf("--output json needs --duration: it formats the snapshot")
	}
	if *recordBefore > 0 && *duration > 0 {
		return fmt.Errorf("--record-before applies to recordings made with c on the interactive screen, not to --duration snapshots")
	}
	var err error
	interfaceNames, err = resolveInterfaces(interfaceNames)
	if err != nil {
		return err
	}
	if handled, err := prepareCaptureMemory(interfaceNames, *memoryLimit, *yes); handled || err != nil {
		return err
	}
	captureInterfaces = interfaceNames
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
	stopSignals := []os.Signal{os.Interrupt, syscall.SIGTERM}
	if !signal.Ignored(syscall.SIGHUP) {
		// A hang-up stops cleanly, closing any recording; under nohup it
		// stays ignored.
		stopSignals = append(stopSignals, syscall.SIGHUP)
	}
	ctx, stop := signal.NotifyContext(context.Background(), stopSignals...)
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
			if os.Geteuid() != 0 && errors.Is(err, os.ErrPermission) {
				tlsStatus += "; run with sudo for full OpenSSL SNI observation"
			}
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
	nat, natStatus := startNAT(probeCtx)
	var natResults <-chan conntrack.Entry
	if nat != nil {
		natResults = nat.results
	}
	streams := make(socketStreams)
	processes := newProcessTable("/proc")
	sockets := &socketInventory{procRoot: "/proc", loaded: make(chan *socketInventory, 1)}
	sockets.load()
	sockets.atStart = sockets.sockets
	captureSockets := make(map[string]*capture.Socket, len(interfaceNames))
	var captureWG sync.WaitGroup
	defer func() {
		cancelRun()
		captureWG.Wait() // A ring stays mapped until its reader has stopped.
		for _, s := range captureSockets {
			s.Close()
		}
	}()
	// The rings share 16 MiB, at least 4 MiB each. A ring cuts a GSO frame to
	// SnapLength, 15 to a 256 KiB block: at 600,000 such frames a second a
	// lone 4 MiB ring held under half a millisecond and dropped 1%, 16 MiB
	// almost nothing.
	ringSize := captureRingSize(len(interfaceNames))
	for _, name := range interfaceNames {
		s, err := capture.Open(name, ringSize)
		if err != nil {
			return err
		}
		captureSockets[name] = s
	}
	// A socket has one batch out at a time: its ring block.
	packets := make(chan capture.Batch, len(interfaceNames))
	packetErrors := make(chan error, len(interfaceNames))
	var recordFrames atomic.Bool
	var history *frameHistory
	if *recordBefore > 0 {
		history = &frameHistory{maxAge: *recordBefore}
		recordFrames.Store(true) // Frames are copied from the start, cut at SnapLength.
	}
	// A recording keeps whole frames; otherwise the rings take SnapLength.
	fullFrames := func(on bool) error {
		recordFrames.Store(on || history != nil)
		for _, s := range captureSockets {
			if err := s.SetFullFrames(on); err != nil {
				return err
			}
		}
		return nil
	}
	for _, name := range interfaceNames {
		s := captureSockets[name]
		captureWG.Go(func() { s.Run(ctx, &recordFrames, packets, packetErrors) })
	}
	go func() {
		captureWG.Wait()
		close(packets)
	}()
	collectors := make(map[string]*collector, len(interfaceNames))
	dnsHints := new(domain.DNSCache)
	for i, name := range interfaceNames {
		collectors[name] = &collector{flows: make(map[flowKey]*flow), dns: dnsHints, nat: nat, roles: make(map[flowKey]roles), wildcards: make(map[wildcardKey]participant), roleSeen: make(map[flowKey]time.Time), wildcardSeen: make(map[wildcardKey]time.Time), pidIO: make(map[processID]processIO), pidSeen: make(map[processID]time.Time), maxFlows: 20_000, filterPort: uint16(*port), loopback: name == "lo", interfaceIndex: i, debugPID: *debugPID && i == 0}
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
		ui.natStatus, ui.nat = natStatus, nat
		ui.processes, ui.scopeFilter = processes, filter
		ui.render(host, 0, 0, 0)
	} else if *output == "text" {
		if autoInterfaces {
			fmt.Printf("socktrail OVERVIEW snapshot: %d capture interfaces, netns=%d; PID socket I/O for whole netns\n", len(interfaceNames), stat.Ino)
		} else {
			fmt.Printf("socktrail capture snapshot: interfaces=%s netns=%d; IP observations per interface, PID socket I/O for whole netns\n", strings.Join(interfaceNames, ","), stat.Ino)
		}
		fmt.Println(tlsStatus)
		fmt.Println(streamStatus)
		fmt.Println(natStatus)
	}
	currentCollector := func() *collector {
		if ui.hostScope && ui.mode != viewInterfaces {
			return host
		}
		return collectors[ui.interfaceName]
	}
	var summary sessionSummary
	if ui != nil {
		summary.sample(collectors)
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
		snapErr := fullFrames(false)
		closeErr := recording.Close()
		if ui != nil {
			ui.capturePath = recording.path
			ui.captureStatus = fmt.Sprintf("saved %s (%d packets, %s)", filepath.Base(recording.path), recording.writer.Packets, reason)
			if closeErr != nil {
				ui.captureStatus = "PCAPNG close failed: " + closeErr.Error()
			} else if snapErr != nil {
				ui.captureStatus += "; capture length not restored: " + snapErr.Error()
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
			if ui != nil {
				summary.sample(collectors)
			}
			if recording != nil && !time.Now().Before(recording.until) {
				stopRecording("15s complete")
			}
			if history != nil {
				history.trim(time.Now())
			}
			processes.expire(time.Now())
			dnsHints.Expire(time.Now())
			streams.expire(time.Now())
			if nat != nil {
				nat.expire(time.Now())
			}
			for _, name := range interfaceNames {
				c := collectors[name]
				c.expire(time.Now())
				c.reconcileWildcards()
				c.attachDNSHints()
				stats, err := captureSockets[name].Statistics()
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
						if history != nil {
							ui.captureStatus = fmt.Sprintf("recording %s from %s before, for 15s; c stops", recording.label, *recordBefore)
						}
						if err := fullFrames(true); err != nil {
							ui.captureStatus = "capture: frames may be cut short: " + err.Error()
						}
						if history != nil {
							for _, h := range history.frames {
								if err := recording.Write(h.packet, h.flow); err != nil {
									stopRecording(err.Error())
									break
								}
							}
						}
					}
				}
			}
			ui.render(currentCollector(), probeStats.Received.Load(), probeStats.KernelLost.Load(), probeStats.Dropped.Load())
		case batch, ok := <-packets:
			if !ok {
				packets = nil
				continue
			}
			for _, p := range batch.Packets {
				collector := collectors[p.Interface]
				collector.packet(p)
				if recording != nil {
					if err := recording.Write(p, collector.flows[packetKey(p)]); err != nil {
						stopRecording(err.Error())
					}
				}
				if history != nil {
					history.add(p, collector.flows[packetKey(p)])
				}
			}
			batch.Release()
		case batch, ok := <-events:
			if !ok {
				events = nil
				continue
			}
			for _, e := range batch {
				e.StartNS = tickStartNS(e.StartNS)
				processes.observe(e)
				for _, name := range interfaceNames {
					collectors[name].event(e)
				}
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
		case next := <-sockets.loaded:
			sockets.apply(next, collectors)
		case e := <-natResults:
			entry := nat.add(e, time.Now())
			for _, name := range interfaceNames {
				collectors[name].linkNAT(entry)
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
	if *duration > 0 && *output == "text" {
		if tlsStats != nil {
			fmt.Printf("OpenSSL SNI events %d invalid %d dropped %d\n", tlsStats.Received.Load(), tlsStats.Invalid.Load(), tlsStats.Dropped.Load())
		}
		if streamStats != nil {
			fmt.Printf("Socket stream chunks %d kernel-lost %d dropped %d invalid %d\n", streamStats.Received.Load(), streamStats.KernelLost.Load(), streamStats.Dropped.Load(), streamStats.Invalid.Load())
		}
		if nat != nil {
			fmt.Println(nat.stats())
		}
	}
	sockets.refreshNow(collectors)
	for _, name := range interfaceNames {
		c := collectors[name]
		c.reconcileWildcards()
		c.attachDNSHints()
		c.expirePendingIO(time.Now(), true)
		packetStats, err := captureSockets[name].Statistics()
		if err != nil {
			return err
		}
		c.kernelReceived += uint64(packetStats.Received)
		c.kernelDropped += uint64(packetStats.Dropped)
	}
	if ui != nil {
		summary.sample(collectors)
		ui.close()
		if ui.capturePath != "" {
			fmt.Printf("PCAPNG: %s (%s)\n", ui.capturePath, ui.captureStatus)
		}
		var packets, ipBytes, dropped uint64
		for _, name := range interfaceNames {
			c := collectors[name]
			packets += c.packets
			ipBytes += c.bytes
			dropped += c.kernelDropped
		}
		summary.print(os.Stdout, len(interfaceNames), packets, ipBytes, dropped, probeStats.KernelLost.Load())
		if !autoInterfaces {
			for _, name := range interfaceNames {
				c := collectors[name]
				fmt.Printf("  %s: %d IP packets, %d IP bytes, capture drops %d\n", name, c.packets, c.bytes, c.kernelDropped)
			}
		}
	} else if *output == "json" {
		snapshot := jsonSnapshot{Version: 1, Netns: stat.Ino, Interfaces: interfaceNames, Probes: jsonProbes{
			PID:          jsonProbe{Received: probeStats.Received.Load(), KernelLost: probeStats.KernelLost.Load(), Dropped: probeStats.Dropped.Load(), Invalid: probeStats.Invalid.Load()},
			OpenSSL:      jsonProbe{Status: tlsStatus},
			SocketStream: jsonProbe{Status: streamStatus},
			NAT:          jsonNAT{Status: natStatus},
		}}
		if tlsStats != nil {
			snapshot.Probes.OpenSSL.Received, snapshot.Probes.OpenSSL.Dropped, snapshot.Probes.OpenSSL.Invalid = tlsStats.Received.Load(), tlsStats.Dropped.Load(), tlsStats.Invalid.Load()
		}
		if streamStats != nil {
			snapshot.Probes.SocketStream = jsonProbe{streamStatus, streamStats.Received.Load(), streamStats.KernelLost.Load(), streamStats.Dropped.Load(), streamStats.Invalid.Load()}
		}
		if nat != nil {
			snapshot.Probes.NAT = nat.json(natStatus)
		}
		scope := newProcessScope(processes, filter)
		// A service's connections span every interface, like the host view.
		host, _, members = hostCollector(interfaceNames, collectors)
		if autoInterfaces {
			hostState.update(host, members)
			snapshot.Reports = []jsonReport{reportJSON(host, "OVERVIEW", *limit, processes, scope)}
		} else {
			for _, name := range interfaceNames {
				snapshot.Reports = append(snapshot.Reports, reportJSON(collectors[name], name, *limit, processes, scope))
			}
		}
		snapshot.Filter = filter.String()
		snapshot.Processes = processesJSON(collectors[interfaceNames[0]], *limit, processes, scope)
		snapshot.Services = servicesJSON(host, processes, scope)
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(snapshot)
	} else {
		scope := newProcessScope(processes, filter)
		if filter.active() {
			fmt.Printf("\nOnly processes matching %s, with their descendants for pid, and the flows and socket I/O they take part in.\n", filter)
		}
		host, _, members = hostCollector(interfaceNames, collectors)
		if autoInterfaces {
			hostState.update(host, members)
			printReport(*host, "OVERVIEW", *limit, probeStats, scope)
		} else {
			for _, name := range interfaceNames {
				printReport(*collectors[name], name, *limit, probeStats, scope)
			}
		}
		printPIDIO(collectors[interfaceNames[0]], *limit, processes, scope)
		printServices(host, *limit, processes, scope)
	}
	return nil
}

// reportFlows returns a snapshot's flows in scope, most bytes first.
func reportFlows(c *collector, scope *processScope) []*flow {
	flows := slices.DeleteFunc(c.allFlows(), func(f *flow) bool { return !scope.flow(f, c) })
	slices.SortFunc(flows, func(a, b *flow) int { return cmp.Compare(b.RX+b.TX, a.RX+a.TX) })
	return flows
}

func parseFailures(flows []*flow) int {
	var failures int
	for _, f := range flows {
		if f.Domain != nil && f.Domain.Evidence().ParseError != "" {
			failures++
		}
	}
	return failures
}

func printReport(c collector, interfaceName string, limit int, probeStats *probe.Statistics, scope *processScope) {
	flows := reportFlows(&c, scope)
	if interfaceName == "OVERVIEW" {
		fmt.Printf("\nOVERVIEW: %d observed flows; IP bytes below use one capture point per flow, not an exact whole-host total; a NAT's two tuples are one flow once conntrack links them\n", len(flows))
	} else {
		fmt.Printf("\n%s: %d IP packets, %d IP bytes, %d retained flows, %d expired flows, %d packets without flow index\n", interfaceName, c.packets, c.bytes, len(flows), c.expiredFlows, c.droppedFlow)
	}
	if c.expiredRX+c.expiredTX+c.unindexedRX+c.unindexedTX > 0 {
		fmt.Printf("detail unavailable: expired RX=%d TX=%d; unindexed RX=%d TX=%d\n", c.expiredRX, c.expiredTX, c.unindexedRX, c.unindexedTX)
	}
	fmt.Printf("capture status: AF_PACKET delivered=%d dropped=%d, truncated IP packets=%d; PID events=%d ring-lost=%d queue-dropped=%d invalid=%d index-dropped=%d; parse failures=%d\n", c.kernelReceived, c.kernelDropped, c.truncated, probeStats.Received.Load(), probeStats.KernelLost.Load(), probeStats.Dropped.Load(), probeStats.Invalid.Load(), c.droppedRole, parseFailures(flows))
	if interfaceName == "OVERVIEW" {
		fmt.Printf("PID socket I/O: %dB without PID index; separate from observed IP bytes\n", c.ioUnindexed.RX+c.ioUnindexed.TX)
	} else {
		fmt.Printf("PID socket I/O: %dB without selected interface/port flow, %dB without PID index; separate from IP packet bytes\n", c.ioUnmatched, c.ioUnindexed.RX+c.ioUnindexed.TX)
	}
	if c.loopback {
		fmt.Println("lo: duplicate receive copies omitted; TX/RX columns reflect capture direction, not two local sockets")
	}
	fmt.Println("PROTO APP            STATE       DIR              IFACE        SOURCE                  TARGET                  RX B      TX B      RTT        RETX    ORIGIN ENDPOINT PID  TARGET ENDPOINT PID  DETAIL")
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
		if f.NAT != nil {
			detail += " [" + f.NAT.String() + "]"
		}
		if tcp := kernelDetail(f); tcp != "" {
			detail += " [tcp " + tcp + "]"
		}
		retx, _ := retransmits(f)
		rtt, _ := flowRTT(f)
		fmt.Printf("%-6s %-14s %-11s %-16s %-12s %-23s %-23s %-9d %-9d %-10s %-7d %-20s %-20s %s\n", proto, f.AppProtocol, flowState(f), f.Direction, interfaceList(f.Interfaces, 0), src, dst, f.RX, f.TX, formatSYNRTT(rtt), retx, formatPID(f.Client), formatPID(f.Server), detail)
	}
	fmt.Println("PID identity = PID@process-start-ns; TCP endpoints are initiator/acceptor, UDP endpoints follow the first datagram. First-packet direction is inferred. ? means unknown TCP initiator. ICMP PIDs cover echo requests sent from this host. RTT and RETX are the kernel's for a local socket, otherwise the SYN handshake sample and overlapping captured segments.")
	if interfaceName == "OVERVIEW" {
		fmt.Println("Domain IP bytes are single-point observations; NAT-transformed paths may still appear as separate connections.")
	}
	if sources := attemptSources(c.attempts); len(sources) > 0 && scope == nil { // Attempts have no process.
		fmt.Println("Inbound attempts without a connection (refused or unanswered), most ports first:")
		for _, source := range sources[:min(len(sources), 10)] {
			fmt.Printf("  %-39s %s\n", source, c.attempts[source])
		}
	}
	printDomains(flows)
	if interfaceName == "OVERVIEW" && c.expiredDomainRX+c.expiredDomainTX > 0 {
		fmt.Printf("expired domain detail (single-point observed IP bytes): RX=%d TX=%d\n", c.expiredDomainRX, c.expiredDomainTX)
	}
}

// pidIOOrder lists processes by socket I/O, most bytes first.
func pidIOOrder(totals map[processID]processIO) []processID {
	return slices.SortedFunc(maps.Keys(totals), func(a, b processID) int {
		return cmp.Compare(totals[b].RX+totals[b].TX, totals[a].RX+totals[a].TX)
	})
}

func printPIDIO(c *collector, limit int, processes *processTable, scope *processScope) {
	totals := c.pidIO
	ids := slices.DeleteFunc(pidIOOrder(totals), func(id processID) bool { return !scope.process(id, totals[id].Name) })
	fmt.Println("\nPID socket I/O (application bytes, independent of IP packet totals):")
	if c.expiredPIDCount > 0 || c.ioUnindexed.RX+c.ioUnindexed.TX > 0 {
		fmt.Printf("expired PID detail: %d identities, RX=%d TX=%d; unindexed RX=%d TX=%d\n", c.expiredPIDCount, c.expiredPIDIO.RX, c.expiredPIDIO.TX, c.ioUnindexed.RX, c.ioUnindexed.TX)
	}
	fmt.Println("PID@START                    PROCESS          PPID     SERVICE                          RX B       TX B")
	for _, id := range ids[:min(limit, len(ids))] {
		v := totals[id]
		parent, service := "-", "unknown cgroup"
		if m := processes.meta(id); m != nil {
			if m.Parent.PID > 0 {
				parent = strconv.Itoa(m.Parent.PID)
			}
			_, service = serviceOf(processes.cgroupOf(m))
		}
		fmt.Printf("%-28s %-16s %-8s %-32s %-10d %d\n", fmt.Sprintf("%d@%d", id.PID, id.StartNS), v.Name, parent, service, v.RX, v.TX)
	}
}

// printServices sums the socket I/O by systemd unit or container.
func printServices(c *collector, limit int, processes *processTable, scope *processScope) {
	services := serviceTotals(c, processes, scope)
	fmt.Println("\nService socket I/O (processes grouped by systemd unit or container through their cgroup):")
	fmt.Println("SERVICE                          PROCS  CONNS  RX B       TX B       CGROUP")
	for _, s := range services[:min(limit, len(services))] {
		fmt.Printf("%-32s %-6d %-6d %-10d %-10d %s\n", s.Label, len(s.Processes), s.Connections, s.RX, s.TX, s.Cgroup)
	}
}

type domainTotals struct {
	Connections uint64
	RX, TX      uint64
	Requests    uint64
	UnknownPID  uint64
}

// domainSummary totals the flows per domain page row and returns the row
// labels, most bytes first.
func domainSummary(flows []*flow) (map[string]*domainTotals, []string) {
	totals := make(map[string]*domainTotals)
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
	}
	labels := slices.SortedFunc(maps.Keys(totals), func(a, b string) int {
		return cmp.Compare(totals[b].RX+totals[b].TX, totals[a].RX+totals[a].TX)
	})
	return totals, labels
}

func printDomains(flows []*flow) {
	totals, labels := domainSummary(flows)
	var pageBytes, connections uint64
	for _, row := range totals {
		pageBytes += row.RX + row.TX
		connections += row.Connections
	}
	fmt.Printf("\nDomain summary (HTTP Host, TLS/QUIC SNI, PROXY target, OpenSSL SNI, DNS answer hint): %d IP bytes on %d recognized connections (subset of capture)\n", pageBytes, connections)
	fmt.Println(httpsCoverage(flows))
	fmt.Println("SOURCE DOMAIN                                   CONNS RX B      TX B      HTTP HOST COUNT  PID UNKNOWN")
	for _, label := range labels {
		row := totals[label]
		fmt.Printf("%-47s %-5d %-9d %-9d %-16d %d\n", label, row.Connections, row.RX, row.TX, row.Requests, row.UnknownPID)
	}
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
