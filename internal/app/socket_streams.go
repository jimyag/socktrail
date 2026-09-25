package app

import (
	"net/netip"
	"time"

	"github.com/jimyag/socktrail/internal/domain"
	"github.com/jimyag/socktrail/internal/quicinitial"
	"github.com/jimyag/socktrail/internal/sockstream"
)

const (
	maxSocketStreams = 20_000
	socketStreamIdle = 2 * time.Minute
	pendingSocketTTL = 10 * time.Second
)

type socketStreamKey struct {
	netns  uint64
	cookie uint64
	sent   bool
	remote netip.AddrPort // Set for UDP: an unconnected socket talks to many peers.
}

// socketStream parses one direction of a socket's first bytes, or the QUIC
// datagrams a UDP socket sends to one peer.
type socketStream struct {
	netns         uint64
	parser        *domain.Stream
	quic          *quicinitial.Tracker // UDP only.
	local, remote netip.AddrPort
	sent          bool
	last          time.Time
}

// socketStreams turns socket-layer chunks into domain evidence. Both
// directions of every socket are parsed; only one that reads as a client's
// ClientHello, request or proxy handshake can name the connection, and once
// the connection's initiator is known, only the direction that carries its
// bytes: a server's reply can read like a request, as a TDS pre-login
// response reads like a SOCKS4 request.
type socketStreams map[socketStreamKey]*socketStream

// add feeds a chunk and returns its stream once it holds client evidence.
func (s socketStreams) add(chunk sockstream.Chunk, now time.Time) *socketStream {
	key := socketStreamKey{netns: chunk.NetNS, cookie: chunk.Cookie, sent: chunk.Sent}
	if chunk.Protocol == 17 {
		key.remote = chunk.Remote
	}
	stream := s[key]
	// Offset 0 starts a socket. Where the kernel has no socket cookies, a new
	// socket can reuse an old one's key, so its stream starts over.
	if stream == nil || chunk.Offset == 0 {
		if stream == nil && len(s) >= maxSocketStreams {
			return nil
		}
		stream = &socketStream{netns: chunk.NetNS, local: chunk.Local, remote: chunk.Remote, sent: chunk.Sent}
		if chunk.Protocol == 17 {
			stream.quic = new(quicinitial.Tracker)
		} else {
			stream.parser = domain.New(0)
		}
		s[key] = stream
	}
	stream.last = now
	if stream.quic != nil {
		// Each UDP chunk starts a datagram; a client Initial names the server.
		hello, _, err := stream.quic.Add(chunk.Data, now)
		if hello == nil || err != nil {
			return nil
		}
		named, err := domain.NewQUICClientHello(hello)
		if err != nil {
			return nil
		}
		stream.parser = named
		return stream
	}
	stream.parser.Add(chunk.Offset, chunk.Data)
	if e := stream.parser.Evidence(); e.ParseError == "" && (e.Named() || e.NoSNI) {
		return stream
	}
	return nil
}

func (s socketStreams) expire(now time.Time) {
	for key, stream := range s {
		if now.Sub(stream.last) > socketStreamIdle {
			delete(s, key)
		}
	}
}

type pendingSocket struct {
	stream *socketStream
	seen   time.Time
}

func unspecified(like netip.Addr) netip.Addr {
	if like.Is4() {
		return netip.IPv4Unspecified()
	}
	return netip.IPv6Unspecified()
}

// socketEvidence attaches socket-layer evidence to the flow with the same
// tuple on this interface, or keeps it briefly for a flow whose packets have
// not been processed yet. An unconnected UDP socket has no local address:
// the kernel picks one per datagram, so its port and peer find the flow.
func (c *collector) socketEvidence(stream *socketStream) {
	local, remote := stream.local, stream.remote
	if !c.acceptPort(local, remote) {
		return
	}
	protocol := uint8(6)
	if stream.quic != nil {
		protocol = 17
	}
	if local.Addr().IsUnspecified() {
		local = netip.AddrPortFrom(unspecified(remote.Addr()), local.Port())
	}
	key := keyFor(local, remote, protocol)
	f := c.flows[key]
	if f == nil && local.Addr().IsUnspecified() {
		f = c.datagramFlow(local.Port(), remote)
	}
	if f != nil {
		attachSocketDomain(f, stream)
		return
	}
	if c.pendingSocket == nil {
		c.pendingSocket = make(map[flowKey]pendingSocket)
	}
	if len(c.pendingSocket) < maxPendingIOSamples {
		c.pendingSocket[key] = pendingSocket{stream: stream, seen: time.Now()}
	}
}

// datagramFlow finds the UDP flow between remote and any local address on
// port.
func (c *collector) datagramFlow(port uint16, remote netip.AddrPort) *flow {
	for key, f := range c.flows {
		if key.Protocol == 17 && (key.A == remote && key.B.Port() == port || key.B == remote && key.A.Port() == port) {
			return f
		}
	}
	return nil
}

// attachSocketDomain records the socket's copy of the client bytes. It also
// labels the application for a flow whose captured packets never showed
// them, such as the return path of a transparently proxied connection.
func attachSocketDomain(f *flow, s *socketStream) {
	client := s.local // The client's bytes: what its socket sent, or what the server's received.
	if !s.sent {
		client = s.remote
	}
	if s.quic == nil && f.Initiator.IsValid() && client != f.Initiator {
		return
	}
	stream := s.parser
	f.SocketDomain = stream
	if f.AppProtocol == "" || f.AppSource == "record-prefix" {
		switch stream.Evidence().Kind {
		case "tls":
			f.AppProtocol, f.AppSource = "TLS", "ClientHello (socket)"
		case "http":
			f.AppProtocol, f.AppSource = "HTTP", "HTTP request header (socket)"
		case "http2":
			f.AppProtocol, f.AppSource = "HTTP/2", "HTTP/2 HEADERS (socket)"
			if stream.Evidence().GRPC {
				f.AppProtocol = "gRPC"
			}
		case "quic":
			f.AppProtocol, f.AppSource = "QUIC", "QUIC Initial ClientHello (socket)"
		}
	}
	chooseDomain(f)
}
