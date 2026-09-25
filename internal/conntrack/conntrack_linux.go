// Package conntrack looks up single connection tracking entries over
// ctnetlink, to learn how NAT rewrote a connection's tuple.
package conntrack

import (
	"cmp"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

// Entry is a tracked connection: each direction's tuple as its first packet
// carries it. Reply is the plain reverse of Orig unless NAT rewrote one side.
type Entry struct {
	Protocol uint8
	Orig     [2]netip.AddrPort // Source, destination.
	Reply    [2]netip.AddrPort
}

// NAT reports whether the reply direction is not the reverse of the original.
func (e Entry) NAT() bool { return e.Reply[0] != e.Orig[1] || e.Reply[1] != e.Orig[0] }

// Other returns the endpoint's counterpart in the other direction's tuple:
// the address a NAT substituted for it, or the endpoint itself.
func (e Entry) Other(endpoint netip.AddrPort) netip.AddrPort {
	switch endpoint {
	case e.Orig[0]:
		return e.Reply[1]
	case e.Orig[1]:
		return e.Reply[0]
	case e.Reply[0]:
		return e.Orig[1]
	case e.Reply[1]:
		return e.Orig[0]
	}
	return endpoint
}

func (e Entry) String() string {
	var parts []string
	if e.Reply[1] != e.Orig[0] {
		parts = append(parts, "SNAT "+e.Orig[0].String()+" as "+e.Reply[1].String())
	}
	if e.Reply[0] != e.Orig[1] {
		parts = append(parts, "DNAT "+e.Orig[1].String()+" to "+e.Reply[0].String())
	}
	return strings.Join(parts, ", ")
}

// Available reports whether lookups can work without loading a module: NAT
// needs nf_nat, and a lookup through an absent nf_conntrack_netlink would
// make the kernel load it.
func Available() error {
	for _, module := range []string{"nf_nat", "nf_conntrack_netlink"} {
		if !moduleLoaded(module) {
			return fmt.Errorf("kernel module %s not loaded", module)
		}
	}
	return nil
}

func moduleLoaded(name string) bool {
	if _, err := os.Stat("/sys/module/" + name); err == nil {
		return true
	}
	var uname unix.Utsname
	if unix.Uname(&uname) != nil {
		return false
	}
	builtin, err := os.ReadFile("/lib/modules/" + unix.ByteSliceToString(uname.Release[:]) + "/modules.builtin")
	return err == nil && strings.Contains(string(builtin), "/"+name+".ko\n")
}

// Conn is a ctnetlink socket for lookups, used by one goroutine.
type Conn struct {
	fd     int
	seq    uint32
	buffer []byte
}

func Open() (*Conn, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_NETFILTER)
	if err != nil {
		return nil, fmt.Errorf("open ctnetlink socket: %w", err)
	}
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("bind ctnetlink socket: %w", err)
	}
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 1}); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("set ctnetlink receive timeout: %w", err)
	}
	return &Conn{fd: fd, buffer: make([]byte, 8192)}, nil
}

func (c *Conn) Close() error { return unix.Close(c.fd) }

const (
	ctnetlinkGet = 1<<8 | 1 // NFNL_SUBSYS_CTNETLINK, IPCTNL_MSG_CT_GET.
	ctnetlinkNew = 1 << 8
	nested       = unix.NLA_F_NESTED
)

// Lookup returns the entry with the directed tuple src to dst, in either of
// its directions; ok is false when conntrack does not track that tuple.
func (c *Conn) Lookup(protocol uint8, src, dst netip.AddrPort) (entry Entry, ok bool, err error) {
	c.seq++
	request := lookupRequest(c.seq, protocol, src.Addr().Unmap(), dst.Addr().Unmap(), src.Port(), dst.Port())
	if err := unix.Sendto(c.fd, request, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return Entry{}, false, fmt.Errorf("send conntrack lookup: %w", err)
	}
	for {
		n, _, err := unix.Recvfrom(c.fd, c.buffer, 0)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return Entry{}, false, fmt.Errorf("receive conntrack reply: %w", err)
		}
		entry, ok, done, err := parseReply(c.buffer[:n], c.seq)
		if done || err != nil {
			return entry, ok, err
		}
		// A late reply to an earlier, timed-out lookup: read on.
	}
}

func attribute(kind uint16, payload ...[]byte) []byte {
	length := 4
	for _, p := range payload {
		length += len(p)
	}
	b := binary.NativeEndian.AppendUint16(nil, uint16(length))
	b = binary.NativeEndian.AppendUint16(b, kind)
	for _, p := range payload {
		b = append(b, p...)
	}
	for len(b)%4 != 0 {
		b = append(b, 0)
	}
	return b
}

func lookupRequest(seq uint32, protocol uint8, src, dst netip.Addr, sport, dport uint16) []byte {
	family, srcKind, dstKind := byte(unix.AF_INET), uint16(1), uint16(2) // CTA_IP_V4_SRC, CTA_IP_V4_DST
	if src.Is6() {
		family, srcKind, dstKind = unix.AF_INET6, 3, 4
	}
	tuple := attribute(1|nested, // CTA_TUPLE_ORIG
		attribute(1|nested, attribute(srcKind, src.AsSlice()), attribute(dstKind, dst.AsSlice())), // CTA_TUPLE_IP
		attribute(2|nested, // CTA_TUPLE_PROTO
			attribute(1, []byte{protocol}),                           // CTA_PROTO_NUM
			attribute(2, binary.BigEndian.AppendUint16(nil, sport)),  // CTA_PROTO_SRC_PORT
			attribute(3, binary.BigEndian.AppendUint16(nil, dport)))) // CTA_PROTO_DST_PORT
	//nolint:gosec // G115: netlink encodes lengths and negative errno in fixed-width fields.
	b := binary.NativeEndian.AppendUint32(nil, uint32(unix.NLMSG_HDRLEN+4+len(tuple)))
	b = binary.NativeEndian.AppendUint16(b, ctnetlinkGet)
	b = binary.NativeEndian.AppendUint16(b, unix.NLM_F_REQUEST)
	b = binary.NativeEndian.AppendUint32(b, seq)
	b = binary.NativeEndian.AppendUint32(b, 0)
	b = append(b, family, 0, 0, 0) // nfgenmsg: family, version 0, resource ID 0.
	return append(b, tuple...)
}

// parseReply reads the kernel's answer to lookup seq: an entry, or an error
// message whose ENOENT means the tuple is not tracked. done is false for
// messages that answer another lookup.
func parseReply(b []byte, seq uint32) (entry Entry, ok, done bool, err error) {
	for len(b) >= unix.NLMSG_HDRLEN {
		length := int(binary.NativeEndian.Uint32(b))
		if length < unix.NLMSG_HDRLEN || length > len(b) {
			return Entry{}, false, true, fmt.Errorf("invalid netlink message length")
		}
		kind, messageSeq := binary.NativeEndian.Uint16(b[4:]), binary.NativeEndian.Uint32(b[8:])
		body := b[unix.NLMSG_HDRLEN:length]
		b = b[min(len(b), (length+3)&^3):]
		if messageSeq != seq {
			continue
		}
		switch kind {
		case unix.NLMSG_ERROR:
			if len(body) < 4 {
				return Entry{}, false, true, fmt.Errorf("short netlink error")
			}
			//nolint:gosec // G115: netlink encodes lengths and negative errno in fixed-width fields.
			switch errno := -int32(binary.NativeEndian.Uint32(body)); unix.Errno(errno) {
			case 0:
				continue // An acknowledgement.
			case unix.ENOENT:
				return Entry{}, false, true, nil
			default:
				//nolint:gosec // G115: netlink encodes lengths and negative errno in fixed-width fields.
				return Entry{}, false, true, fmt.Errorf("conntrack lookup: %w", unix.Errno(errno))
			}
		case ctnetlinkNew:
			if len(body) < 4 {
				return Entry{}, false, true, fmt.Errorf("short conntrack message")
			}
			entry, err := parseEntry(body[4:])
			return entry, err == nil, true, err
		}
	}
	return Entry{}, false, false, nil
}

// attributes calls visit for each netlink attribute in b.
func attributes(b []byte, visit func(kind uint16, payload []byte)) error {
	for len(b) >= 4 {
		length := int(binary.NativeEndian.Uint16(b))
		if length < 4 || length > len(b) {
			return fmt.Errorf("invalid netlink attribute length")
		}
		visit(binary.NativeEndian.Uint16(b[2:])&^(unix.NLA_F_NESTED|unix.NLA_F_NET_BYTEORDER), b[4:length])
		b = b[min(len(b), (length+3)&^3):]
	}
	return nil
}

func parseEntry(b []byte) (Entry, error) {
	var e Entry
	var tupleErr error
	err := attributes(b, func(kind uint16, payload []byte) {
		if kind == 1 || kind == 2 { // CTA_TUPLE_ORIG, CTA_TUPLE_REPLY
			tuple, protocol, err := parseTuple(payload)
			tupleErr = cmp.Or(tupleErr, err)
			e.Protocol = protocol
			if kind == 1 {
				e.Orig = tuple
			} else {
				e.Reply = tuple
			}
		}
	})
	if err = cmp.Or(err, tupleErr); err != nil {
		return Entry{}, err
	}
	if !e.Orig[0].IsValid() || !e.Reply[0].IsValid() {
		return Entry{}, fmt.Errorf("conntrack entry without tuples")
	}
	return e, nil
}

func parseTuple(b []byte) ([2]netip.AddrPort, uint8, error) {
	var addresses [2]netip.Addr
	var ports [2]uint16
	var protocol uint8
	var inner error
	err := attributes(b, func(kind uint16, payload []byte) {
		switch kind {
		case 1: // CTA_TUPLE_IP
			inner = cmp.Or(inner, attributes(payload, func(kind uint16, payload []byte) {
				if kind >= 1 && kind <= 4 { // CTA_IP_V4_SRC, _DST, CTA_IP_V6_SRC, _DST
					addresses[(kind-1)%2], _ = netip.AddrFromSlice(payload)
				}
			}))
		case 2: // CTA_TUPLE_PROTO
			inner = cmp.Or(inner, attributes(payload, func(kind uint16, payload []byte) {
				switch {
				case kind == 1 && len(payload) == 1:
					protocol = payload[0]
				case (kind == 2 || kind == 3) && len(payload) == 2:
					ports[kind-2] = binary.BigEndian.Uint16(payload)
				}
			}))
		}
	})
	if err = cmp.Or(err, inner); err != nil {
		return [2]netip.AddrPort{}, 0, err
	}
	return [2]netip.AddrPort{netip.AddrPortFrom(addresses[0], ports[0]), netip.AddrPortFrom(addresses[1], ports[1])}, protocol, nil
}
