// Package sockstream captures the first bytes each local TCP socket sends and
// receives, and the QUIC long-header datagrams each UDP socket sends, at the
// socket layer. A ClientHello or request header arrives whole and with its
// process, even when the packets cross an interface that is not captured,
// are split by TSO/GRO, or are redirected by a transparent proxy.
package sockstream

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/jimyag/socktrail/internal/kernelbtf"
	"github.com/jimyag/socktrail/internal/procname"
)

// Chunk is part of the first 16 KiB one socket sent or received.
type Chunk struct {
	Cookie   uint64 // Unique per socket for its lifetime.
	PID      int
	StartNS  uint64
	Process  string
	Protocol uint8          // 6 or 17. A UDP chunk starts a datagram.
	Local    netip.AddrPort // Unspecified for an unconnected UDP socket.
	Remote   netip.AddrPort
	Sent     bool   // false: bytes the socket received.
	Offset   uint32 // Position of Data in that direction's byte stream.
	Data     []byte
}

type Statistics struct {
	Received   atomic.Uint64
	KernelLost atomic.Uint64
	Dropped    atomic.Uint64
	Invalid    atomic.Uint64
}

// Start attaches the capture for sockets in netNS. A non-zero port limits it
// to connections using that port, like the wire flow filter.
func Start(ctx context.Context, netNS uint64, port uint16) (<-chan Chunk, <-chan error, *Statistics, error) {
	if err := rlimit.RemoveMemlock(); err != nil { // Kernels before 5.11 charge BPF maps to it.
		return nil, nil, nil, fmt.Errorf("remove eBPF memlock limit: %w", err)
	}
	spec, err := LoadSockstream()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("read socket stream probe: %w", err)
	}
	kernelbtf.KeepRecvmsgVariants(spec, "stream_recv_enter", "stream_recv_exit")
	if haveCookies() {
		delete(spec.Programs, "socket_freed")
	} else if err := spec.Variables["has_socket_cookie"].Set(false); err != nil {
		return nil, nil, nil, fmt.Errorf("configure socket stream probe: %w", err)
	}
	objects, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("load socket stream probe: %w", err)
	}
	var links []link.Link
	cleanup := func() {
		for _, attached := range links {
			attached.Close()
		}
		objects.Close()
	}
	key := uint32(0)
	if err := objects.Maps["settings"].Update(key, SockstreamConfig{Netns: netNS, Port: port}, ebpf.UpdateAny); err != nil {
		cleanup()
		return nil, nil, nil, fmt.Errorf("configure socket stream probe: %w", err)
	}
	for name, program := range objects.Programs {
		attached, err := link.AttachTracing(link.TracingOptions{Program: program})
		if err != nil {
			cleanup()
			return nil, nil, nil, fmt.Errorf("attach socket stream probe %s: %w", name, err)
		}
		links = append(links, attached)
	}
	reader, err := ringbuf.NewReader(objects.Maps["chunks"])
	if err != nil {
		cleanup()
		return nil, nil, nil, fmt.Errorf("open socket stream ring: %w", err)
	}
	chunks := make(chan Chunk, 4096)
	done := make(chan error, 1)
	stats := new(Statistics)
	readLost := func() {
		var lost uint64
		if err := objects.Maps["lost"].Lookup(key, &lost); err == nil {
			stats.KernelLost.Store(lost)
		}
	}
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				readLost()
			case <-ctx.Done():
				reader.Close()
				return
			}
		}
	}()
	go func() {
		defer close(chunks)
		defer cleanup()
		var readErr error
		for {
			record, err := reader.Read()
			if errors.Is(err, ringbuf.ErrClosed) && ctx.Err() != nil {
				break
			}
			if err != nil {
				readErr = fmt.Errorf("read socket stream ring: %w", err)
				break
			}
			chunk, err := decode(record.RawSample)
			if err != nil {
				stats.Invalid.Add(1)
				continue
			}
			stats.Received.Add(1)
			select {
			case chunks <- chunk:
			default:
				stats.Dropped.Add(1)
			}
		}
		readLost()
		done <- readErr
	}()
	return chunks, done, stats, nil
}

// haveCookies is replaced in tests to run the address-keyed mode anywhere.
var haveCookies = haveSocketCookie

// haveSocketCookie reports whether tracing programs may call
// bpf_get_socket_cookie, which Linux 5.12 allowed. The probe program has no
// argument for the helper: the verifier rejects that with EACCES when it
// knows the helper here, and with EINVAL when it does not.
func haveSocketCookie() bool {
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Type: ebpf.Tracing, AttachType: ebpf.AttachTraceFEntry, AttachTo: "tcp_sendmsg", License: "GPL",
		Instructions: asm.Instructions{asm.FnGetSocketCookie.Call(), asm.Return()},
	})
	if err == nil {
		prog.Close()
	}
	return !errors.Is(err, syscall.EINVAL)
}

func decode(raw []byte) (Chunk, error) {
	var header SockstreamChunkHeader
	size := binary.Size(header)
	if len(raw) < size {
		return Chunk{}, fmt.Errorf("short socket stream record")
	}
	if err := binary.Read(bytes.NewReader(raw[:size]), binary.NativeEndian, &header); err != nil {
		return Chunk{}, err
	}
	if int(header.Len) > len(raw)-size || header.Direction < 1 || header.Direction > 2 || header.Protocol != 6 && header.Protocol != 17 {
		return Chunk{}, fmt.Errorf("invalid socket stream record")
	}
	var local, remote netip.Addr
	switch header.Family {
	case 4:
		local, remote = netip.AddrFrom4([4]byte(header.LocalIp[:4])), netip.AddrFrom4([4]byte(header.RemoteIp[:4]))
	case 6:
		local, remote = netip.AddrFrom16(header.LocalIp).Unmap(), netip.AddrFrom16(header.RemoteIp).Unmap()
	default:
		return Chunk{}, fmt.Errorf("invalid socket stream family %d", header.Family)
	}
	name := make([]byte, 0, len(header.Comm))
	for _, c := range header.Comm {
		if c == 0 {
			break
		}
		name = append(name, byte(c))
	}
	return Chunk{
		Cookie: header.Cookie, PID: int(header.Pid), StartNS: header.StartNs, Process: procname.Clean(name), Protocol: header.Protocol,
		Local:  netip.AddrPortFrom(local, header.LocalPort),
		Remote: netip.AddrPortFrom(remote, header.RemotePort),
		Sent:   header.Direction == 1, Offset: header.Offset,
		Data: bytes.Clone(raw[size : size+int(header.Len)]),
	}, nil
}
