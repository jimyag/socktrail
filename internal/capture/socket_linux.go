package capture

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	etherTypeAll   = 0x0003
	arphrdEther    = 1
	arphrdLoopback = 772
	packetOutgoing = 4

	// The receive ring replaces the 8 MiB socket buffer. Packets are packed
	// by length and cut at SnapLength, so 4 MiB holds more of them than that
	// buffer held skbs: a 256 KiB block takes about 2,000 small packets or 15
	// cut GSO frames. The ring counts in RSS; the buffer did not.
	ringBlockSize = 256 << 10
	ringFrameSize = 1 << 11 // Only validated by the kernel; TPACKET_V3 packs packets by length.
	// A partly filled block is handed over after this many milliseconds.
	// Light traffic retires a block per timeout, so blocks times timeout is
	// how long the reader may wait on the main loop before packets drop.
	ringBlockTimeout = 100
	tpacketAlignment = 16
)

type Statistics struct {
	Received uint32
	Dropped  uint32
}

// Socket is an AF_PACKET socket bound to one interface. Packets arrive in a
// TPACKET_V3 ring shared with the kernel, which wakes the reader once per
// filled or timed-out block instead of once per packet.
type Socket struct {
	fd       int
	ring     []byte
	blocks   int
	name     string
	next     int
	packets  []Packet      // Reused for every batch: one is out at a time.
	released chan struct{} // Buffered, so a release after Run returned never blocks.
	mu       sync.Mutex    // Orders capture length changes against the stop.
	stopped  bool
}

// Batch holds the packets of one ring block. Their payloads point into the
// ring, which Release hands back to the kernel; no payload may be read after.
type Batch struct {
	Packets  []Packet
	released chan<- struct{}
}

func (b Batch) Release() { b.released <- struct{}{} }

func htons(v uint16) uint16 { return v>>8 | v<<8 }

// Open binds a ring-backed AF_PACKET socket to one interface in the caller's
// netns; ringSize is rounded down to whole 256 KiB blocks. The caller must
// close it; no promiscuous mode is enabled.
func Open(interfaceName string, ringSize int) (*Socket, error) {
	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return nil, fmt.Errorf("interface %q: %w", interfaceName, err)
	}
	// Protocol 0 receives nothing until bind, so no packet of another
	// interface arrives before the socket is bound to this one.
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open AF_PACKET socket (need CAP_NET_RAW): %w", err)
	}
	s := &Socket{fd: fd, blocks: max(1, ringSize/ringBlockSize), name: interfaceName, released: make(chan struct{}, 1)}
	if err := unix.SetsockoptInt(fd, unix.SOL_PACKET, unix.PACKET_VERSION, unix.TPACKET_V3); err != nil {
		_ = s.Close()
		return nil, fmt.Errorf("select TPACKET_V3: %w", err)
	}
	request := unix.TpacketReq3{
		//nolint:gosec // G115: ring dimensions and file descriptors are bounded by the kernel allocation.
		Block_size: ringBlockSize, Block_nr: uint32(s.blocks),
		//nolint:gosec // G115: ring dimensions and file descriptors are bounded by the kernel allocation.
		Frame_size: ringFrameSize, Frame_nr: uint32(ringBlockSize / ringFrameSize * s.blocks),
		Retire_blk_tov: ringBlockTimeout,
	}
	if err := unix.SetsockoptTpacketReq3(fd, unix.SOL_PACKET, unix.PACKET_RX_RING, &request); err != nil {
		_ = s.Close()
		return nil, fmt.Errorf("set up AF_PACKET receive ring: %w", err)
	}
	if s.ring, err = unix.Mmap(fd, 0, ringBlockSize*s.blocks, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED); err != nil {
		_ = s.Close()
		return nil, fmt.Errorf("map AF_PACKET receive ring: %w", err)
	}
	if err := s.SetFullFrames(false); err != nil {
		_ = s.Close()
		return nil, err
	}
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: htons(etherTypeAll), Ifindex: iface.Index}); err != nil {
		_ = s.Close()
		return nil, fmt.Errorf("bind AF_PACKET to %s: %w", interfaceName, err)
	}
	return s, nil
}

// SetFullFrames keeps whole frames, for a recording, or only SnapLength
// bytes of each: copying less into the ring keeps its cost off the path
// that forwards the packet. Whole means up to 64 KiB, the capture length a
// PCAPNG recording declares.
func (s *Socket) SetFullFrames(full bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch {
	case s.stopped:
		return nil
	case full:
		return s.keep(1 << 16)
	}
	return s.keep(SnapLength)
}

// keep sets how many bytes of each frame reach the ring; 0 delivers none,
// and the kernel then counts them neither as received nor as dropped.
func (s *Socket) keep(length uint32) error {
	filter := []unix.SockFilter{{Code: unix.BPF_RET | unix.BPF_K, K: length}}
	if err := unix.SetsockoptSockFprog(s.fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, &unix.SockFprog{Len: 1, Filter: &filter[0]}); err != nil {
		return fmt.Errorf("set AF_PACKET capture length on %s: %w", s.name, err)
	}
	return nil
}

func (s *Socket) Close() error {
	var unmapErr error
	if s.ring != nil {
		unmapErr = unix.Munmap(s.ring)
		s.ring = nil
	}
	return errors.Join(unmapErr, unix.Close(s.fd))
}

// Statistics returns the kernel's AF_PACKET counters since the last call:
// reading them resets them.
func (s *Socket) Statistics() (Statistics, error) {
	stats, err := unix.GetsockoptTpacketStatsV3(s.fd, unix.SOL_PACKET, unix.PACKET_STATISTICS)
	if err != nil {
		return Statistics{}, fmt.Errorf("read AF_PACKET statistics: %w", err)
	}
	return Statistics{Received: stats.Packets, Dropped: stats.Drops}, nil
}

// Run sends the decoded IP packets of each ring block as one Batch and hands
// the block back to the kernel once the batch is released. It returns when
// ctx is done; the caller unmaps the ring only after that.
func (s *Socket) Run(ctx context.Context, recordFrames *atomic.Bool, out chan<- Batch, errorsOut chan<- error) {
	defer func() {
		// Nothing reads the ring any more: a full ring would count every
		// later packet as dropped while the program shuts down.
		s.mu.Lock()
		defer s.mu.Unlock()
		s.stopped = true
		if err := s.keep(0); err != nil {
			select {
			case errorsOut <- err:
			default:
			}
		}
	}()
	loopback := s.name == "lo"
	headerLen := (unix.SizeofTpacket3Hdr + tpacketAlignment - 1) &^ (tpacketAlignment - 1)
	for ctx.Err() == nil {
		block := s.ring[s.next*ringBlockSize : (s.next+1)*ringBlockSize]
		//nolint:gosec // G103: kernel ABI requires this layout overlay after buffer bounds checks.
		desc := (*unix.TpacketHdrV1)(unsafe.Pointer(&block[unsafe.Offsetof(unix.TpacketBlockDesc{}.Hdr)]))
		if atomic.LoadUint32(&desc.Block_status)&unix.TP_STATUS_USER == 0 {
			// The 200 ms timeout lets cancellation stop the loop.
			//nolint:gosec // G115: ring dimensions and file descriptors are bounded by the kernel allocation.
			fds := []unix.PollFd{{Fd: int32(s.fd), Events: unix.POLLIN}}
			_, err := unix.Poll(fds, 200)
			if err == nil && fds[0].Revents&unix.POLLERR != 0 {
				// The interface went down or away; POLLERR stays set until read.
				errno, readErr := unix.GetsockoptInt(s.fd, unix.SOL_SOCKET, unix.SO_ERROR)
				err = cmp.Or(readErr, error(unix.Errno(errno)))
			}
			if err != nil && !errors.Is(err, unix.EINTR) {
				select {
				case errorsOut <- fmt.Errorf("capture on %s: %w", s.name, err):
				case <-ctx.Done():
				}
				return
			}
			continue
		}
		batch := s.packets[:0]
		offset := int(desc.Offset_to_first_pkt)
		for range desc.Num_pkts {
			if offset+headerLen+unix.SizeofSockaddrLinklayer > len(block) {
				break
			}
			//nolint:gosec // G103: kernel ABI requires this layout overlay after buffer bounds checks.
			header := (*unix.Tpacket3Hdr)(unsafe.Pointer(&block[offset]))
			//nolint:gosec // G103: kernel ABI requires this layout overlay after buffer bounds checks.
			ll := (*unix.RawSockaddrLinklayer)(unsafe.Pointer(&block[offset+headerLen]))
			start := offset + int(header.Mac)
			if start+int(header.Snaplen) > len(block) {
				break
			}
			if p, ok := decodeFrame(block[start:start+int(header.Snaplen)], ll, loopback, recordFrames); ok {
				p.Interface = s.name
				p.CapturedAt = time.Unix(int64(header.Sec), int64(header.Nsec))
				if p.Frame != nil {
					// A frame written before the recording began was cut at SnapLength.
					p.FrameLen = int(header.Len) + len(p.Frame) - int(header.Snaplen)
				}
				batch = append(batch, p)
			}
			offset += int(header.Next_offset)
		}
		s.packets = batch
		if len(batch) > 0 {
			select {
			case out <- Batch{Packets: batch, released: s.released}:
			case <-ctx.Done():
				return
			}
			select {
			case <-s.released:
			case <-ctx.Done():
				return
			}
		}
		atomic.StoreUint32(&desc.Block_status, unix.TP_STATUS_KERNEL)
		s.next = (s.next + 1) % s.blocks
	}
}

func decodeFrame(frame []byte, ll *unix.RawSockaddrLinklayer, loopback bool, recordFrames *atomic.Bool) (Packet, bool) {
	// AF_PACKET sees both the transmit and receive delivery on lo. Count one.
	if loopback && ll.Pkttype != packetOutgoing {
		return Packet{}, false
	}
	outgoing := ll.Pkttype == packetOutgoing
	// Tun devices, such as WireGuard and Tailscale interfaces, have no
	// link-layer header: the frame starts at the IP header.
	ethernet, etherType := ll.Hatype == arphrdEther || ll.Hatype == arphrdLoopback, htons(ll.Protocol)
	var p Packet
	var ok bool
	if ethernet {
		p, ok = Decode(frame, outgoing)
	} else {
		p, ok = DecodeNetwork(frame, etherType, outgoing)
	}
	if !ok {
		return Packet{}, false
	}
	if recordFrames != nil && recordFrames.Load() {
		if ethernet {
			p.Frame = append([]byte(nil), frame...)
		} else {
			p.Frame = EthernetFrame(etherType, frame)
		}
	}
	return p, true
}
