package capture

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"
)

const (
	etherTypeAll   = 0x0003
	arphrdEther    = 1
	arphrdLoopback = 772
	packetOutgoing = 4
	solPacket      = 263
	packetStatsOpt = 6
)

type Statistics struct {
	Received uint32
	Dropped  uint32
}

// SocketStatistics returns the kernel's AF_PACKET counters since socket open.
// Calling this resets those counters, so the caller should do it once at exit.
func SocketStatistics(fd int) (Statistics, error) {
	var stats Statistics
	size := uint32(unsafe.Sizeof(stats))
	_, _, errno := syscall.Syscall6(syscall.SYS_GETSOCKOPT, uintptr(fd), solPacket, packetStatsOpt, uintptr(unsafe.Pointer(&stats)), uintptr(unsafe.Pointer(&size)), 0)
	if errno != 0 {
		return Statistics{}, fmt.Errorf("read AF_PACKET statistics: %w", errno)
	}
	return stats, nil
}

func htons(v uint16) int { return int(v>>8 | v<<8) }

// Open binds an AF_PACKET socket to one interface in the caller's netns.
// The caller must close it; no promiscuous mode is enabled.
func Open(interfaceName string) (int, error) {
	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return -1, fmt.Errorf("interface %q: %w", interfaceName, err)
	}
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, htons(etherTypeAll))
	if err != nil {
		return -1, fmt.Errorf("open AF_PACKET socket (need CAP_NET_RAW): %w", err)
	}
	// The default 208 KiB kernel receive limit is too small for short bursts on
	// a busy host. Force a private 8 MiB socket buffer without changing sysctls.
	if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUFFORCE, 8<<20); err != nil {
		syscall.Close(fd)
		return -1, fmt.Errorf("set AF_PACKET receive buffer (need CAP_NET_ADMIN): %w", err)
	}
	if err := syscall.Bind(fd, &syscall.SockaddrLinklayer{Protocol: uint16(htons(etherTypeAll)), Ifindex: iface.Index}); err != nil {
		syscall.Close(fd)
		return -1, fmt.Errorf("bind AF_PACKET to %s: %w", interfaceName, err)
	}
	if err := syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &syscall.Timeval{Usec: 200_000}); err != nil {
		syscall.Close(fd)
		return -1, fmt.Errorf("set packet receive timeout: %w", err)
	}
	return fd, nil
}

// Run emits decoded IP packets. A timeout allows context cancellation without
// closing the descriptor from a second goroutine.
func Run(ctx context.Context, fd int, interfaceName string, recordFrames *atomic.Bool, out chan<- Packet, errorsOut chan<- error) {
	buffer := make([]byte, 65536)
	loopback := interfaceName == "lo"
	for ctx.Err() == nil {
		n, addr, err := syscall.Recvfrom(fd, buffer, 0)
		if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EINTR) {
			continue
		}
		if err != nil {
			select {
			case errorsOut <- fmt.Errorf("receive packet: %w", err):
			case <-ctx.Done():
			}
			return
		}
		ll, ok := addr.(*syscall.SockaddrLinklayer)
		if !ok {
			continue
		}
		// AF_PACKET sees both the transmit and receive delivery on lo. Count one.
		if loopback && ll.Pkttype != packetOutgoing {
			continue
		}
		frame, outgoing := buffer[:n], ll.Pkttype == packetOutgoing
		// Tun devices, such as WireGuard and Tailscale interfaces, have no
		// link-layer header: the frame starts at the IP header.
		ethernet, etherType := ll.Hatype == arphrdEther || ll.Hatype == arphrdLoopback, uint16(htons(ll.Protocol))
		var p Packet
		if ethernet {
			p, ok = Decode(frame, outgoing)
		} else {
			p, ok = DecodeNetwork(frame, etherType, outgoing)
		}
		if !ok {
			continue
		}
		p.Interface = interfaceName
		p.CapturedAt = time.Now()
		if recordFrames != nil && recordFrames.Load() {
			if !ethernet {
				frame = EthernetFrame(etherType, frame)
			}
			p.Frame = append([]byte(nil), frame...)
		}
		select {
		case out <- p:
		case <-ctx.Done():
			return
		}
	}
}
