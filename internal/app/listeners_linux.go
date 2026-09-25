package app

import (
	"encoding/binary"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

type listenerSocket struct {
	tuple          socketTuple
	inode          uint64
	queue, backlog uint32
	backlogKnown   bool
}

// inet_diag_req_v2 and inet_diag_msg are Linux UAPI structures. Only the
// fixed header is needed: LISTEN queue lengths are in the base message.
func socketDiagListeners() map[socketTuple]listenerSocket {
	result := make(map[socketTuple]listenerSocket)
	for _, family := range []uint8{unix.AF_INET, unix.AF_INET6} {
		fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_SOCK_DIAG)
		if err != nil {
			continue // /proc/net remains the fallback.
		}
		func() {
			defer func() { _ = unix.Close(fd) }()
			if unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}) != nil || unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 1}) != nil {
				return
			}
			request := make([]byte, 16+56)
			binary.NativeEndian.PutUint32(request[0:], 72)
			binary.NativeEndian.PutUint16(request[4:], unix.SOCK_DIAG_BY_FAMILY)
			binary.NativeEndian.PutUint16(request[6:], unix.NLM_F_REQUEST|unix.NLM_F_DUMP)
			binary.NativeEndian.PutUint32(request[8:], 1)
			request[16], request[17] = family, unix.IPPROTO_TCP
			binary.NativeEndian.PutUint32(request[20:], 1<<10) // TCP_LISTEN.
			if unix.Sendto(fd, request, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}) != nil {
				return
			}
			buffer := make([]byte, 64*1024)
			for {
				n, _, err := unix.Recvfrom(fd, buffer, 0)
				if err != nil {
					return
				}
				for offset := 0; offset+16 <= n; {
					length := int(binary.NativeEndian.Uint32(buffer[offset:]))
					if length < 16 || offset+length > n {
						return
					}
					kind := binary.NativeEndian.Uint16(buffer[offset+4:])
					if kind == unix.NLMSG_DONE || kind == unix.NLMSG_ERROR {
						return
					}
					if kind == unix.SOCK_DIAG_BY_FAMILY {
						if entry, ok := parseDiagListener(buffer[offset+16 : offset+length]); ok {
							result[entry.tuple] = entry
						}
					}
					offset += (length + 3) &^ 3
				}
			}
		}()
	}
	return result
}

func parseDiagListener(data []byte) (listenerSocket, bool) {
	if len(data) < 72 || data[1] != 10 { // inet_diag_msg, TCP_LISTEN.
		return listenerSocket{}, false
	}
	var addr netip.Addr
	switch data[0] {
	case unix.AF_INET:
		addr = netip.AddrFrom4([4]byte(data[8:12]))
	case unix.AF_INET6:
		addr = netip.AddrFrom16([16]byte(data[8:24])).Unmap()
	default:
		return listenerSocket{}, false
	}
	port := binary.BigEndian.Uint16(data[4:6])
	tuple := socketTuple{protocol: 6, local: netip.AddrPortFrom(addr, port)}
	return listenerSocket{
		//nolint:gosec // G602: len(data) >= 72 was checked above.
		tuple: tuple, inode: uint64(binary.NativeEndian.Uint32(data[68:])),
		//nolint:gosec // G602: len(data) >= 72 was checked above.
		queue: binary.NativeEndian.Uint32(data[56:]), backlog: binary.NativeEndian.Uint32(data[60:]), backlogKnown: true,
	}, true
}

func readListenDrops(procRoot string) (overflows, drops uint64) {
	//nolint:gosec // G304: procRoot is the internal procfs root; the leaf is fixed.
	data, err := os.ReadFile(filepath.Join(procRoot, "net", "netstat"))
	if err != nil {
		return 0, 0
	}
	lines := strings.Split(string(data), "\n")
	for i := 0; i+1 < len(lines); i++ {
		head, values := strings.Fields(lines[i]), strings.Fields(lines[i+1])
		if len(head) == 0 || len(head) != len(values) || head[0] != "TcpExt:" || values[0] != "TcpExt:" {
			continue
		}
		for j, name := range head {
			switch name {
			case "ListenOverflows":
				overflows, _ = strconv.ParseUint(values[j], 10, 64)
			case "ListenDrops":
				drops, _ = strconv.ParseUint(values[j], 10, 64)
			}
		}
		break
	}
	return overflows, drops
}
