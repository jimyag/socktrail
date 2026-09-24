package main

import (
	"encoding/binary"
	"encoding/hex"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/jimyag/socktrail/internal/procname"
)

// The kernel socket table fills in what the eBPF probes cannot see: sockets
// that already existed, or whose connect or accept ran before the probes
// attached. It is the same source ss and netstat read.

const socketTableInterval = 10 * time.Second

// socketTuple names a socket by its endpoints. A TCP listener or an
// unconnected UDP socket has no remote endpoint.
type socketTuple struct {
	protocol      uint8
	local, remote netip.AddrPort
}

// socketInventory is the latest reading of the TCP and UDP sockets in
// socktrail's network namespace.
type socketInventory struct {
	procRoot  string
	read      time.Time
	loading   bool                   // A background reading is under way.
	loaded    chan *socketInventory  // Delivers it.
	atStart   map[socketTuple]uint64 // The table before capture began.
	sockets   map[socketTuple]uint64 // Inode, 0 when no process holds the socket, as in TIME_WAIT.
	local     map[netip.Addr]bool
	pids      map[uint64]int // Read on first use: walking every process's descriptors is the costly part.
	processes map[int]participant
}

// parseProcNet reads /proc/net/tcp, tcp6, udp or udp6 into sockets.
func parseProcNet(data []byte, protocol uint8, sockets map[socketTuple]uint64) {
	for i, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if i == 0 || len(fields) < 10 {
			continue
		}
		local, okLocal := parseProcAddr(fields[1])
		remote, okRemote := parseProcAddr(fields[2])
		inode, err := strconv.ParseUint(fields[9], 10, 64)
		if !okLocal || !okRemote || err != nil {
			continue
		}
		if protocol == 6 && fields[3] == "0A" || protocol == 17 && remote.Port() == 0 { // TCP LISTEN, or unconnected UDP.
			remote = netip.AddrPort{}
		}
		tuple := socketTuple{protocol, local, remote}
		if sockets[tuple] == 0 {
			sockets[tuple] = inode
		}
	}
}

// parseProcAddr decodes an address printed as 32-bit words in host byte order.
func parseProcAddr(text string) (netip.AddrPort, bool) {
	hexAddr, hexPort, ok := strings.Cut(text, ":")
	port, err := strconv.ParseUint(hexPort, 16, 16)
	raw, hexErr := hex.DecodeString(hexAddr)
	if !ok || err != nil || hexErr != nil || len(raw) != 4 && len(raw) != 16 {
		return netip.AddrPort{}, false
	}
	for i := 0; i < len(raw); i += 4 {
		binary.NativeEndian.PutUint32(raw[i:], binary.BigEndian.Uint32(raw[i:]))
	}
	addr, _ := netip.AddrFromSlice(raw)
	return netip.AddrPortFrom(addr.Unmap(), uint16(port)), true
}

// socketPIDs maps socket inodes to the first process found holding them.
func socketPIDs(procRoot string) map[uint64]int {
	pids := make(map[uint64]int)
	entries, _ := os.ReadDir(procRoot)
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		fdDir := filepath.Join(procRoot, entry.Name(), "fd")
		fds, _ := os.ReadDir(fdDir) // Fails for exited processes and kernel threads.
		for _, fd := range fds {
			link, _ := os.Readlink(filepath.Join(fdDir, fd.Name()))
			number, ok := strings.CutPrefix(link, "socket:[")
			inode, err := strconv.ParseUint(strings.TrimSuffix(number, "]"), 10, 64)
			if _, seen := pids[inode]; ok && err == nil && !seen {
				pids[inode] = pid
			}
		}
	}
	return pids
}

// load reads the socket tables and resets the owners resolved last time.
func (inv *socketInventory) load() {
	inv.sockets, inv.local, inv.pids, inv.processes = make(map[socketTuple]uint64), make(map[netip.Addr]bool), nil, make(map[int]participant)
	for name, protocol := range map[string]uint8{"tcp": 6, "tcp6": 6, "udp": 17, "udp6": 17} {
		if data, err := os.ReadFile(filepath.Join(inv.procRoot, "net", name)); err == nil {
			parseProcNet(data, protocol, inv.sockets)
		}
	}
	addrs, _ := net.InterfaceAddrs()
	for _, addr := range addrs {
		if prefix, err := netip.ParsePrefix(addr.String()); err == nil {
			inv.local[prefix.Addr()] = true
		}
	}
}

// refresh reads the socket tables in the background when some TCP or UDP
// flow has no process on either end; apply takes the reading once it
// arrives. Walking every process's descriptors takes tens of milliseconds
// (30 ms for 6,400 descriptors), longer than a capture ring lasts at 20 Gbps
// while the main loop does not hand its blocks back.
func (inv *socketInventory) refresh(collectors map[string]*collector, now time.Time) {
	inv.read = now
	if inv.loading || !anyOwnerless(collectors) {
		return
	}
	inv.loading = true
	next := &socketInventory{procRoot: inv.procRoot}
	go func() {
		next.load()
		next.pids = socketPIDs(next.procRoot)
		inv.loaded <- next
	}()
}

// apply names the processes of ownerless flows from a background reading.
func (inv *socketInventory) apply(next *socketInventory, collectors map[string]*collector) {
	inv.loading = false
	inv.sockets, inv.local, inv.pids, inv.processes = next.sockets, next.local, next.pids, next.processes
	for _, c := range collectors {
		c.applySocketInventory(inv)
	}
}

// refreshNow reads the socket tables and applies them at once, for the final
// report after capture stopped.
func (inv *socketInventory) refreshNow(collectors map[string]*collector) {
	if !anyOwnerless(collectors) {
		return
	}
	inv.load()
	for _, c := range collectors {
		c.applySocketInventory(inv)
	}
}

func anyOwnerless(collectors map[string]*collector) bool {
	for _, c := range collectors {
		for _, f := range c.flows {
			if ownerless(f) {
				return true
			}
		}
	}
	return false
}

func ownerless(f *flow) bool {
	return f.Key.EtherType == 0 && (f.Key.Protocol == 6 || f.Key.Protocol == 17) && f.Client.PID == 0 && f.Server.PID == 0
}

func (inv *socketInventory) isLocal(addr netip.Addr) bool {
	return inv.local[addr] || addr.IsLoopback()
}

// receiving finds the listener or unconnected UDP socket that accepts traffic
// for local: bound to that address, or to the wildcard address of either
// family. Only a local address can match, so a remote port that happens to
// equal a local one is not taken for it.
func (inv *socketInventory) receiving(protocol uint8, local netip.AddrPort) (uint64, bool) {
	addr := local.Addr()
	if !inv.isLocal(addr) && !addr.IsMulticast() && addr != netip.AddrFrom4([4]byte{255, 255, 255, 255}) {
		return 0, false
	}
	for _, bound := range []netip.Addr{addr, netip.IPv4Unspecified(), netip.IPv6Unspecified()} {
		if inode, ok := inv.sockets[socketTuple{protocol, netip.AddrPortFrom(bound, local.Port()), netip.AddrPort{}}]; ok {
			return inode, true
		}
	}
	return 0, false
}

// owner returns the process holding a socket, identified as the eBPF events
// identify it after tickStartNS.
func (inv *socketInventory) owner(inode uint64) (participant, bool) {
	if inode == 0 {
		return participant{}, false
	}
	if inv.pids == nil {
		inv.pids = socketPIDs(inv.procRoot)
	}
	pid, ok := inv.pids[inode]
	if !ok {
		return participant{}, false
	}
	if p, ok := inv.processes[pid]; ok {
		return p, p.PID != 0
	}
	var p participant
	base := filepath.Join(inv.procRoot, strconv.Itoa(pid))
	stat, statErr := os.ReadFile(filepath.Join(base, "stat"))
	_, ticks, parseErr := parseProcessStat(stat)
	clockTicks, clockErr := systemClockTicks()
	if statErr == nil && parseErr == nil && clockErr == nil {
		comm, _ := os.ReadFile(filepath.Join(base, "comm"))
		p = participant{PID: pid, StartNS: ticksToNS(ticks, clockTicks), Name: procname.Clean(comm)}
	}
	inv.processes[pid] = p
	return p, p.PID != 0
}

// applySocketInventory names the processes of flows that have none and, for a
// TCP connection first seen mid-stream, which side connected. The socket
// state decides, never the port numbers: a listener on the local port, or a
// local address that is not this host's because a transparent proxy accepted
// the connection, means the peer connected in.
func (c *collector) applySocketInventory(inv *socketInventory) {
	for _, f := range c.flows {
		if !ownerless(f) {
			continue
		}
		for _, ends := range [][2]netip.AddrPort{{f.Key.A, f.Key.B}, {f.Key.B, f.Key.A}} {
			local, remote := ends[0], ends[1]
			inode, found := inv.sockets[socketTuple{f.Key.Protocol, local, remote}]
			if !found && f.Key.Protocol == 17 {
				inode, found = inv.receiving(17, local)
			}
			if !found {
				continue
			}
			if _, open := inv.atStart[socketTuple{f.Key.Protocol, local, remote}]; open && !f.SYNSeen {
				f.Preexisting = true
			}
			if f.Key.Protocol == 6 && !f.Initiator.IsValid() {
				f.Initiator, f.Target, f.Direction = local, remote, "outbound"
				if _, listening := inv.receiving(6, local); listening || !inv.isLocal(local.Addr()) {
					f.Initiator, f.Target, f.Direction = remote, local, "inbound"
				}
				if c.loopback {
					f.Direction = "local"
				}
			}
			if p, ok := inv.owner(inode); ok && local == f.Initiator {
				f.Client = p
			} else if ok && local == f.Target {
				f.Server = p
			}
		}
	}
}
