package main

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jimyag/socktrail/internal/capture"
)

// procAddr prints an endpoint the way /proc/net/tcp does: 32-bit words in
// host byte order.
func procAddr(ap netip.AddrPort) string {
	raw := ap.Addr().AsSlice()
	var text strings.Builder
	for i := 0; i < len(raw); i += 4 {
		fmt.Fprintf(&text, "%08X", binary.NativeEndian.Uint32(raw[i:]))
	}
	return fmt.Sprintf("%s:%04X", text.String(), ap.Port())
}

func procNetLine(local, remote netip.AddrPort, state string, inode int) string {
	return fmt.Sprintf("   0: %s %s %s 00000000:00000000 00:00000000 00000000     0        0 %d 1 0000000000000000 20 4 30 10 -1\n", procAddr(local), procAddr(remote), state, inode)
}

func TestParseProcNetDecodesHostOrderAddresses(t *testing.T) {
	v6 := netip.MustParseAddrPort("[2001:db8::10]:443")
	mapped := netip.MustParseAddrPort("[::ffff:192.0.2.10]:22")
	remote := netip.MustParseAddrPort("[2001:db8::20]:50000")
	sockets := make(map[socketTuple]uint64)
	parseProcNet([]byte("header\n"+procNetLine(v6, remote, "01", 7)+procNetLine(mapped, netip.MustParseAddrPort("[::]:0"), "0A", 8)), 6, sockets)
	if sockets[socketTuple{6, v6, remote}] != 7 {
		t.Fatalf("IPv6 connection not decoded: %v", sockets)
	}
	if sockets[socketTuple{6, netip.MustParseAddrPort("192.0.2.10:22"), netip.AddrPort{}}] != 8 {
		t.Fatalf("IPv4-mapped listener not unmapped: %v", sockets)
	}
}

// Connections that existed before socktrail started are seen mid-stream with
// no connect or accept event. The socket table still names their process and
// shows that the peer connected in.
func TestSocketTableNamesConnectionsSeenMidstream(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.10")
	at := func(addr netip.Addr, port uint16) netip.AddrPort { return netip.AddrPortFrom(addr, port) }
	remote := netip.MustParseAddr("203.0.113.5")
	ssh, https := at(local, 22), at(local, 40000)
	sshPeer, httpsPeer, dnsPeer := at(remote, 50000), netip.MustParseAddrPort("198.51.100.7:443"), at(remote, 40001)
	// A transparent proxy's accepted socket keeps the original destination as
	// its local address, which is not this host's.
	proxied, lanClient := netip.MustParseAddrPort("198.51.100.9:443"), netip.MustParseAddrPort("192.0.2.50:51000")
	any4 := netip.MustParseAddrPort("0.0.0.0:0")

	root := t.TempDir()
	files := map[string]string{
		"net/tcp": "header\n" + procNetLine(at(netip.IPv4Unspecified(), 22), any4, "0A", 100) + procNetLine(ssh, sshPeer, "01", 101) +
			procNetLine(https, httpsPeer, "01", 102) + procNetLine(proxied, lanClient, "01", 103),
		"net/udp": "header\n" + procNetLine(at(netip.IPv4Unspecified(), 53), any4, "07", 200) + procNetLine(at(netip.IPv4Unspecified(), 40001), any4, "07", 201),
	}
	owners := map[int]struct {
		name   string
		inodes []int
	}{123: {"sshd", []int{100, 101}}, 456: {"curl", []int{102}}, 789: {"dnsd", []int{200}}, 790: {"other", []int{201}}, 791: {"proxy", []int{103}}}
	for pid, owner := range owners {
		files[fmt.Sprintf("%d/stat", pid)] = testProcessStat(uint64(pid) * 10)
		files[fmt.Sprintf("%d/comm", pid)] = owner.name + "\n"
	}
	for name, content := range files {
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for pid, owner := range owners {
		fdDir := filepath.Join(root, fmt.Sprint(pid), "fd")
		if err := os.Mkdir(fdDir, 0o700); err != nil {
			t.Fatal(err)
		}
		for fd, inode := range owner.inodes {
			if err := os.Symlink(fmt.Sprintf("socket:[%d]", inode), filepath.Join(fdDir, fmt.Sprint(fd+3))); err != nil {
				t.Fatal(err)
			}
		}
	}

	c := newTestCollector()
	for _, ends := range [][2]netip.AddrPort{{sshPeer, ssh}, {https, httpsPeer}, {lanClient, proxied}} {
		c.packet(capture.Packet{Source: ends[0], Destination: ends[1], Protocol: 6, HasPorts: true, ACK: true, IPBytes: 52})
	}
	c.packet(capture.Packet{Source: dnsPeer, Destination: at(local, 53), Protocol: 17, HasPorts: true, IPBytes: 60})
	inv := &socketInventory{procRoot: root}
	inv.load()
	inv.atStart, inv.local = inv.sockets, map[netip.Addr]bool{local: true}
	c.applySocketInventory(inv)

	clockTicks, err := systemClockTicks()
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []struct {
		key                 flowKey
		direction           string
		initiator           netip.AddrPort
		client, server, pid int
	}{
		{keyFor(sshPeer, ssh, 6), "inbound", sshPeer, 0, 123, 123},
		{keyFor(https, httpsPeer, 6), "outbound", https, 456, 0, 456},
		{keyFor(lanClient, proxied, 6), "inbound", lanClient, 0, 791, 791},
		{keyFor(dnsPeer, at(local, 53), 17), "first-packet-in", dnsPeer, 0, 789, 789},
	} {
		f := c.flows[want.key]
		// Only the TCP connections were in the table when capture began.
		if f == nil || f.Direction != want.direction || f.Initiator != want.initiator || f.Client.PID != want.client || f.Server.PID != want.server || f.Preexisting != (want.key.Protocol == 6) {
			t.Fatalf("flow %v: got %+v", want.key, f)
		}
		owner := f.Client
		if want.client == 0 {
			owner = f.Server
		}
		if owner.Name != owners[want.pid].name || owner.StartNS != ticksToNS(uint64(want.pid)*10, clockTicks) {
			t.Fatalf("flow %v owner %+v, want %s", want.key, owner, owners[want.pid].name)
		}
	}
}
