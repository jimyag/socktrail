package probe

import (
	"maps"
	"net"
	"net/netip"
	"os"
	"slices"
	"syscall"
	"testing"
	"time"
)

// Needs root to load the probe: sudo go test ./internal/probe/
// It exercises every hook on the running kernel, including the recvmsg and
// accept variants the loader picks by kernel version.
func TestProbeReportsSocketEvents(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("loading eBPF programs needs root")
	}
	info, err := os.Stat("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	events, _, _, err := StartEmbedded(t.Context(), info.Sys().(*syscall.Stat_t).Ino, 0)
	if err != nil {
		t.Fatal(err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 16)
		n, _ := conn.Read(buf)
		conn.Write(buf[:n])
	}()
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.Write([]byte("hello"))
	conn.Read(make([]byte, 16))
	client, server := netip.MustParseAddrPort(conn.LocalAddr().String()), netip.MustParseAddrPort(ln.Addr().String())

	receiver, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer receiver.Close()
	sender, err := net.DialUDP("udp", nil, receiver.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()
	sender.Write([]byte("datagram"))
	receiver.ReadFromUDP(make([]byte, 16))
	datagramPort := uint16(sender.LocalAddr().(*net.UDPAddr).Port)

	// A raw socket carries the echo identifier in the message.
	raw, err := net.ListenPacket("ip4:icmp", "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	raw.WriteTo([]byte{8, 0, 0, 0, 0x12, 0x34, 0, 1}, &net.IPAddr{IP: net.IPv4(127, 0, 0, 1)})

	want := map[string]func(Event) bool{
		"connect": func(e Event) bool { return e.Operation == "connect" && e.Local == client && e.Remote == server },
		"accept":  func(e Event) bool { return e.Operation == "accept" && e.Local == server && e.Remote == client },
		"tcp recv": func(e Event) bool {
			return e.Protocol == 6 && e.Operation == "recv" && e.Local == server && e.AppBytes == 5
		},
		"udp send": func(e Event) bool {
			return e.Protocol == 17 && e.Operation == "send" && e.Local.Port() == datagramPort && e.AppBytes == 8
		},
		"udp recv": func(e Event) bool { return e.Protocol == 17 && e.Operation == "recv" && e.AppBytes == 8 },
		"raw echo": func(e Event) bool {
			return e.Protocol == 1 && e.Local.Port() == 0x1234 && e.Remote.Addr() == netip.MustParseAddr("127.0.0.1")
		},
	}
	deadline := time.After(5 * time.Second)
	for len(want) > 0 {
		select {
		case e := <-events:
			for name, match := range want {
				if match(e) {
					delete(want, name)
				}
			}
		case <-deadline:
			t.Fatalf("events never seen: %v", slices.Sorted(maps.Keys(want)))
		}
	}
}
