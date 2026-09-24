package sockstream

import (
	"bytes"
	"context"
	"io"
	"net"
	"os"
	"syscall"
	"testing"
	"time"
)

// Needs root to load the probe: sudo go test ./internal/sockstream/
// Kernels before 5.12 key sockets by address instead of cookie; that mode
// runs here too, whatever the kernel.
func TestCapturesFirstBytesOfBothSocketDirections(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("loading eBPF programs needs root")
	}
	t.Run("socket cookies", captureBothDirections)
	t.Run("socket addresses", func(t *testing.T) {
		haveCookies = func() bool { return false }
		defer func() { haveCookies = haveSocketCookie }()
		captureBothDirections(t)
	})
}

func captureBothDirections(t *testing.T) {
	info, err := os.Stat("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	chunks, _, stats, err := Start(ctx, info.Sys().(*syscall.Stat_t).Ino, 0)
	if err != nil {
		t.Fatal(err)
	}
	cookies := haveCookies() // A feature probe: it loads a program, which takes most of a second under emulation.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	payload := make([]byte, 20000)
	for i := range payload {
		payload[i] = byte(i * 7)
	}
	go func() {
		conn, err := ln.Accept()
		if err == nil {
			io.Copy(io.Discard, conn)
		}
	}()
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	client := conn.LocalAddr().String()
	conn.Write(payload[:1000])                                                               // write(2): one user buffer.
	(&net.Buffers{payload[1000:1500], payload[1500:1600], payload[1600:3000]}).WriteTo(conn) // writev(2): an iovec array.
	conn.Write(payload[3000:])                                                               // Crosses the 16 KiB budget.
	conn.Close()

	streams := map[bool][]byte{true: make([]byte, 16384), false: make([]byte, 16384)}
	got := map[bool]int{}
	deadline := time.After(5 * time.Second)
	for got[true] < 16384 || got[false] < 16384 {
		select {
		case c := <-chunks:
			if c.Sent && c.Local.String() != client || !c.Sent && c.Remote.String() != client {
				continue // Another socket in this netns.
			}
			if (c.Cookie >= 1<<63) == cookies { // Kernel addresses have the top bit set; cookies count up from 1.
				t.Fatalf("socket key %#x does not match cookie support %t", c.Cookie, cookies)
			}
			copy(streams[c.Sent][c.Offset:], c.Data)
			got[c.Sent] += len(c.Data)
		case <-deadline:
			t.Fatalf("captured sent=%d received=%d of 16384 bytes; ring lost %d, queue dropped %d", got[true], got[false], stats.KernelLost.Load(), stats.Dropped.Load())
		}
	}
	for sent, stream := range streams {
		if got[sent] != 16384 || !bytes.Equal(stream, payload[:16384]) {
			t.Fatalf("sent=%t: captured %d bytes, prefix intact=%t", sent, got[sent], bytes.Equal(stream, payload[:16384]))
		}
	}
}

// An unconnected UDP socket names its peer only in sendto; only QUIC
// long-header datagrams are copied.
func TestCapturesQUICLongHeaderDatagrams(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("loading eBPF programs needs root")
	}
	info, err := os.Stat("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	chunks, _, _, err := Start(ctx, info.Sys().(*syscall.Stat_t).Ino, 0)
	if err != nil {
		t.Fatal(err)
	}
	receiver, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer receiver.Close()
	sender, err := net.ListenUDP("udp", nil) // A dual-stack socket bound to the wildcard address.
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()
	long := append([]byte{0xc3, 0, 0, 0, 1}, make([]byte, 1195)...)
	sender.WriteToUDP([]byte{0x40, 1, 2, 3}, receiver.LocalAddr().(*net.UDPAddr)) // A short header: skipped.
	sender.WriteToUDP(long, receiver.LocalAddr().(*net.UDPAddr))
	port := uint16(sender.LocalAddr().(*net.UDPAddr).Port)
	deadline := time.After(5 * time.Second)
	for {
		select {
		case c := <-chunks:
			if c.Protocol != 17 || c.Local.Port() != port {
				continue
			}
			if !bytes.Equal(c.Data, long) || c.Remote.String() != receiver.LocalAddr().String() || !c.Local.Addr().IsUnspecified() || !c.Sent {
				t.Fatalf("datagram chunk: local=%s remote=%s sent=%t %d bytes", c.Local, c.Remote, c.Sent, len(c.Data))
			}
			return
		case <-deadline:
			t.Fatal("QUIC long-header datagram not captured")
		}
	}
}
