package capture

import (
	"bytes"
	"context"
	"io"
	"net"
	"os"
	"testing"
	"time"
)

// TestSocketRingOnLoopback sends one 40 KB TCP segment over lo: the ring
// keeps SnapLength of the frame, which the decoder reports as a payload
// prefix rather than a truncated packet.
func TestSocketRingOnLoopback(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	s, err := Open("lo")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	batches, errs, done := make(chan Batch, 1), make(chan error, 1), make(chan struct{})
	go func() { s.Run(ctx, nil, batches, errs); close(done) }()
	defer func() { cancel(); <-done; s.Close() }() // The ring stays mapped until Run returns.

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		if conn, err := listener.Accept(); err == nil {
			io.Copy(io.Discard, conn)
			conn.Close()
		}
	}()
	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	message := bytes.Repeat([]byte("0123456789"), 4000)
	if _, err := conn.Write(message); err != nil {
		t.Fatal(err)
	}
	local := conn.LocalAddr().(*net.TCPAddr).AddrPort()
	var payload int
	var cut bool // A segment longer than SnapLength keeps.
	deadline := time.After(5 * time.Second)
	for payload < len(message) {
		select {
		case b := <-batches:
			for _, p := range b.Packets {
				if p.Source.Port() != local.Port() || p.PayloadLen == 0 {
					continue
				}
				if p.Truncated || len(p.Payload) != min(p.PayloadLen, maxTCPPayload) || !bytes.Equal(p.Payload, message[payload:payload+len(p.Payload)]) {
					t.Fatalf("segment of %d B: payload %d B truncated=%v", p.PayloadLen, len(p.Payload), p.Truncated)
				}
				payload += p.PayloadLen
				cut = cut || p.PayloadLen > maxTCPPayload
			}
			b.Release()
		case err := <-errs:
			t.Fatal(err)
		case <-deadline:
			t.Fatalf("captured %d of %d payload bytes", payload, len(message))
		}
	}
	if !cut {
		t.Fatal("no segment exceeded the capture length; lo split the write")
	}
}
