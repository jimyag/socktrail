package main

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jimyag/socktrail/internal/capture"
)

func TestCaptureSessionFiltersFlowAndWritesReadablePCAPNG(t *testing.T) {
	source := netip.MustParseAddrPort("127.0.0.1:40000")
	target := netip.MustParseAddrPort("127.0.0.2:40001")
	key := keyFor(source, target, 17)
	now := time.Now()
	f := &flow{Key: key, Direction: "local", First: now, Last: now, AppProtocol: "DNS", AppSource: "payload+port", Client: participant{PID: 42, Name: "test-client"}}
	collectors := map[string]*collector{"lo": {flows: map[flowKey]*flow{key: f}}}
	session, err := startCapture(filepath.Join(t.TempDir(), "captures"), []string{"lo"}, f, processID{}, collectors)
	if err != nil {
		t.Fatal(err)
	}
	// Built as a tun interface's packet is recorded: the IP packet in a blank
	// Ethernet header, which tcpdump must still decode.
	ip := make([]byte, 20+8+3)
	ip[0], ip[9] = 0x45, 17
	binary.BigEndian.PutUint16(ip[2:4], 31)
	copy(ip[12:16], source.Addr().AsSlice())
	copy(ip[16:20], target.Addr().AsSlice())
	binary.BigEndian.PutUint16(ip[20:22], source.Port())
	binary.BigEndian.PutUint16(ip[22:24], target.Port())
	binary.BigEndian.PutUint16(ip[24:26], 11)
	copy(ip[28:], "dns")
	p := capture.Packet{Interface: "lo", Source: source, Destination: target, Protocol: 17, Frame: capture.EthernetFrame(0x0800, ip), CapturedAt: now}
	if err := session.Write(p, f); err != nil {
		t.Fatal(err)
	}
	if err := session.Write(p, &flow{Key: key}); err != nil {
		t.Fatal(err)
	}
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
	if session.writer.Packets != 1 {
		t.Fatalf("recorded %d packets, want one", session.writer.Packets)
	}
	info, err := os.Stat(session.path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("capture permissions are %o", info.Mode().Perm())
	}
	contents, err := os.ReadFile(session.path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(contents, []byte("packet_direction=rx")) || !bytes.Contains(contents, []byte("origin_pid=42")) || !bytes.Contains(contents, []byte(`origin_process="test-client"`)) {
		t.Fatal("packet comment is missing capture and process evidence")
	}
	if _, err := exec.LookPath("tcpdump"); err != nil {
		return
	}
	out, err := exec.Command("tcpdump", "-nnr", session.path).CombinedOutput()
	if err != nil || !strings.Contains(string(out), "UDP, length 3") {
		t.Fatalf("tcpdump could not decode PCAPNG: %v: %s", err, out)
	}
}

// The history keeps the latest frames within its age and byte limits.
func TestFrameHistoryKeepsLatestFrames(t *testing.T) {
	h := &frameHistory{maxAge: 10 * time.Second}
	f, start := &flow{}, time.Now()
	for i := range 4 {
		h.add(capture.Packet{Frame: make([]byte, 100), CapturedAt: start.Add(time.Duration(i) * 4 * time.Second)}, f)
	}
	if len(h.frames) != 3 || h.bytes != 300 || !h.frames[0].packet.CapturedAt.Equal(start.Add(4*time.Second)) {
		t.Fatalf("after aging: %d frames, %d bytes", len(h.frames), h.bytes)
	}
	h.add(capture.Packet{Frame: make([]byte, historyLimit-150), CapturedAt: start.Add(12 * time.Second)}, f)
	if len(h.frames) != 2 || h.bytes != historyLimit-50 {
		t.Fatalf("over the byte limit: %d frames, %d bytes", len(h.frames), h.bytes)
	}
	h.trim(start.Add(time.Minute))
	if len(h.frames) != 0 || h.bytes != 0 {
		t.Fatalf("after a quiet minute: %d frames, %d bytes", len(h.frames), h.bytes)
	}
}
