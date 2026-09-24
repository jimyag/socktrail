package quicinitial

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// The encrypted client Initial packets are from RFC 9001 Appendix A.2 and
// RFC 9369 Appendix A.2. Both contain a ClientHello for example.com.
func TestRFCClientInitial(t *testing.T) {
	for _, name := range []string{"rfc9001-client-initial.hex", "rfc9369-client-initial.hex"} {
		t.Run(name, func(t *testing.T) {
			packet := testPacket(t, name)
			var tracker Tracker
			hello, authenticated, err := tracker.Add(packet, time.Now())
			if err != nil || !authenticated || len(hello) < 4 || hello[0] != 1 {
				t.Fatalf("Add: hello=%x authenticated=%t err=%v", hello, authenticated, err)
			}
			if !bytes.Contains(hello, []byte("example.com")) {
				t.Fatal("ClientHello has no expected SNI")
			}
		})
	}
}

func TestUnauthenticatedInitialIgnored(t *testing.T) {
	packet := testPacket(t, "rfc9001-client-initial.hex")
	packet[len(packet)-1] ^= 1
	var tracker Tracker
	hello, authenticated, err := tracker.Add(packet, time.Now())
	if err != nil || authenticated || hello != nil {
		t.Fatalf("tampered packet accepted: hello=%x authenticated=%t err=%v", hello, authenticated, err)
	}
	packet = testPacket(t, "rfc9001-client-initial.hex")[:500]
	hello, authenticated, err = tracker.Add(packet, time.Now())
	if err != nil || authenticated || hello != nil {
		t.Fatalf("truncated packet accepted: hello=%x authenticated=%t err=%v", hello, authenticated, err)
	}
}

func TestCryptoReassemblyAndRetransmission(t *testing.T) {
	var tracker Tracker
	if err := tracker.addCrypto(4, []byte("abc")); err != nil {
		t.Fatal(err)
	}
	if err := tracker.addCrypto(0, []byte{1, 0, 0, 3}); err != nil {
		t.Fatal(err)
	}
	hello, err := tracker.clientHello()
	if err != nil || !bytes.Equal(hello, []byte{1, 0, 0, 3, 'a', 'b', 'c'}) {
		t.Fatalf("reassembled hello=%x err=%v", hello, err)
	}
	if err := tracker.addCrypto(4, []byte("abc")); err != nil {
		t.Fatalf("retransmission: %v", err)
	}
	if err := tracker.addCrypto(4, []byte("xyz")); err == nil {
		t.Fatal("conflicting retransmission accepted")
	}
}

func TestPendingCryptoOverlapMustAgree(t *testing.T) {
	var tracker Tracker
	if err := tracker.addCrypto(10, []byte("abcdef")); err != nil {
		t.Fatal(err)
	}
	if err := tracker.addCrypto(12, []byte("cdefgh")); err != nil {
		t.Fatalf("matching overlap rejected: %v", err)
	}
	if err := tracker.addCrypto(13, []byte("wrong")); err == nil {
		t.Fatal("conflicting out-of-order overlap accepted")
	}
}

func testPacket(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	packet, err := hex.DecodeString(string(bytes.Join(bytes.Fields(data), nil)))
	if err != nil {
		t.Fatal(err)
	}
	return packet
}
