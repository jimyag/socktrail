package main

import (
	"bytes"
	"encoding/hex"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jimyag/socktrail/internal/capture"
)

func TestQUICDomainAppearsInBothDirections(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "internal", "quicinitial", "testdata", "rfc9001-client-initial.hex"))
	if err != nil {
		t.Fatal(err)
	}
	initial, err := hex.DecodeString(string(bytes.Join(bytes.Fields(data), nil)))
	if err != nil {
		t.Fatal(err)
	}
	client := netip.MustParseAddrPort("192.0.2.10:51000")
	server := netip.MustParseAddrPort("192.0.2.20:443")
	for _, outgoing := range []bool{true, false} {
		c := &collector{flows: make(map[flowKey]*flow), maxFlows: 10}
		c.packet(capture.Packet{
			Source: client, Destination: server, Protocol: 17, HasPorts: true,
			Outgoing: outgoing, CapturedAt: time.Now(), Payload: initial, IPBytes: uint32(len(initial) + 28),
		})
		f := c.flows[keyFor(client, server, 17)]
		wantDirection := "inbound"
		if outgoing {
			wantDirection = "outbound"
		}
		if f == nil || f.Domain == nil || f.Domain.Evidence().Group() != "example.com" || f.Domain.Evidence().Kind != "quic" || f.Direction != wantDirection {
			t.Fatalf("outgoing=%t flow=%+v", outgoing, f)
		}
		rows := (&terminalUI{}).rows(c, viewDomain)
		if len(rows) != 1 || rows[0].label != "QUIC example.com" || rows[0].reqs != 0 || rows[0].rx+rows[0].tx != uint64(len(initial)+28) {
			t.Fatalf("outgoing=%t domain rows=%+v", outgoing, rows)
		}
	}
}
