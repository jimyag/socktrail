package app

import (
	"net"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/vmihailenco/msgpack/v5"

	"github.com/jimyag/socktrail/internal/capture"
	"github.com/jimyag/socktrail/internal/probe"
)

// The summary frame is the only way a subscriber learns what its own
// per-process total is missing: bytes that never matched a flow are absent from
// every flow's io[], so summing those undercounts. This test pins the gap at
// 50 bytes and checks the summary does not repeat the mistake.
func TestStreamSummaryCoversBytesMissingFromFlows(t *testing.T) {
	c := &collector{flows: make(map[flowKey]*flow), maxFlows: 10}
	server := netip.MustParseAddrPort("127.0.0.1:8080")
	onFlow := netip.MustParseAddrPort("127.0.0.1:51000")
	offFlow := netip.MustParseAddrPort("127.0.0.1:51001")
	id := processID{PID: 101, StartNS: 1000}
	send := func(local netip.AddrPort, bytes uint64) {
		c.event(probe.Event{
			Protocol: 6, Operation: "send", AppBytes: bytes, Role: "out",
			PID: id.PID, StartNS: id.StartNS, Process: "curl", Local: local, Remote: server,
		})
	}

	c.packet(capture.Packet{Source: onFlow, Destination: server, Protocol: 6, SYN: true, TCPSeq: 1, IPBytes: 40})
	send(onFlow, 100) // Matches a flow, so it lands in that flow's io[].
	send(offFlow, 50) // No flow has this tuple.
	c.expirePendingIO(time.Now(), true)

	var inFlows uint64
	for _, f := range c.allFlows() {
		for _, io := range f.IO {
			inFlows += io.TX
		}
	}
	if inFlows != 100 {
		t.Fatalf("flow io[] holds %d TX bytes, want 100", inFlows)
	}

	rows := allProcessesJSON(c, newProcessTable(t.TempDir()), nil)
	if len(rows) != 1 {
		t.Fatalf("process_io has %d rows, want 1: %+v", len(rows), rows)
	}
	if got := rows[0].TXBytes; got != 150 {
		t.Errorf("process_io TX = %d, want 150: it totals pidIO, not the flows", got)
	}
	if c.ioUnmatched != 50 {
		t.Errorf("ioUnmatched = %d, want 50", c.ioUnmatched)
	}
}

// A subscriber that only saw the --limit rows could not total per-process
// traffic, so the summary lists every process.
func TestStreamSummaryListsEveryProcess(t *testing.T) {
	c := &collector{flows: make(map[flowKey]*flow), pidIO: map[processID]processIO{
		{PID: 1, StartNS: 10}: {Name: "a", ioBytes: ioBytes{RX: 1}},
		{PID: 2, StartNS: 20}: {Name: "b", ioBytes: ioBytes{RX: 2}},
		{PID: 3, StartNS: 30}: {Name: "c", ioBytes: ioBytes{RX: 3}},
	}}
	processes := newProcessTable(t.TempDir())
	if limited := processesJSON(c, 1, processes, nil); len(limited) != 1 {
		t.Fatalf("processesJSON with limit 1 returned %d rows", len(limited))
	}
	if all := allProcessesJSON(c, processes, nil); len(all) != 3 {
		t.Errorf("allProcessesJSON returned %d rows, want all 3", len(all))
	}
}

// A new subscriber must see hello, then the current view, then the summary
// before any increment, all wrapped in frames it can tell apart.
func TestStreamGreetSendsHandshakeBeforeIncrements(t *testing.T) {
	path := filepath.Join(t.TempDir(), "socktrail.sock")
	hub, err := listenStreamSocket(path)
	if err != nil {
		t.Fatalf("listenStreamSocket: %v", err)
	}
	defer hub.close()
	sink, err := newStreamSink("msgpack", nil, hub)
	if err != nil {
		t.Fatal(err)
	}

	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()
	waitFor(t, "the client to be adopted", func() bool {
		sink.adoptClients()
		return hub.active()
	})

	if err := sink.greet(func(send func(any) error) error {
		if err := send(streamFrame{Kind: streamKindHello, Hello: &streamHello{Version: 1}}); err != nil {
			return err
		}
		if err := send(jsonFlow{Protocol: "tcp", Source: "a", Target: "b"}); err != nil {
			return err
		}
		summary := streamSummary{IPBytes: 7}
		return send(streamFrame{Kind: streamKindStats, Stats: &summary})
	}); err != nil {
		t.Fatalf("greet: %v", err)
	}

	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	decoder := msgpack.NewDecoder(conn)
	decoder.SetCustomStructTag("json")
	var hello, flow, summary streamFrame
	for _, target := range []*streamFrame{&hello, &flow, &summary} {
		if err := decoder.Decode(target); err != nil {
			t.Fatalf("decode frame: %v", err)
		}
	}
	if hello.Kind != streamKindHello || hello.Hello == nil || hello.Hello.Version != 1 {
		t.Errorf("first frame = %+v, want hello version 1", hello)
	}
	if flow.Kind != streamKindFlow || flow.Flow == nil || flow.Flow.Protocol != "tcp" {
		t.Errorf("second frame = %+v, want the flow rows", flow)
	}
	if summary.Kind != streamKindStats || summary.Stats == nil || summary.Stats.IPBytes != 7 {
		t.Errorf("third frame = %+v, want the summary", summary)
	}
}

// Nothing is encoded while nobody is subscribed. A nil codec proves it: the
// sink would panic reaching it.
func TestStreamSinkSkipsEncodingWithoutClients(t *testing.T) {
	sink := &streamSink{format: "msgpack", hub: newStreamHub("", nil)}
	if err := sink.flow(jsonFlow{Protocol: "tcp"}); err != nil {
		t.Errorf("the sink encoded a flow with no subscribers: %v", err)
	}
	if err := sink.writeFrame(streamFrame{Kind: streamKindStats}); err != nil {
		t.Errorf("the sink encoded a summary with no subscribers: %v", err)
	}
}
