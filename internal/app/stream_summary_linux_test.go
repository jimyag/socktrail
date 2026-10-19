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

	rows := processesJSON(c, 0, newProcessTable(t.TempDir()), nil)
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
	if all := processesJSON(c, 0, processes, nil); len(all) != 3 {
		t.Errorf("processesJSON without a limit returned %d rows, want all 3", len(all))
	}
}

// A new subscriber must see hello, then the current view, then the summary
// before any increment, all wrapped in frames it can tell apart.
func TestStreamGreetSendsHandshakeBeforeIncrements(t *testing.T) {
	path := filepath.Join(t.TempDir(), "socktrail.sock")
	hub, err := listenStreamSocket(path, 0o600)
	if err != nil {
		t.Fatalf("listenStreamSocket: %v", err)
	}
	defer hub.close()
	sink, err := newStreamSink("msgpack", nil, hub, allStreamFrameKinds())
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
	sink := &streamSink{format: "msgpack", hub: newStreamHub(nil), kinds: allStreamFrameKinds()}
	if err := sink.flow(jsonFlow{Protocol: "tcp"}); err != nil {
		t.Errorf("the sink encoded a flow with no subscribers: %v", err)
	}
	if err := sink.writeFrame(streamFrame{Kind: streamKindStats}); err != nil {
		t.Errorf("the sink encoded a summary with no subscribers: %v", err)
	}
}

// Standard output has no handshake. The capture loop calls these on every sink,
// so without a hub they must do nothing rather than dereference a nil hub.
// The CI smoke test caught this as a panic at the first tick of a bare
// `--output msgpack` run.
func TestStreamSinkWithoutHubIsANoOp(t *testing.T) {
	sink := &streamSink{format: "msgpack", kinds: allStreamFrameKinds()}
	sink.adoptClients()
	if err := sink.greet(func(send func(any) error) error {
		t.Error("the handshake ran without a hub")
		return nil
	}); err != nil {
		t.Errorf("greet without a hub: %v", err)
	}
	if err := sink.writeFrame(streamFrame{Kind: streamKindStats}); err != nil {
		t.Errorf("writeFrame without a hub: %v", err)
	}
}

// A subscriber that only totals per-process traffic must not have to read every
// flow frame. --socket-kinds stats keeps the socket to hello plus the periodic
// summary, which is what such a consumer actually uses.
func TestSocketKindsStatsSkipsFlowFrames(t *testing.T) {
	path := filepath.Join(t.TempDir(), "socktrail.sock")
	hub, err := listenStreamSocket(path, 0o600)
	if err != nil {
		t.Fatalf("listenStreamSocket: %v", err)
	}
	defer hub.close()
	kinds, err := parseSocketKinds("stats")
	if err != nil {
		t.Fatalf("parseSocketKinds: %v", err)
	}
	sink, err := newStreamSink("msgpack", nil, hub, kinds)
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
		// The handshake still carries the flow snapshot; a stats-only consumer
		// must not receive it.
		for range 4 {
			if err := send(jsonFlow{Protocol: "tcp", Source: "a", Target: "b"}); err != nil {
				return err
			}
		}
		summary := streamSummary{IPBytes: 7}
		return send(streamFrame{Kind: streamKindStats, Stats: &summary})
	}); err != nil {
		t.Fatalf("greet: %v", err)
	}
	// Increments after the handshake are dropped the same way.
	if err := sink.flow(jsonFlow{Protocol: "tcp", Source: "c", Target: "d"}); err != nil {
		t.Fatalf("flow: %v", err)
	}
	if err := sink.writeFrame(streamFrame{Kind: streamKindStats, Stats: &streamSummary{IPBytes: 9}}); err != nil {
		t.Fatalf("stats: %v", err)
	}

	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	decoder := msgpack.NewDecoder(conn)
	decoder.SetCustomStructTag("json")
	// The incremental summary is the last frame sent, so reading up to it sees
	// everything without waiting out the deadline.
	var received []streamFrame
	for {
		var frame streamFrame
		if err := decoder.Decode(&frame); err != nil {
			t.Fatalf("decode after %d frames: %v", len(received), err)
		}
		received = append(received, frame)
		if frame.Kind == streamKindStats && frame.Stats != nil && frame.Stats.IPBytes == 9 {
			break
		}
	}
	if len(received) < 3 {
		t.Fatalf("received %d frames, want hello + handshake stats + incremental stats: %+v",
			len(received), received)
	}
	for i, frame := range received {
		if frame.Kind == streamKindFlow {
			t.Fatalf("frame %d is a flow frame; --socket-kinds stats must not publish any", i)
		}
	}
	if received[0].Kind != streamKindHello {
		t.Errorf("first frame = %q, want hello", received[0].Kind)
	}
	// The handshake summary is the one that reached the client, since the
	// incremental frames follow it in order.
	if received[1].Kind != streamKindStats || received[1].Stats == nil || received[1].Stats.IPBytes != 7 {
		t.Errorf("second frame = %+v, want the handshake summary", received[1])
	}
}

// Turning stats off leaves the socket a bare flow stream, so the flag means what
// it says in both directions.
func TestSocketKindsFlowSkipsStatsFrames(t *testing.T) {
	kinds, err := parseSocketKinds("flow")
	if err != nil {
		t.Fatalf("parseSocketKinds: %v", err)
	}
	if kinds.stats || !kinds.flow {
		t.Fatalf("kinds = %+v, want flow only", kinds)
	}
	// The default publishes everything.
	all, err := parseSocketKinds("stats,flow")
	if err != nil {
		t.Fatalf("parseSocketKinds: %v", err)
	}
	if !all.stats || !all.flow {
		t.Errorf("kinds = %+v, want both", all)
	}
	// An empty or unknown selection is refused rather than silently ignored.
	for _, value := range []string{"", "transit", "stats,nope", "hello"} {
		if _, err := parseSocketKinds(value); err == nil {
			t.Errorf("parseSocketKinds(%q) succeeded, want an error", value)
		}
	}

	// The flag decides what the socket encodes, not just how the value parses:
	// stats frames encode to nothing while hello and flow stay non-empty.
	sink, err := newStreamSink("msgpack", nil, nil, kinds)
	if err != nil {
		t.Fatalf("newStreamSink: %v", err)
	}
	stats, err := sink.encodeFrame(streamFrame{Kind: streamKindStats, Stats: &streamSummary{IPBytes: 7}})
	if err != nil {
		t.Fatalf("encode stats: %v", err)
	}
	if len(stats) != 0 {
		t.Errorf("a flow-only socket encoded %d bytes of stats", len(stats))
	}
	hello, err := sink.encodeFrame(streamFrame{Kind: streamKindHello, Hello: &streamHello{Version: 1}})
	if err != nil {
		t.Fatalf("encode hello: %v", err)
	}
	if len(hello) == 0 {
		t.Error("a flow-only socket dropped hello, which every subscriber needs")
	}
	flow, err := sink.encodeFrame(jsonFlow{Protocol: "tcp", Source: "a", Target: "b"})
	if err != nil {
		t.Fatalf("encode flow: %v", err)
	}
	if len(flow) == 0 {
		t.Error("a flow-only socket dropped a flow frame")
	}
}

// A filtered kind must not reach the client buffer at all: an empty frame still
// takes a slot, and a slow stats-only subscriber would be dropped for flow
// frames it never receives. The client has no writer, so the buffer shows
// exactly what was offered.
func TestSocketKindsFilteredFramesTakeNoBufferSlot(t *testing.T) {
	hub := newStreamHub(nil)
	client := &streamClient{frames: make(chan []byte, 1), closing: make(chan struct{})}
	hub.clients[client] = struct{}{}
	sink, err := newStreamSink("msgpack", nil, hub, streamFrameKinds{stats: true})
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := sink.flow(jsonFlow{Protocol: "tcp"}); err != nil {
			t.Fatalf("flow: %v", err)
		}
	}
	if len(client.frames) != 0 || !hub.active() {
		t.Fatalf("filtered flow frames queued %d buffers, client kept: %v", len(client.frames), hub.active())
	}
}
