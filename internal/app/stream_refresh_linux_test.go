package app

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"

	"github.com/vmihailenco/msgpack/v5"
)

func TestStreamRefreshFilteringAndFullResync(t *testing.T) {
	for name, kinds := range map[string]streamFrameKinds{
		"all": allStreamFrameKinds(), "stats": {stats: true}, "none": {},
	} {
		t.Run(name, func(t *testing.T) {
			hub := newStreamHub(nil)
			reader, writer := io.Pipe()
			defer func() { _ = reader.Close() }()
			client := newStreamClient(writer)
			defer client.close()
			hub.clients[client] = struct{}{}
			sink, err := newStreamSink("msgpack", nil, hub, kinds)
			if err != nil {
				t.Fatal(err)
			}
			sink.beginBatch()
			row := testFlowRow()
			if err := sink.flow(row); err != nil {
				t.Fatal(err)
			}
			firstSize := len(sink.batch)
			if err := sink.refreshFlow(row); err != nil {
				t.Fatal(err)
			}
			if len(sink.batch) != firstSize {
				t.Fatal("unchanged refresh was encoded")
			}
			if !kinds.flow {
				if firstSize != 0 || sink.sentFlow != nil {
					t.Fatal("filtered flow was encoded or cached")
				}
				return
			}
			if firstSize == 0 {
				t.Fatal("initial flow was not encoded")
			}
			cached := sink.sentFlow[row.ID]
			cached.at = time.Now().Add(-streamFullRefreshInterval)
			sink.sentFlow[row.ID] = cached
			if err := sink.refreshFlow(row); err != nil {
				t.Fatal(err)
			}
			if len(sink.batch) <= firstSize {
				t.Fatal("periodic full refresh was suppressed")
			}
			sink.flushBatch()
		})
	}
}

func TestStreamRefreshWithoutSubscribers(t *testing.T) {
	sink, err := newStreamSink("msgpack", nil, newStreamHub(nil), allStreamFrameKinds())
	if err != nil {
		t.Fatal(err)
	}
	row := testFlowRow()
	if err := sink.flow(row); err != nil {
		t.Fatal(err)
	}
	if err := sink.refreshFlow(row); err != nil {
		t.Fatal(err)
	}
	if len(sink.sentFlow) != 0 {
		t.Fatal("unpublished rows were cached")
	}
}

func TestStreamRefreshKeepsBareOutput(t *testing.T) {
	var output bytes.Buffer
	sink, err := newStreamSink("ndjson", &output, nil, allStreamFrameKinds())
	if err != nil {
		t.Fatal(err)
	}
	row := testFlowRow()
	row.Changes = []string{"refresh"}
	if err := sink.refreshFlow(row); err != nil {
		t.Fatal(err)
	}
	firstSize := output.Len()
	if err := sink.refreshFlow(row); err != nil {
		t.Fatal(err)
	}
	if firstSize == 0 || output.Len() != 2*firstSize || sink.sentFlow != nil {
		t.Fatal("bare stdout/log refreshes must not be deduplicated")
	}
}

func TestStreamRefreshKeepsReconnectSnapshot(t *testing.T) {
	hub := newStreamHub(nil)
	server, subscriber := net.Pipe()
	defer func() { _ = subscriber.Close() }()
	client := newStreamClient(server)
	defer client.close()
	hub.clients[client] = struct{}{}
	hub.pending = []*streamClient{client}
	sink, err := newStreamSink("msgpack", nil, hub, allStreamFrameKinds())
	if err != nil {
		t.Fatal(err)
	}
	row := testFlowRow()
	sink.sentFlow[row.ID] = streamFlowFingerprint{hash: flowContentHash(&row), at: time.Now()}
	row.Changes = []string{"snapshot"}
	if err := sink.greet(func(send func(any) error) error { return send(row) }); err != nil {
		t.Fatal(err)
	}
	if err := subscriber.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	decoder := msgpack.NewDecoder(subscriber)
	decoder.SetCustomStructTag("json")
	var frame streamFrame
	if err := decoder.Decode(&frame); err != nil {
		t.Fatal(err)
	}
	if frame.Flow == nil || frame.Flow.ID != row.ID || len(frame.Flow.Changes) != 1 || frame.Flow.Changes[0] != "snapshot" {
		t.Fatalf("cached row missing from reconnect snapshot: %+v", frame)
	}
}

func BenchmarkStreamRefreshFlow(b *testing.B) {
	for _, deduplicate := range []bool{false, true} {
		name := "encode"
		if deduplicate {
			name = "unchanged"
		}
		b.Run(name, func(b *testing.B) {
			hub := newStreamHub(nil)
			reader, writer := io.Pipe()
			defer func() { _ = reader.Close() }()
			client := newStreamClient(writer)
			defer client.close()
			hub.clients[client] = struct{}{}
			sink, err := newStreamSink("msgpack", nil, hub, allStreamFrameKinds())
			if err != nil {
				b.Fatal(err)
			}
			row := testFlowRow()
			sink.beginBatch()
			if err := sink.flow(row); err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				sink.beginBatch()
				if deduplicate {
					err = sink.refreshFlow(row)
				} else {
					err = sink.writeFrame(streamFrame{Kind: streamKindFlow, Flow: &row})
				}
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
