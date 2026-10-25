package app

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/vmihailenco/msgpack/v5"
)

// waitFor polls until ok reports true, which is how the tests wait on the
// accept goroutine without depending on timing.
func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if ok() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// A killed process leaves the socket file behind without a listener. The next
// start has to replace it, or every restart after a crash would fail.
func TestListenStreamSocketReplacesStaleSocket(t *testing.T) {
	path := filepath.Join(t.TempDir(), "stale.sock")
	stale, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	stale.(*net.UnixListener).SetUnlinkOnClose(false)
	if err := stale.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(path); err != nil {
		t.Fatalf("the stale socket file should still exist: %v", err)
	}

	hub, err := listenStreamSocket(path, 0o600)
	if err != nil {
		t.Fatalf("listenStreamSocket on a stale socket: %v", err)
	}
	defer hub.close()
}

// A regular file at the socket path is the user's, not ours to delete.
func TestListenStreamSocketRefusesNonSocketPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "not-a-socket")
	if err := os.WriteFile(path, []byte("keep me"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := listenStreamSocket(path, 0o600); err == nil {
		t.Fatal("a regular file at the socket path should be refused")
	}
	if data, err := os.ReadFile(path); err != nil || string(data) != "keep me" {
		t.Errorf("the file at the socket path changed: %q, %v", data, err)
	}
}

func TestListenStreamSocketRefusesLiveSocket(t *testing.T) {
	path := filepath.Join(t.TempDir(), "live.sock")
	first, err := listenStreamSocket(path, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer first.close()
	if _, err := listenStreamSocket(path, 0o600); err == nil {
		t.Fatal("a second listener on the same path should be refused")
	}
}

// Only a refused connection proves a socket is stale. A datagram socket refuses
// a stream connection, and a listener we may not connect to refuses us; both
// can belong to a running service, so neither path may be removed.
func TestListenStreamSocketKeepsSocketItCannotCheck(t *testing.T) {
	for name, listen := range map[string]func(path string) (io.Closer, error){
		"datagram": func(path string) (io.Closer, error) {
			return net.ListenUnixgram("unixgram", &net.UnixAddr{Name: path, Net: "unixgram"})
		},
		// Root connects anyway and finds the listener; anyone else is denied.
		"no permission": func(path string) (io.Closer, error) {
			listener, err := net.Listen("unix", path)
			if err != nil {
				return nil, err
			}
			return listener, os.Chmod(path, 0)
		},
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "live.sock")
			live, err := listen(path)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = live.Close() }()
			if _, err := listenStreamSocket(path, 0o600); err == nil {
				t.Fatal("a socket that may be in use should be refused")
			}
			if _, err := os.Lstat(path); err != nil {
				t.Errorf("the socket at the path was removed: %v", err)
			}
		})
	}
}

// Exit removes the socket file, so the next start finds the path free. Nothing
// but the listener removes it: net.Listen created the file, so Close unlinks it.
func TestStreamHubCloseRemovesSocket(t *testing.T) {
	path := filepath.Join(t.TempDir(), "socktrail.sock")
	hub, err := listenStreamSocket(path, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	hub.close()
	if _, err := os.Lstat(path); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("the socket file outlived the hub: %v", err)
	}
}

func TestStreamHubDeliversFramesToClients(t *testing.T) {
	path := filepath.Join(t.TempDir(), "socktrail.sock")
	hub, err := listenStreamSocket(path, 0o660)
	if err != nil {
		t.Fatalf("listenStreamSocket: %v", err)
	}
	defer hub.close()

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o660 {
		t.Errorf("socket mode = %o, want 660: the mode argument must be applied", perm)
	}

	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()
	waitFor(t, "the client to be adopted", func() bool {
		hub.adopt()
		return hub.active()
	})

	frame := []byte("first frame")
	hub.broadcast(frame)
	// The codec reuses its buffer, so a client must already hold a copy.
	copy(frame, "XXXXXXXXXXX")

	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	got := make([]byte, len("first frame"))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read frame: %v", err)
	}
	if string(got) != "first frame" {
		t.Errorf("client read %q, want %q: broadcast must copy the frame", got, "first frame")
	}
}

// A client that never reads must be closed, never allowed to stall the capture
// loop, because a stalled loop drops packets.
func TestStreamHubDropsSlowClient(t *testing.T) {
	hub := newStreamHub(nil)
	_, blocked := io.Pipe() // Nobody reads this end, so the write goroutine blocks.
	client := newStreamClient(blocked)
	defer client.close()
	hub.clients[client] = struct{}{}

	done := make(chan struct{})
	go func() {
		defer close(done)
		for range streamClientBuffer + 2 {
			hub.broadcast([]byte("frame"))
		}
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("broadcast blocked on a client that never reads")
	}
	if hub.active() {
		t.Error("the client that fell behind is still registered")
	}
}

// The handshake carries every connection in view, up to maxFlows of them, so a
// client must receive it however many rows that is. Queued frame by frame it
// would overflow the client buffer before the writer took a frame, and every
// new client of a busy host would be dropped, on every reconnect.
func TestStreamGreetLargerThanClientBuffer(t *testing.T) {
	hub := newStreamHub(nil)
	_, blocked := io.Pipe() // The writer takes the first buffer and blocks on it.
	client := newStreamClient(blocked)
	defer client.close()
	hub.clients[client] = struct{}{}
	hub.pending = []*streamClient{client}
	sink, err := newStreamSink("msgpack", nil, hub, allStreamFrameKinds())
	if err != nil {
		t.Fatal(err)
	}
	if err := sink.greet(func(send func(any) error) error {
		for range streamClientBuffer + 10 {
			if err := send(jsonFlow{Protocol: "tcp"}); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("greet: %v", err)
	}
	if !hub.active() {
		t.Error("a handshake longer than the client buffer dropped the client")
	}
}

func TestParseSocketMode(t *testing.T) {
	for value, want := range map[string]fs.FileMode{"0600": 0o600, "0660": 0o660, "777": 0o777} {
		got, err := parseSocketMode(value)
		if err != nil || got != want {
			t.Errorf("parseSocketMode(%q) = %o, %v; want %o", value, got, err, want)
		}
	}
	for _, bad := range []string{"", "abc", "0999", "1777"} {
		if _, err := parseSocketMode(bad); err == nil {
			t.Errorf("parseSocketMode(%q) should be rejected", bad)
		}
	}
}

// A large greeting followed by a refresh must not spend a slot for every flow.
// The blocked writer models a healthy subscriber still decoding the greeting.
func TestStreamRefreshBatchKeepsGreetedClient(t *testing.T) {
	hub := newStreamHub(nil)
	_, blocked := io.Pipe()
	client := newStreamClient(blocked)
	defer client.close()
	hub.clients[client] = struct{}{}
	hub.pending = []*streamClient{client}
	sink, err := newStreamSink("ndjson", nil, hub, allStreamFrameKinds())
	if err != nil {
		t.Fatal(err)
	}
	if err := sink.greet(func(send func(any) error) error {
		return send(streamFrame{Kind: streamKindHello, Hello: &streamHello{Version: 1}})
	}); err != nil {
		t.Fatal(err)
	}
	sink.beginBatch()
	const count = streamClientBuffer + 100
	for i := range count {
		if err := sink.flow(jsonFlow{ID: uint64(i + 1), Protocol: "tcp"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := sink.writeFrame(streamFrame{Kind: streamKindStats, Stats: &streamSummary{}}); err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(bytes.NewReader(sink.batch))
	for range count {
		var frame streamFrame
		if err := decoder.Decode(&frame); err != nil {
			t.Fatal(err)
		}
		if frame.Kind != streamKindFlow {
			t.Fatalf("batch frame kind = %q, want flow", frame.Kind)
		}
	}
	var last streamFrame
	if err := decoder.Decode(&last); err != nil {
		t.Fatal(err)
	}
	if last.Kind != streamKindStats {
		t.Fatalf("last kind = %q, want stats", last.Kind)
	}
	sink.flushBatch()
	if !hub.active() {
		t.Fatal("refresh burst dropped a client still receiving its greeting")
	}
	if len(client.frames) > 2 {
		t.Fatalf("batch used %d queue slots", len(client.frames))
	}
}

func TestStreamClientBoundsQueuedBytes(t *testing.T) {
	hub := newStreamHub(nil)
	_, blocked := io.Pipe()
	client := newStreamClient(blocked)
	defer client.close()
	hub.clients[client] = struct{}{}
	frame := make([]byte, 4<<20)
	for range 5 {
		hub.broadcast(frame)
	}
	if hub.active() {
		t.Fatal("byte budget did not drop a blocked client")
	}
	if got := client.queuedBytes.Load(); got > streamClientByteBudget {
		t.Fatalf("queued %d bytes, budget %d", got, streamClientByteBudget)
	}
}

// A refresh is dropped when its fingerprint matches, so a field the fingerprint
// misses would never reach a subscriber again. The check walks the encoded
// output instead of the struct: whatever the codec writes must move the hash.
func TestFlowContentHashCoversEveryEncodedField(t *testing.T) {
	baseline := testFlowRow()
	baselineHash := flowContentHash(&baseline)
	var walk func(reflect.Type, string, []int)
	walk = func(typ reflect.Type, path string, indices []int) {
		for typ.Kind() == reflect.Pointer || typ.Kind() == reflect.Slice {
			typ = typ.Elem()
		}
		if typ.Kind() == reflect.Struct && typ != reflect.TypeFor[time.Time]() {
			for i := range typ.NumField() {
				field := typ.Field(i)
				name, _, _ := strings.Cut(field.Tag.Get("json"), ",")
				if name == "changes" || name == "-" {
					continue
				}
				walk(field.Type, path+"/"+field.Name, append(slices.Clone(indices), i))
			}
			return
		}
		t.Run(path, func(t *testing.T) {
			mutated := testFlowRow()
			mutateJSONField(t, &mutated, indices)
			if reflect.DeepEqual(decodedMsgpack(t, mutated), decodedMsgpack(t, baseline)) {
				t.Fatal("mutation did not change the encoded field")
			}
			if flowContentHash(&mutated) == baselineHash {
				t.Fatal("wire field does not move the fingerprint; refresh would be suppressed")
			}
		})
	}
	walk(reflect.TypeFor[jsonFlow](), "flow", nil)
}

// Go randomizes map iteration order per range, so a fingerprint that depended
// on it would drop and re-send the same refresh at random. Repeating the hash
// over one map is what catches that.
func TestFlowContentHashIgnoresMapIterationOrder(t *testing.T) {
	m := map[string]uint64{"a": 1, "b": 2, "c": 3, "d": 4, "e": 5, "f": 6, "g": 7, "h": 8}
	row := testFlowRow()
	row.Drops = m
	row.Evidence.Hosts = m
	first := flowContentHash(&row)
	for i := range 500 {
		if h := flowContentHash(&row); h != first {
			t.Fatalf("hash changed across iterations: %d != %d at round %d", h, first, i)
		}
	}
	row.Drops = map[string]uint64{"a": 1, "b": 2, "c": 3, "d": 4, "e": 5, "f": 6, "g": 7, "h": 9}
	if flowContentHash(&row) == first {
		t.Error("different map content hashed the same")
	}
	// The same content in a different drops map must fold identically through
	// the production path too.
	build := func(values map[string]uint64) uint64 {
		row := testFlowRow()
		row.Drops = values
		return flowContentHash(&row)
	}
	if build(m) != build(map[string]uint64{"h": 8, "g": 7, "f": 6, "e": 5, "d": 4, "c": 3, "b": 2, "a": 1}) {
		t.Error("drops map folding depends on insertion order")
	}
}

// A refresh repeating the last row must not reach the socket, and the same row
// must go out again once a field changes.
func TestStreamRefreshFlowDropsUnchangedRows(t *testing.T) {
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
	sink.beginBatch()

	row := testFlowRow()
	row.ID = 7
	if err := sink.flow(row); err != nil {
		t.Fatalf("flow: %v", err)
	}
	// An identical refresh carries no information: it must be dropped.
	row.Changes = []string{"refresh"}
	if err := sink.refreshFlow(row); err != nil {
		t.Fatalf("refreshFlow: %v", err)
	}
	// A changed counter must be published.
	row.RXBytes++
	if err := sink.refreshFlow(row); err != nil {
		t.Fatalf("refreshFlow after a change: %v", err)
	}
	// A changed field far from the counters must be published too.
	row.Name = "moved.example"
	if err := sink.refreshFlow(row); err != nil {
		t.Fatalf("refreshFlow after a name change: %v", err)
	}
	sink.flushBatch()

	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	decoder := msgpack.NewDecoder(conn)
	decoder.SetCustomStructTag("json")
	var frames []streamFrame
	for {
		var frame streamFrame
		if err := decoder.Decode(&frame); err != nil {
			break
		}
		frames = append(frames, frame)
	}
	if len(frames) != 3 {
		t.Fatalf("received %d frames, want 3 (first flow, counter change, name change): %+v", len(frames), frames)
	}
	if frames[1].Flow == nil || frames[1].Flow.RXBytes != row.RXBytes {
		t.Errorf("second frame = %+v, want the changed counter", frames[1].Flow)
	}
	if frames[2].Flow == nil || frames[2].Flow.Name != "moved.example" {
		t.Errorf("third frame = %+v, want the changed name", frames[2].Flow)
	}
}

// The sink must publish the changes marker the caller set. It is tempting to
// clear it while computing the content fingerprint, which silently drops every
// new/state/end marker and leaves subscribers unable to tell a change from a
// refresh.
func TestStreamFlowKeepsTheChangesMarker(t *testing.T) {
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
	sink.beginBatch()
	row := testFlowRow()
	row.ID = 21
	row.Changes = []string{"new", "state"}
	if err := sink.flow(row); err != nil {
		t.Fatalf("flow: %v", err)
	}
	sink.flushBatch()

	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	decoder := msgpack.NewDecoder(conn)
	decoder.SetCustomStructTag("json")
	var frame streamFrame
	if err := decoder.Decode(&frame); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if frame.Flow == nil {
		t.Fatal("no flow row in the published frame")
	}
	if !slices.Equal(frame.Flow.Changes, []string{"new", "state"}) {
		t.Errorf("changes = %v, want [new state]: the sink altered the caller's marker", frame.Flow.Changes)
	}
}

// A forgotten connection must be published again even if it repeats its last
// row: the ID may have been reused by a different connection in between.
func TestStreamRefreshFlowRepublishesAfterForget(t *testing.T) {
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
	sink.beginBatch()
	row := testFlowRow()
	row.ID = 11
	row.Changes = []string{"refresh"}
	if err := sink.refreshFlow(row); err != nil {
		t.Fatalf("refreshFlow: %v", err)
	}
	sink.forgetFlow(row.ID)
	if err := sink.refreshFlow(row); err != nil {
		t.Fatalf("refreshFlow after forget: %v", err)
	}
	sink.flushBatch()

	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	decoder := msgpack.NewDecoder(conn)
	decoder.SetCustomStructTag("json")
	var frames []streamFrame
	for {
		var frame streamFrame
		if err := decoder.Decode(&frame); err != nil {
			break
		}
		frames = append(frames, frame)
	}
	if len(frames) != 2 {
		t.Fatalf("received %d frames, want 2 (before and after forget): %+v", len(frames), frames)
	}
}
