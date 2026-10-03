package app

import (
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
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

	hub, err := listenStreamSocket(path)
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
	if _, err := listenStreamSocket(path); err == nil {
		t.Fatal("a regular file at the socket path should be refused")
	}
	if data, err := os.ReadFile(path); err != nil || string(data) != "keep me" {
		t.Errorf("the file at the socket path changed: %q, %v", data, err)
	}
}

func TestListenStreamSocketRefusesLiveSocket(t *testing.T) {
	path := filepath.Join(t.TempDir(), "live.sock")
	first, err := listenStreamSocket(path)
	if err != nil {
		t.Fatal(err)
	}
	defer first.close()
	if _, err := listenStreamSocket(path); err == nil {
		t.Fatal("a second listener on the same path should be refused")
	}
}

func TestStreamHubDeliversFramesToClients(t *testing.T) {
	path := filepath.Join(t.TempDir(), "socktrail.sock")
	hub, err := listenStreamSocket(path)
	if err != nil {
		t.Fatalf("listenStreamSocket: %v", err)
	}
	defer hub.close()

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("socket mode = %o, want 600", perm)
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
	hub := newStreamHub("", nil)
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

// Nothing is encoded while nobody is subscribed, so an unwatched capture pays
// no serialization cost.
func TestStreamSinkSkipsEncodingWithoutClients(t *testing.T) {
	sink, err := newStreamSink("msgpack", nil, newStreamHub("", nil))
	if err != nil {
		t.Fatal(err)
	}
	// A channel cannot be encoded: an error here would prove the codec ran.
	if err := sink.write(struct{ C chan int }{make(chan int)}); err != nil {
		t.Errorf("the sink encoded a row with no subscribers: %v", err)
	}
}
