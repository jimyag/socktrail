package app

import (
	"errors"
	"io"
	"io/fs"
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
	sink, err := newStreamSink("msgpack", nil, hub)
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
