package app

import (
	"encoding/binary"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"golang.org/x/sys/unix"
)

func TestListenerSocketSources(t *testing.T) {
	local := netip.MustParseAddrPort("127.0.0.1:18080")
	remote := netip.MustParseAddrPort("0.0.0.0:0")
	sockets := make(map[socketTuple]uint64)
	listeners := make(map[socketTuple]listenerSocket)
	parseProcNet([]byte("header\n"+procNetLine(local, remote, "0A", 123)), 6, sockets, listeners)
	tuple := socketTuple{protocol: 6, local: local}
	if got := listeners[tuple]; got.inode != 123 || got.backlogKnown {
		t.Fatalf("/proc listener: %+v", got)
	}

	message := make([]byte, 72)
	message[0], message[1] = unix.AF_INET, 10
	binary.BigEndian.PutUint16(message[4:], local.Port())
	copy(message[8:], local.Addr().AsSlice())
	binary.NativeEndian.PutUint32(message[56:], 2)
	binary.NativeEndian.PutUint32(message[60:], 5)
	binary.NativeEndian.PutUint32(message[68:], 123)
	entry, ok := parseDiagListener(message)
	if !ok || entry.tuple != tuple || entry.queue != 2 || entry.backlog != 5 || !entry.backlogKnown {
		t.Fatalf("sock_diag listener: %+v, %v", entry, ok)
	}
	if _, ok := parseDiagListener(message[:50]); ok {
		t.Fatal("accepted truncated sock_diag message")
	}
}

func TestPortsPageKeepsSameBindInDifferentNamespaces(t *testing.T) {
	tuple := socketTuple{protocol: 6, local: netip.MustParseAddrPort("172.17.0.2:18081")}
	a := &networkNamespace{name: "one", inode: 1001}
	b := &networkNamespace{name: "two", inode: 1002}
	u := &terminalUI{
		namespaces: []*networkNamespace{a, b},
		collectors: map[string]*collector{
			"one:lo": {netns: a.inode, flows: make(map[flowKey]*flow)},
			"two:lo": {netns: b.inode, flows: make(map[flowKey]*flow)},
		},
		socketsByNS: map[uint64]*socketInventory{
			a.inode: {listeners: map[socketTuple]listenerSocket{tuple: {tuple: tuple, inode: 1}}, pids: map[uint64]int{}},
			b.inode: {listeners: map[socketTuple]listenerSocket{tuple: {tuple: tuple, inode: 2}}, pids: map[uint64]int{}},
		},
	}
	rows := u.rows(&collector{}, viewPorts)
	if len(rows) != 2 || rows[0].key == rows[1].key || rows[0].label == rows[1].label {
		t.Fatalf("namespace listener rows merged: %+v", rows)
	}
}

func TestReadListenDrops(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "net"), 0o700); err != nil {
		t.Fatal(err)
	}
	data := []byte("TcpExt: SyncookiesSent ListenOverflows ListenDrops\nTcpExt: 2 3 4\n")
	if err := os.WriteFile(filepath.Join(root, "net", "netstat"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	if overflow, drops := readListenDrops(root); overflow != 3 || drops != 4 {
		t.Fatalf("overflows=%d drops=%d", overflow, drops)
	}
}

func TestSocketDiagLiveListener(t *testing.T) {
	server, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = server.Close() }()
	addr := server.Addr().(*net.TCPAddr).AddrPort()
	entry, ok := socketDiagListeners()[socketTuple{protocol: 6, local: addr}]
	if !ok || !entry.backlogKnown || entry.backlog == 0 || entry.inode == 0 {
		t.Fatalf("sock_diag did not report live listener: %+v, found=%v", entry, ok)
	}
}

func TestSocketDiagPendingAcceptQueue(t *testing.T) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(fd) }()
	if err := unix.Bind(fd, &unix.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}}); err != nil {
		t.Fatal(err)
	}
	if err := unix.Listen(fd, 1); err != nil {
		t.Fatal(err)
	}
	bound, err := unix.Getsockname(fd)
	if err != nil {
		t.Fatal(err)
	}
	port := bound.(*unix.SockaddrInet4).Port
	client, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()
	entry, ok := socketDiagListeners()[socketTuple{protocol: 6, local: netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(port))}]
	if !ok || entry.queue == 0 || entry.backlog != 1 {
		t.Fatalf("pending accept queue: %+v, found=%v", entry, ok)
	}
}

func TestPortRowsIncludeConnectionsAndAttempts(t *testing.T) {
	c := newTestCollector()
	local := netip.MustParseAddrPort("127.0.0.1:18080")
	client := netip.MustParseAddrPort("127.0.0.1:45000")
	key := flowKey{A: client, B: local, Protocol: 6}
	c.flows[key] = &flow{Key: key, Initiator: client, Target: local, Direction: "inbound"}
	c.attempts = map[netip.Addr]*attemptSummary{client.Addr(): {Ports: map[uint16]attemptPort{18080: {Refused: 2}, 18081: {Unanswered: 3}}}}
	tuple := socketTuple{protocol: 6, local: local}
	inv := &socketInventory{listeners: map[socketTuple]listenerSocket{tuple: {tuple: tuple, inode: 123, queue: 1, backlog: 2, backlogKnown: true}}, pids: map[uint64]int{}}
	rows := listenerRows(c, inv, nil, nil, nil)
	if len(rows) != 2 || rows[0].listener.port != 18080 || len(rows[0].flows) != 1 || rows[0].listener.refused != 2 || !rows[1].listener.noListener || rows[1].listener.unanswered != 3 {
		t.Fatalf("port rows: %+v", rows)
	}
	jsonRows := listenersJSON(c, inv, nil, nil)
	if len(jsonRows) != 2 || jsonRows[0].Active != 1 || jsonRows[0].Backlog == nil || *jsonRows[0].Backlog != 2 || jsonRows[1].NoListener != true {
		t.Fatalf("JSON listeners: %+v", jsonRows)
	}
	delete(c.flows, key)
	u := &terminalUI{filter: "port:18080", sockets: inv}
	if filtered := u.rows(c, viewPorts); len(filtered) != 1 || filtered[0].listener.port != 18080 {
		t.Fatalf("idle port filter: %+v", filtered)
	}
}
