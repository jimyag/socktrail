package probe

import (
	"io"
	"maps"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

func TestRingEventSize(t *testing.T) {
	if size := unsafe.Sizeof(BpfEvent{}); size != 128 {
		t.Fatalf("PID ring event is %d B, want 128 B", size)
	}
}

// Needs root to load the probe: sudo go test ./internal/probe/
// It exercises every hook on the running kernel, including the recvmsg and
// accept variants the loader picks by kernel version.
//
// startProbe attaches the probes for netNS and hands their events over one
// at a time.
func startProbe(t *testing.T, netNS uint64) <-chan Event {
	events, _ := startProbeStats(t, netNS)
	return events
}

func startProbeStats(t *testing.T, netNS uint64) (<-chan Event, *Statistics) {
	batches, _, stats, err := StartEmbedded(t.Context(), netNS, 0)
	if err != nil {
		t.Fatal(err)
	}
	events := make(chan Event, 1024)
	go func() {
		defer close(events)
		for batch := range batches {
			for _, e := range batch {
				events <- e
			}
		}
	}()
	return events, stats
}

// ownCgroupID returns the ID of this process's cgroup v2: the inode of its
// directory. It is 0 where cgroup v2 is not mounted at /sys/fs/cgroup, as in
// the test VMs.
func ownCgroupID(t *testing.T) uint64 {
	var fs unix.Statfs_t
	if unix.Statfs("/sys/fs/cgroup", &fs) != nil || fs.Type != unix.CGROUP2_SUPER_MAGIC {
		return 0
	}
	data, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		t.Fatal(err)
	}
	for line := range strings.SplitSeq(string(data), "\n") {
		if path, ok := strings.CutPrefix(line, "0::"); ok {
			info, err := os.Stat(filepath.Join("/sys/fs/cgroup", path))
			if err != nil {
				t.Fatal(err)
			}
			return info.Sys().(*syscall.Stat_t).Ino
		}
	}
	return 0
}

// The tests read the network namespace from /proc/thread-self: a test that
// moves its locked thread into a private namespace may have been running on
// the main thread, which Go cannot discard, and /proc/self follows it.
func TestProbeReportsSocketEvents(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("loading eBPF programs needs root")
	}
	info, err := os.Stat("/proc/thread-self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	events := startProbe(t, info.Sys().(*syscall.Stat_t).Ino)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		buf := make([]byte, 16)
		n, _ := conn.Read(buf)
		_, _ = conn.Write(buf[:n])
	}()
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_, _ = conn.Write([]byte("hello"))
	_, _ = conn.Read(make([]byte, 16))
	client, server := netip.MustParseAddrPort(conn.LocalAddr().String()), netip.MustParseAddrPort(ln.Addr().String())

	receiver, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = receiver.Close() }()
	sender, err := net.DialUDP("udp", nil, receiver.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sender.Close() }()
	_, _ = sender.Write([]byte("datagram"))
	_, _, _ = receiver.ReadFromUDP(make([]byte, 16))
	datagramPort := uint16(sender.LocalAddr().(*net.UDPAddr).Port)

	// A raw socket carries the echo identifier in the message.
	raw, err := net.ListenPacket("ip4:icmp", "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = raw.Close() }()
	_, _ = raw.WriteTo([]byte{8, 0, 0, 0, 0x12, 0x34, 0, 1}, &net.IPAddr{IP: net.IPv4(127, 0, 0, 1)})

	cgroup := ownCgroupID(t)
	want := map[string]func(Event) bool{
		"connect": func(e Event) bool { return e.Operation == "connect" && e.Local == client && e.Remote == server },
		"accept":  func(e Event) bool { return e.Operation == "accept" && e.Local == server && e.Remote == client },
		"tcp recv": func(e Event) bool {
			return e.Protocol == 6 && e.Operation == "recv" && e.Local == server && e.AppBytes == 5
		},
		"tcp state": func(e Event) bool {
			return e.Protocol == 6 && e.Operation == "send" && e.Local == client && e.TCP.RTT > 0 && e.TCP.Cwnd > 0 && e.TCP.SegsOut > 0
		},
		"process": func(e Event) bool {
			return e.Operation == "connect" && e.PID == os.Getpid() && e.ParentPID == os.Getppid() && e.ParentStartNS > 0 &&
				e.CgroupID != 0 && (cgroup == 0 || e.CgroupID == cgroup)
		},
		"udp send": func(e Event) bool {
			return e.Protocol == 17 && e.Operation == "send" && e.Local.Port() == datagramPort && e.AppBytes == 8
		},
		"udp recv": func(e Event) bool { return e.Protocol == 17 && e.Operation == "recv" && e.AppBytes == 8 },
		"raw echo": func(e Event) bool {
			return e.Protocol == 1 && e.Local.Port() == 0x1234 && e.Remote.Addr() == netip.MustParseAddr("127.0.0.1")
		},
	}
	deadline := time.After(5 * time.Second)
	for len(want) > 0 {
		select {
		case e := <-events:
			for name, match := range want {
				if match(e) {
					delete(want, name)
				}
			}
		case <-deadline:
			t.Fatalf("events never seen: %v", slices.Sorted(maps.Keys(want)))
		}
	}
}

func TestProbeReportsConnectResults(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("loading eBPF programs needs root")
	}
	info, err := os.Stat("/proc/thread-self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	events, stats := startProbeStats(t, info.Sys().(*syscall.Stat_t).Ino)
	if !strings.HasSuffix(stats.ConnectStatus, "active") {
		t.Skip(stats.ConnectStatus)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	good := netip.MustParseAddrPort(ln.Addr().String())
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	_ = ln.Close()
	_, err = net.DialTimeout("tcp", good.String(), time.Second)
	if err == nil {
		t.Fatal("closed listener accepted a connection")
	}
	var success, refused bool
	deadline := time.After(3 * time.Second)
	for !success || !refused {
		select {
		case e := <-events:
			if e.Operation != "connect_result" || e.Remote != good || e.PID != os.Getpid() {
				continue
			}
			if e.Local.Port() == 0 {
				t.Fatalf("connect result lost the local port: %+v", e)
			}
			if e.ConnectLatency == 0 {
				t.Fatalf("connect result has no latency: %+v", e)
			}
			if e.Result == 0 {
				success = true
			} else if e.Result == int32(syscall.ECONNREFUSED) {
				refused = true
			}
		case <-deadline:
			t.Fatalf("connect results: success=%t refused=%t", success, refused)
		}
	}
}

func TestProbeReportsAbortedAndTimedOutConnects(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("loading eBPF programs needs root")
	}
	nft, err := exec.LookPath("nft")
	if err != nil {
		t.Skip("needs nft")
	}
	runtime.LockOSThread() // This thread's private namespace ends with the test.
	if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
		t.Fatal(err)
	}
	run := func(name string, args ...string) {
		if out, err := exec.Command(name, args...).CombinedOutput(); err != nil {
			t.Fatalf("%s %v: %v %s", name, args, err, out)
		}
	}
	run("ip", "link", "set", "lo", "up")
	info, err := os.Stat("/proc/thread-self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	batches, _, stats, err := StartEmbedded(t.Context(), info.Sys().(*syscall.Stat_t).Ino, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(stats.ConnectStatus, "active") {
		t.Skip(stats.ConnectStatus)
	}
	run(nft, "add table inet t; add chain inet t in { type filter hook input priority 0; }; add rule inet t in tcp dport 43999 drop")
	connect := func(abort bool) netip.AddrPort {
		fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_NONBLOCK, 0)
		if err != nil {
			t.Fatal(err)
		}
		if err := unix.SetsockoptInt(fd, unix.IPPROTO_TCP, unix.TCP_SYNCNT, 1); err != nil {
			t.Fatal(err)
		}
		if err := unix.Connect(fd, &unix.SockaddrInet4{Port: 43999, Addr: [4]byte{127, 0, 0, 1}}); err != unix.EINPROGRESS {
			t.Fatalf("nonblocking connect: %v", err)
		}
		local, err := unix.Getsockname(fd)
		if err != nil {
			t.Fatal(err)
		}
		port := uint16(local.(*unix.SockaddrInet4).Port)
		localPort := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port)
		if abort {
			time.Sleep(100 * time.Millisecond)
			_ = unix.Close(fd)
		} else {
			t.Cleanup(func() { _ = unix.Close(fd) })
		}
		return localPort
	}
	aborted, timedOut := connect(true), connect(false)
	want := map[netip.AddrPort]int32{aborted: -1, timedOut: int32(syscall.ETIMEDOUT)}
	deadline := time.After(20 * time.Second)
	for len(want) > 0 {
		select {
		case batch := <-batches:
			for _, event := range batch {
				if expected, ok := want[event.Local]; ok && event.Operation == "connect_result" && event.Result == expected && event.ConnectLatency > 0 {
					delete(want, event.Local)
				}
			}
		case <-deadline:
			t.Fatalf("missing connection results: %v", want)
		}
	}
}

// sendfile and splice move socket bytes without tcp_sendmsg or tcp_recvmsg
// on some kernels. Go uses sendfile to copy a file to a connection, and
// splice to copy one connection to another, as a relay does.
func TestProbeCountsSendfileAndSplice(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("loading eBPF programs needs root")
	}
	info, err := os.Stat("/proc/thread-self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	events := startProbe(t, info.Sys().(*syscall.Stat_t).Ino)
	const size = 256 << 10
	path := filepath.Join(t.TempDir(), "payload")
	if err := os.WriteFile(path, make([]byte, size), 0o600); err != nil {
		t.Fatal(err)
	}
	addr := func(a net.Addr) netip.AddrPort { return netip.MustParseAddrPort(a.String()) }

	sink, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sink.Close() }()
	go func() {
		if conn, err := sink.Accept(); err == nil {
			_, _ = io.Copy(io.Discard, conn)
			_ = conn.Close()
		}
	}()
	relay, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = relay.Close() }()
	relayed := make(chan [2]netip.AddrPort, 1)
	go func() {
		in, err := relay.Accept()
		if err != nil {
			return
		}
		defer func() { _ = in.Close() }()
		out, err := net.Dial("tcp", sink.Addr().String())
		if err != nil {
			return
		}
		defer func() { _ = out.Close() }()
		relayed <- [2]netip.AddrPort{addr(in.LocalAddr()), addr(out.LocalAddr())}
		_, _ = out.(*net.TCPConn).ReadFrom(in) // splice
	}()
	client, err := net.Dial("tcp", relay.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = client.(*net.TCPConn).ReadFrom(file) // sendfile
	_ = file.Close()
	_ = client.Close()
	ends := <-relayed

	totals := map[string]uint64{}
	deadline := time.After(10 * time.Second)
	for totals["sendfile"] < size || totals["splice read"] < size || totals["splice write"] < size {
		select {
		case e := <-events:
			switch {
			case e.Operation == "send" && e.Local == addr(client.LocalAddr()):
				totals["sendfile"] += e.AppBytes
			case e.Operation == "recv" && e.Local == ends[0]:
				totals["splice read"] += e.AppBytes
			case e.Operation == "send" && e.Local == ends[1]:
				totals["splice write"] += e.AppBytes
			}
		case <-deadline:
			t.Fatalf("socket bytes counted %v, want %d each", totals, size)
		}
	}
}

// TestProbeReportsKernelRetransmits drops a third of the packets bound for a
// server in a private network namespace, so the client retransmits, and
// compares the probe's running total with the socket's own TCP_INFO.
func TestProbeReportsKernelRetransmits(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("loading eBPF programs needs root")
	}
	nft, err := exec.LookPath("nft")
	if err != nil {
		t.Skip("needs nft")
	}
	runtime.LockOSThread() // Never unlocked: the thread and its namespace end with the test.
	if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
		t.Fatal(err)
	}
	run := func(name string, args ...string) {
		if out, err := exec.Command(name, args...).CombinedOutput(); err != nil {
			t.Fatalf("%s %v: %v %s", name, args, err, out)
		}
	}
	run("ip", "link", "set", "lo", "up")
	info, err := os.Stat("/proc/thread-self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	events := startProbe(t, info.Sys().(*syscall.Stat_t).Ino)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	port := strconv.Itoa(listener.Addr().(*net.TCPAddr).Port)
	run(nft, "add table inet t; add chain inet t in { type filter hook input priority 0; }; add rule inet t in tcp dport "+port+" numgen random mod 3 == 0 drop")

	const size = 1 << 20
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		if _, err := io.CopyN(io.Discard, conn, size); err == nil {
			_, _ = conn.Write([]byte{1}) // All data arrived.
		}
	}()
	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.Write(make([]byte, size)); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Read(make([]byte, 1)); err != nil {
		t.Fatal(err)
	}
	local := netip.MustParseAddrPort(conn.LocalAddr().String())
	var reported uint32
	quiet := time.NewTimer(2 * time.Second) // Retransmissions may still be in flight.
	for waiting := true; waiting; {
		select {
		case e := <-events:
			if e.Operation == "retransmit" && e.Local == local {
				reported = max(reported, e.TCP.Retransmits)
				quiet.Reset(time.Second)
			}
		case <-quiet.C:
			waiting = false
		}
	}
	raw, err := conn.(*net.TCPConn).SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var tcpInfo *unix.TCPInfo
	_ = raw.Control(func(fd uintptr) { tcpInfo, err = unix.GetsockoptTCPInfo(int(fd), unix.IPPROTO_TCP, unix.TCP_INFO) })
	if err != nil {
		t.Fatal(err)
	}
	if reported == 0 || reported != tcpInfo.Total_retrans {
		t.Fatalf("probe reported %d retransmissions, TCP_INFO says %d", reported, tcpInfo.Total_retrans)
	}
}

// TestProbeReportsSYNRetransmits needs no packet filter, so it runs in bare
// virtual machines too: a listener with a full accept queue drops the next
// SYN, and the client retransmits it.
func TestProbeReportsSYNRetransmits(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("loading eBPF programs needs root")
	}
	netns, err := os.Stat("/proc/thread-self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	events := startProbe(t, netns.Sys().(*syscall.Stat_t).Ino)
	listener, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(listener) }()
	loopback := &unix.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}}
	if err := unix.Bind(listener, loopback); err != nil {
		t.Fatal(err)
	}
	if err := unix.Listen(listener, 0); err != nil { // Room for one connection.
		t.Fatal(err)
	}
	bound, err := unix.Getsockname(listener)
	if err != nil {
		t.Fatal(err)
	}
	connect := func() int {
		fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		if err := unix.Connect(fd, bound); err != nil && err != unix.EINPROGRESS {
			t.Fatal(err)
		}
		return fd
	}
	first := connect() // Fills the accept queue, which nobody drains.
	defer func() { _ = unix.Close(first) }()
	for start := time.Now(); ; { // Its handshake must finish before the second SYN.
		info, err := unix.GetsockoptTCPInfo(first, unix.IPPROTO_TCP, unix.TCP_INFO)
		if err != nil {
			t.Fatal(err)
		}
		if info.State == 1 { // TCP_ESTABLISHED
			break
		}
		if time.Since(start) > 5*time.Second {
			t.Fatalf("first connection stuck in state %d", info.State)
		}
		time.Sleep(10 * time.Millisecond)
	}
	second := connect()
	defer func() { _ = unix.Close(second) }()
	name, err := unix.Getsockname(second)
	if err != nil {
		t.Fatal(err)
	}
	local := netip.AddrPortFrom(netip.AddrFrom4(name.(*unix.SockaddrInet4).Addr), uint16(name.(*unix.SockaddrInet4).Port))
	var reported uint32
	var info *unix.TCPInfo
	deadline := time.After(15 * time.Second)
	// The SYN goes again after 1 s, then 2 s more; stop once the probe
	// has caught up with two of them.
	for info == nil || info.Total_retrans < 2 || reported != info.Total_retrans {
		select {
		case e := <-events:
			if e.Operation == "retransmit" && e.Local == local {
				reported = max(reported, e.TCP.Retransmits)
			}
		case <-time.After(100 * time.Millisecond):
		case <-deadline:
			t.Fatalf("probe reported %d SYN retransmissions, TCP_INFO says %+v", reported, info)
		}
		if info, err = unix.GetsockoptTCPInfo(second, unix.IPPROTO_TCP, unix.TCP_INFO); err != nil {
			t.Fatal(err)
		}
	}
}

// TestProbeCountsKTLSBytes moves data over a kernel TLS socket pair set up
// with a fixed key, as the kernel's own tls selftest does. The bytes pass
// through the tls module rather than tcp_sendmsg and tcp_recvmsg.
func TestProbeCountsKTLSBytes(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("loading eBPF programs needs root")
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	accepted := make(chan net.Conn, 1)
	go func() {
		if conn, err := listener.Accept(); err == nil {
			accepted <- conn
		}
	}()
	client, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()
	server := <-accepted
	defer func() { _ = server.Close() }()
	// TLS 1.2 AES-GCM-128 crypto info: version, cipher, IV, key, salt, record sequence.
	const tlsTX, tlsRX = 1, 2
	info := []byte{0x03, 0x03, 51, 0}
	info = append(info, make([]byte, 8+16+4+8)...)
	setsockopt := func(conn net.Conn, level, option int, value string) error {
		raw, err := conn.(*net.TCPConn).SyscallConn()
		if err != nil {
			return err
		}
		var setErr error
		if err := raw.Control(func(fd uintptr) { setErr = unix.SetsockoptString(int(fd), level, option, value) }); err != nil {
			return err
		}
		return setErr
	}
	for _, conn := range []net.Conn{client, server} {
		if err := setsockopt(conn, unix.SOL_TCP, unix.TCP_ULP, "tls"); err != nil {
			t.Skip("kernel TLS unavailable:", err)
		}
	}
	// The tls module is loaded now, so the probe attaches its hooks.
	netns, err := os.Stat("/proc/thread-self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	events := startProbe(t, netns.Sys().(*syscall.Stat_t).Ino)
	// Read events as they come: the whole host's socket I/O shares the queue.
	const size = 64 << 10
	clientEnd := netip.MustParseAddrPort(client.LocalAddr().String())
	serverEnd := netip.MustParseAddrPort(server.LocalAddr().String())
	counted := make(chan [2]uint64, 1)
	go func() {
		var sent, received uint64
		deadline := time.After(10 * time.Second)
		for sent < size || received < size {
			select {
			case e := <-events:
				switch {
				case e.Operation == "send" && e.Local == clientEnd:
					sent += e.AppBytes
				case e.Operation == "recv" && e.Local == serverEnd:
					received += e.AppBytes
				}
			case <-deadline:
				counted <- [2]uint64{sent, received}
				return
			}
		}
		counted <- [2]uint64{sent, received}
	}()
	if err := setsockopt(client, unix.SOL_TLS, tlsTX, string(info)); err != nil {
		t.Fatal(err)
	}
	if err := setsockopt(server, unix.SOL_TLS, tlsRX, string(info)); err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, size)
	go func() { _, _ = client.Write(payload) }()
	if _, err := io.ReadFull(server, make([]byte, size)); err != nil {
		t.Fatal(err)
	}
	if totals := <-counted; totals != [2]uint64{size, size} {
		t.Fatalf("kernel TLS bytes counted: sent %d, received %d, want %d each", totals[0], totals[1], size)
	}
}
