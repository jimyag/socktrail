package conntrack

import (
	"encoding/binary"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"runtime"
	"testing"

	"golang.org/x/sys/unix"
)

func message(kind uint16, seq uint32, body []byte) []byte {
	b := binary.NativeEndian.AppendUint32(nil, uint32(unix.NLMSG_HDRLEN+len(body)))
	b = binary.NativeEndian.AppendUint16(b, kind)
	b = binary.NativeEndian.AppendUint16(b, 0)
	b = binary.NativeEndian.AppendUint32(b, seq)
	b = binary.NativeEndian.AppendUint32(b, 0)
	return append(b, body...)
}

func tupleAttribute(kind uint16, src, dst netip.AddrPort) []byte {
	return attribute(kind|nested,
		attribute(1|nested, attribute(1, src.Addr().AsSlice()), attribute(2, dst.Addr().AsSlice())),
		attribute(2|nested, attribute(1, []byte{17}),
			attribute(2, binary.BigEndian.AppendUint16(nil, src.Port())),
			attribute(3, binary.BigEndian.AppendUint16(nil, dst.Port()))))
}

func TestParseReply(t *testing.T) {
	client, server := netip.MustParseAddrPort("192.168.1.10:5353"), netip.MustParseAddrPort("198.51.100.7:53")
	masquerade := netip.MustParseAddrPort("203.0.113.5:61000")
	body := append([]byte{unix.AF_INET, 0, 0, 0}, tupleAttribute(1, client, server)...)
	body = append(body, tupleAttribute(2, server, masquerade)...)
	body = append(body, attribute(3, []byte{0, 0, 1, 0x9e})...) // CTA_STATUS is skipped.
	entry, ok, done, err := parseReply(message(ctnetlinkNew, 7, body), 7)
	want := Entry{Protocol: 17, Orig: [2]netip.AddrPort{client, server}, Reply: [2]netip.AddrPort{server, masquerade}}
	if err != nil || !ok || !done || entry != want || !entry.NAT() || entry.String() != "SNAT 192.168.1.10:5353 as 203.0.113.5:61000" {
		t.Fatalf("entry %+v ok=%v done=%v err=%v %q", entry, ok, done, err, entry.String())
	}
	if entry.Other(masquerade) != client || entry.Other(server) != server {
		t.Fatalf("Other: %s %s", entry.Other(masquerade), entry.Other(server))
	}
	if _, _, done, _ := parseReply(message(ctnetlinkNew, 6, body), 7); done {
		t.Fatal("a reply to an earlier lookup answered this one")
	}
	errno := -int32(unix.ENOENT)
	notFound := binary.NativeEndian.AppendUint32(nil, uint32(errno))
	if _, ok, done, err := parseReply(message(unix.NLMSG_ERROR, 7, notFound), 7); ok || !done || err != nil {
		t.Fatalf("ENOENT: ok=%v done=%v err=%v", ok, done, err)
	}
}

// TestLookupFindsDNAT connects through an nftables DNAT rule in a private
// network namespace and finds the rewritten tuple from either direction.
func TestLookupFindsDNAT(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
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
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	backend := listener.Addr().(*net.TCPAddr).AddrPort()
	run(nft, "add table ip t; add chain ip t out { type nat hook output priority -100; }; add rule ip t out tcp dport 9 dnat to "+backend.String())
	if err := Available(); err != nil {
		t.Skip(err)
	}
	conn, err := net.Dial("tcp", "127.0.0.1:9")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	local, service := conn.LocalAddr().(*net.TCPAddr).AddrPort(), netip.MustParseAddrPort("127.0.0.1:9")
	local = netip.AddrPortFrom(local.Addr().Unmap(), local.Port())
	c, err := Open()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	want := Entry{Protocol: 6, Orig: [2]netip.AddrPort{local, service}, Reply: [2]netip.AddrPort{backend, local}}
	for _, tuple := range [][2]netip.AddrPort{{local, service}, {backend, local}} {
		entry, ok, err := c.Lookup(6, tuple[0], tuple[1])
		if err != nil || !ok || entry != want || entry.String() != "DNAT 127.0.0.1:9 to "+backend.String() {
			t.Fatalf("lookup %v: %+v ok=%v err=%v", tuple, entry, ok, err)
		}
	}
	// The pre-NAT tuple read backwards matches neither direction.
	if _, ok, err := c.Lookup(6, service, local); ok || err != nil {
		t.Fatalf("reverse of the original tuple: ok=%v err=%v", ok, err)
	}
	if _, ok, err := c.Lookup(6, local, netip.AddrPortFrom(service.Addr(), 1)); ok || err != nil {
		t.Fatalf("untracked tuple: ok=%v err=%v", ok, err)
	}
}
