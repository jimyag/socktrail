package dropprobe

import (
	"net"
	"os"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf/btf"
)

func TestUnboundUDPDrop(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("loading the kernel drop probe needs root")
	}
	info, err := os.Stat("/proc/thread-self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	updates, err := Start(t.Context(), []uint64{info.Sys().(*syscall.Stat_t).Ino})
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.LocalAddr().(*net.UDPAddr).Port
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	conn, err := net.Dial("udp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.Write([]byte("drop test")); err != nil {
		t.Fatal(err)
	}
	select {
	case samples := <-updates:
		for _, sample := range samples {
			if sample.Target.Port() == uint16(port) && sample.Reason != "" {
				if spec, err := btf.LoadKernelSpec(); err == nil {
					var reasons *btf.Enum
					if spec.TypeByName("skb_drop_reason", &reasons) == nil && sample.Reason != "NO_SOCKET" {
						t.Fatalf("unbound UDP reason = %q, want NO_SOCKET", sample.Reason)
					}
				}
				t.Logf("unbound UDP drop: %+v", sample)
				return
			}
		}
		t.Fatalf("UDP drop missing from %v", samples)
	case <-time.After(3 * time.Second):
		t.Fatal("no kernel drop sample")
	}
}
