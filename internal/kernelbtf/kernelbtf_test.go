package kernelbtf

import (
	"fmt"
	"maps"
	"slices"
	"testing"

	"github.com/cilium/ebpf"
)

func recvmsgSpec() *ebpf.CollectionSpec {
	spec := &ebpf.CollectionSpec{Programs: make(map[string]*ebpf.ProgramSpec)}
	for name, function := range map[string]string{
		"tcp_recv": "tcp_recvmsg", "udp_recv": "udp_recvmsg", "tls_recv": "tls_sw_recvmsg",
	} {
		for _, suffix := range []string{"", "_4", "_old"} {
			spec.Programs[name+suffix] = &ebpf.ProgramSpec{AttachTo: function}
		}
	}
	return spec
}

func TestKeepRecvmsgVariants(t *testing.T) {
	for count, suffix := range map[int]string{4: "_4", 5: "", 6: "_old", -1: "missing", 7: "unsupported"} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			spec := recvmsgSpec()
			KeepRecvmsgVariants(spec, func(string) int { return count }, "tcp_recv", "udp_recv", "tls_recv")
			want := []string{}
			if count >= 4 && count <= 6 {
				want = []string{"tcp_recv" + suffix, "tls_recv" + suffix, "udp_recv" + suffix}
			}
			got := slices.Sorted(maps.Keys(spec.Programs))
			if !slices.Equal(got, want) {
				t.Fatalf("programs = %v, want %v", got, want)
			}
		})
	}
}

func TestKeepRecvmsgVariantsUsesEachAttachTarget(t *testing.T) {
	spec := recvmsgSpec()
	counts := map[string]int{"tcp_recvmsg": 5, "udp_recvmsg": 4, "tls_sw_recvmsg": -1}
	KeepRecvmsgVariants(spec, func(name string) int { return counts[name] }, "tcp_recv", "udp_recv", "tls_recv")
	want := []string{"tcp_recv", "udp_recv_4"}
	if got := slices.Sorted(maps.Keys(spec.Programs)); !slices.Equal(got, want) {
		t.Fatalf("programs = %v, want %v", got, want)
	}
}

func TestKeepRecvmsgVariantsHandlesAbsentPrograms(t *testing.T) {
	spec := &ebpf.CollectionSpec{Programs: make(map[string]*ebpf.ProgramSpec)}
	KeepRecvmsgVariants(spec, func(string) int { return -1 }, "missing")
	if len(spec.Programs) != 0 {
		t.Fatal("absent programs must stay absent")
	}
}
