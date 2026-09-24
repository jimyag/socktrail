// Package kernelbtf reads kernel function signatures from the running
// kernel's BTF, so each probe loads the program variant that matches them.
package kernelbtf

import (
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
)

// Params returns how many parameters the kernel function takes, or -1 when
// the kernel has no function of that name.
func Params(name string) int {
	spec, err := btf.LoadKernelSpec()
	if err != nil {
		return -1
	}
	var fn *btf.Func
	if err := spec.TypeByName(name, &fn); err != nil {
		return -1
	}
	proto, ok := fn.Type.(*btf.FuncProto)
	if !ok {
		return -1
	}
	return len(proto.Params)
}

// KeepRecvmsgVariants removes, for each named program, the variant that does
// not match the kernel: Linux 5.19 dropped the nonblock argument of the
// recvmsg functions, and a program written for one signature fails the
// verifier on the other. The variant for earlier kernels is named with an
// "_old" suffix.
func KeepRecvmsgVariants(spec *ebpf.CollectionSpec, names ...string) {
	withNonblock := Params("tcp_recvmsg") == 6
	for _, name := range names {
		if withNonblock {
			delete(spec.Programs, name)
		} else {
			delete(spec.Programs, name+"_old")
		}
	}
}
