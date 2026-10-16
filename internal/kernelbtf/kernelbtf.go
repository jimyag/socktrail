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
	return params(spec, name)
}

// ModuleParams is Params for a function of a loaded kernel module, or of the
// kernel itself when the module is built in.
func ModuleParams(module, name string) int {
	if n := Params(name); n >= 0 {
		return n
	}
	spec, err := btf.LoadKernelModuleSpec(module)
	if err != nil {
		return -1
	}
	return params(spec, name)
}

func params(spec *btf.Spec, name string) int {
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

// recvmsgVariants maps a recvmsg function's parameter count to the program
// name suffix carrying that signature. Linux 5.19 dropped the nonblock
// argument (6 to 5) and later kernels dropped addr_len (5 to 4); a program
// written for one signature fails the verifier on another.
var recvmsgVariants = map[int]string{4: "_4", 5: "", 6: "_old"}

// KeepRecvmsgVariants keeps, for each named program, the variant whose
// parameter count matches the kernel function the program attaches to, and
// removes the others. paramCount resolves a function name against the kernel
// or the module that defines it; a missing function leaves no variant loaded.
func KeepRecvmsgVariants(spec *ebpf.CollectionSpec, paramCount func(name string) int, names ...string) {
	for _, name := range names {
		want := paramCount(attachTo(spec, name))
		for arity, suffix := range recvmsgVariants {
			if arity != want {
				delete(spec.Programs, name+suffix)
			}
		}
	}
}

// attachTo returns the kernel function the named program attaches to,
// whichever signature variant still carries it.
func attachTo(spec *ebpf.CollectionSpec, name string) string {
	for _, suffix := range recvmsgVariants {
		if program := spec.Programs[name+suffix]; program != nil {
			return program.AttachTo
		}
	}
	return ""
}
