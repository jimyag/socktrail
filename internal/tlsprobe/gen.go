package tlsprobe

// Uprobes read function arguments from registers, so the object is built per
// architecture; bpf2go defines __TARGET_ARCH_* for each target.
//go:generate go tool bpf2go -cc clang-18 -strip llvm-strip-18 -tags linux -target amd64,arm64 -type event Tls openssl.bpf.c -- -I/usr/include/x86_64-linux-gnu
