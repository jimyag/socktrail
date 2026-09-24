package tlsprobe

//go:generate go tool bpf2go -cc clang-18 -strip llvm-strip-18 -tags linux -type event Tls openssl.bpf.c -- -D__TARGET_ARCH_x86 -I/usr/include/x86_64-linux-gnu
