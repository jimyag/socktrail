package dropprobe

//go:generate go tool bpf2go -cc clang-18 -strip llvm-strip-18 -tags linux -type drop_key Drop drop.bpf.c -- -I/usr/include/x86_64-linux-gnu
