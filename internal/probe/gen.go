package probe

//go:generate go tool bpf2go -cc clang-18 -strip llvm-strip-18 -tags linux -type event -type tcp_metric_event Bpf pid.bpf.c -- -I/usr/include/x86_64-linux-gnu
