//go:build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual MIT/GPL";

#define AF_INET 2
#define AF_INET6 10
#define S_IFMT 0170000
#define S_IFSOCK 0140000
#define SSL_CTRL_SET_TLSEXT_HOSTNAME 55

// The uprobe register context, as bpf_tracing.h reads it on each
// architecture this object is built for.
#if defined(__TARGET_ARCH_arm64)
struct pt_regs;
struct user_pt_regs {
    __u64 regs[31];
    __u64 sp;
    __u64 pc;
    __u64 pstate;
};
#else
struct pt_regs {
    unsigned long r15, r14, r13, r12, bp, bx;
    unsigned long r11, r10, r9, r8, rax, rcx, rdx, rsi, rdi;
    unsigned long orig_ax, ip, cs, flags, sp, ss;
};
#endif

struct in6_addr {
    union { __u8 u6_addr8[16]; } in6_u;
} __attribute__((preserve_access_index));
struct sock_common {
    __be32 skc_daddr;
    __be32 skc_rcv_saddr;
    __be16 skc_dport;
    __u16 skc_num;
    unsigned short skc_family;
    struct in6_addr skc_v6_daddr;
    struct in6_addr skc_v6_rcv_saddr;
} __attribute__((preserve_access_index));
struct sock { struct sock_common __sk_common; } __attribute__((preserve_access_index));
struct socket { struct sock *sk; } __attribute__((preserve_access_index));
struct inode { unsigned short i_mode; } __attribute__((preserve_access_index));
struct file {
    struct inode *f_inode;
    void *private_data;
} __attribute__((preserve_access_index));
struct fdtable {
    unsigned int max_fds;
    struct file **fd;
} __attribute__((preserve_access_index));
struct files_struct { struct fdtable *fdt; } __attribute__((preserve_access_index));
struct ns_common { unsigned int inum; } __attribute__((preserve_access_index));
struct net { struct ns_common ns; } __attribute__((preserve_access_index));
struct nsproxy { struct net *net_ns; } __attribute__((preserve_access_index));
struct task_struct {
    struct task_struct *group_leader;
    __u64 start_boottime;
    struct nsproxy *nsproxy;
    struct files_struct *files;
} __attribute__((preserve_access_index));
struct task_struct___old { __u64 real_start_time; } __attribute__((preserve_access_index));

// process_start is the start time /proc reports, which keeps counting across
// suspend: start_boottime from Linux 5.5, real_start_time before it.
static __always_inline __u64 process_start(struct task_struct *task)
{
    struct task_struct *leader = BPF_CORE_READ(task, group_leader);
    if (bpf_core_field_exists(leader->start_boottime))
        return BPF_CORE_READ(leader, start_boottime);
    return BPF_CORE_READ((struct task_struct___old *)leader, real_start_time);
}

// Every byte participates in BPF map key comparisons. Explicitly account for
// alignment so uninitialized padding cannot split one SSL into two keys.
struct ssl_key { __u64 ssl; __u32 pid; __u32 reserved; };
struct bio_key { __u64 bio; __u32 pid; __u32 reserved; };
// Map values are also written whole from the stack, and verifiers before
// Linux 6.x reject uninitialized padding there too.
struct ssl_state { __s32 fd; __u8 source; char hostname[256]; __u8 reserved[3]; };
struct call { __u64 ssl; __u64 arg; __s32 fd; __u32 reserved; };
struct active_connect { struct ssl_key key; __u8 emitted; __u8 reserved[7]; };
struct event {
    __u64 start_ns;
    __u64 netns;
    __u32 pid;
    __u16 local_port;
    __u16 remote_port;
    __u8 family;
    __u8 source;
    __u8 local_ip[16];
    __u8 remote_ip[16];
    char hostname[256];
    char comm[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);
    __type(key, struct ssl_key);
    __type(value, struct ssl_state);
} ssl_states SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, __u64);
    __type(value, struct call);
} calls SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, __u64);
    __type(value, struct active_connect);
} active_connects SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, __u64);
    __type(value, __s32);
} bio_calls SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);
    __type(key, struct bio_key);
    __type(value, __s32);
} bio_fds SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
    __type(value, struct event);
} events SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} target_netns SEC(".maps");

static __always_inline int in_scope(void)
{
    __u32 zero = 0;
    __u64 *wanted = bpf_map_lookup_elem(&target_netns, &zero);
    if (!wanted) return 0;
    struct task_struct *task = (void *)bpf_get_current_task(); // The _btf variant needs Linux 5.11.
    return BPF_CORE_READ(task, nsproxy, net_ns, ns.inum) == *wanted;
}

static __always_inline struct ssl_state *get_state(struct ssl_key *key)
{
    struct ssl_state *state = bpf_map_lookup_elem(&ssl_states, key);
    if (state) return state;
    struct ssl_state empty = {.fd = -1};
    bpf_map_update_elem(&ssl_states, key, &empty, BPF_NOEXIST);
    return bpf_map_lookup_elem(&ssl_states, key);
}

static __always_inline int emit_sock(struct ssl_key *key, struct ssl_state *state,
                                    struct sock *sk, __u64 netns)
{
    if (!state || !sk || state->hostname[0] == 0) return 0;
    struct task_struct *task = (void *)bpf_get_current_task(); // The _btf variant needs Linux 5.11.
    __u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
    if (family != AF_INET && family != AF_INET6) return 0;
    __u16 local_port = BPF_CORE_READ(sk, __sk_common.skc_num);
    __u16 remote_port = __builtin_bswap16(BPF_CORE_READ(sk, __sk_common.skc_dport));
    if (!local_port || !remote_port) return 0;

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;
    __builtin_memset(e, 0, sizeof(*e));
    e->pid = key->pid;
    e->start_ns = process_start(task);
    e->netns = netns;
    e->family = family == AF_INET ? 4 : 6;
    e->local_port = local_port;
    e->remote_port = remote_port;
    e->source = state->source;
    if (family == AF_INET) {
        __be32 local = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
        __be32 remote = BPF_CORE_READ(sk, __sk_common.skc_daddr);
        __builtin_memcpy(e->local_ip, &local, 4);
        __builtin_memcpy(e->remote_ip, &remote, 4);
    } else {
        struct in6_addr local = {}, remote = {};
        BPF_CORE_READ_INTO(&local, sk, __sk_common.skc_v6_rcv_saddr);
        BPF_CORE_READ_INTO(&remote, sk, __sk_common.skc_v6_daddr);
        __builtin_memcpy(e->local_ip, local.in6_u.u6_addr8, 16);
        __builtin_memcpy(e->remote_ip, remote.in6_u.u6_addr8, 16);
    }
    __builtin_memcpy(e->hostname, state->hostname, sizeof(e->hostname));
    bpf_get_current_comm(e->comm, sizeof(e->comm));
    bpf_ringbuf_submit(e, 0);
    return 1;
}

static __always_inline int emit(struct ssl_key *key, struct ssl_state *state)
{
    if (!state || state->fd < 0 || state->hostname[0] == 0) return 0;
    __u32 zero = 0;
    __u64 *wanted = bpf_map_lookup_elem(&target_netns, &zero);
    if (!wanted) return 0;
    struct task_struct *task = (void *)bpf_get_current_task(); // The _btf variant needs Linux 5.11.
    __u64 netns = BPF_CORE_READ(task, nsproxy, net_ns, ns.inum);
    if (netns != *wanted) return 0;

    struct fdtable *fdt = BPF_CORE_READ(task, files, fdt);
    if (!fdt || (__u32)state->fd >= BPF_CORE_READ(fdt, max_fds)) return 0;
    struct file **fd_array = BPF_CORE_READ(fdt, fd);
    struct file *file = 0;
    if (!fd_array || bpf_probe_read_kernel(&file, sizeof(file), fd_array + state->fd) || !file) return 0;
    unsigned short mode = BPF_CORE_READ(file, f_inode, i_mode);
    if ((mode & S_IFMT) != S_IFSOCK) return 0;
    struct socket *socket = BPF_CORE_READ(file, private_data);
    if (!socket) return 0;
    return emit_sock(key, state, BPF_CORE_READ(socket, sk), netns);
}

SEC("uprobe/SSL_set_fd")
int set_fd_enter(struct pt_regs *ctx)
{
    if (!in_scope()) return 0;
    __u64 tid = bpf_get_current_pid_tgid();
    struct call call = {.ssl = PT_REGS_PARM1(ctx), .fd = (__s32)PT_REGS_PARM2(ctx)};
    bpf_map_update_elem(&calls, &tid, &call, BPF_ANY);
    return 0;
}

SEC("uprobe/BIO_new_socket")
int bio_new_socket_enter(struct pt_regs *ctx)
{
    if (!in_scope()) return 0;
    __u64 tid = bpf_get_current_pid_tgid();
    __s32 fd = (__s32)PT_REGS_PARM1(ctx);
    bpf_map_update_elem(&bio_calls, &tid, &fd, BPF_ANY);
    return 0;
}

SEC("uretprobe/BIO_new_socket")
int bio_new_socket_return(struct pt_regs *ctx)
{
    if (!in_scope()) return 0;
    __u64 tid = bpf_get_current_pid_tgid();
    __s32 *fd = bpf_map_lookup_elem(&bio_calls, &tid);
    if (fd && *fd >= 0 && PT_REGS_RC(ctx)) {
        struct bio_key key = {.pid = tid >> 32, .bio = PT_REGS_RC(ctx)};
        bpf_map_update_elem(&bio_fds, &key, fd, BPF_ANY);
    }
    bpf_map_delete_elem(&bio_calls, &tid);
    return 0;
}

static __always_inline int set_bio_fd(__u64 ssl, __u64 bio)
{
    __u64 tid = bpf_get_current_pid_tgid();
    struct bio_key bio_key = {.pid = tid >> 32, .bio = bio};
    __s32 *fd = bpf_map_lookup_elem(&bio_fds, &bio_key);
    if (!fd) return 0;
    struct ssl_key key = {.pid = tid >> 32, .ssl = ssl};
    struct ssl_state *state = get_state(&key);
    if (state) state->fd = *fd;
    return 0;
}

SEC("uprobe/SSL_set0_rbio")
int set0_rbio_enter(struct pt_regs *ctx)
{
    if (!in_scope()) return 0;
    return set_bio_fd(PT_REGS_PARM1(ctx), PT_REGS_PARM2(ctx));
}

SEC("uprobe/SSL_set_bio")
int set_bio_enter(struct pt_regs *ctx)
{
    if (!in_scope()) return 0;
    return set_bio_fd(PT_REGS_PARM1(ctx), PT_REGS_PARM2(ctx));
}

SEC("uprobe/BIO_free")
int bio_free_enter(struct pt_regs *ctx)
{
    if (!in_scope()) return 0;
    __u64 tid = bpf_get_current_pid_tgid();
    struct bio_key key = {.pid = tid >> 32, .bio = PT_REGS_PARM1(ctx)};
    bpf_map_delete_elem(&bio_fds, &key);
    return 0;
}

SEC("uretprobe/SSL_set_fd")
int set_fd_return(struct pt_regs *ctx)
{
    if (!in_scope()) return 0;
    __u64 tid = bpf_get_current_pid_tgid();
    struct call *call = bpf_map_lookup_elem(&calls, &tid);
    if (call && PT_REGS_RC(ctx) == 1 && call->fd >= 0) {
        struct ssl_key key = {.pid = tid >> 32, .ssl = call->ssl};
        struct ssl_state *state = get_state(&key);
        if (state) state->fd = call->fd;
    }
    bpf_map_delete_elem(&calls, &tid);
    return 0;
}

SEC("uprobe/SSL_ctrl")
int ctrl_enter(struct pt_regs *ctx)
{
    if (!in_scope()) return 0;
    if ((__s32)PT_REGS_PARM2(ctx) != SSL_CTRL_SET_TLSEXT_HOSTNAME) return 0;
    __u64 tid = bpf_get_current_pid_tgid();
    struct call call = {.ssl = PT_REGS_PARM1(ctx), .arg = PT_REGS_PARM4(ctx)};
    bpf_map_update_elem(&calls, &tid, &call, BPF_ANY);
    return 0;
}

SEC("uretprobe/SSL_ctrl")
int ctrl_return(struct pt_regs *ctx)
{
    if (!in_scope()) return 0;
    __u64 tid = bpf_get_current_pid_tgid();
    struct call *call = bpf_map_lookup_elem(&calls, &tid);
    if (call && PT_REGS_RC(ctx) > 0 && call->arg) {
        struct ssl_key key = {.pid = tid >> 32, .ssl = call->ssl};
        struct ssl_state *state = get_state(&key);
        if (state && bpf_probe_read_user_str(state->hostname, sizeof(state->hostname), (void *)call->arg) > 1)
            state->source = 1;
    }
    bpf_map_delete_elem(&calls, &tid);
    return 0;
}

SEC("uprobe/SSL_get_servername")
int get_servername_enter(struct pt_regs *ctx)
{
    if (!in_scope()) return 0;
    __u64 tid = bpf_get_current_pid_tgid();
    struct call call = {.ssl = PT_REGS_PARM1(ctx)};
    bpf_map_update_elem(&calls, &tid, &call, BPF_ANY);
    return 0;
}

SEC("uretprobe/SSL_get_servername")
int get_servername_return(struct pt_regs *ctx)
{
    if (!in_scope()) return 0;
    __u64 tid = bpf_get_current_pid_tgid();
    struct call *call = bpf_map_lookup_elem(&calls, &tid);
    if (call && PT_REGS_RC(ctx)) {
        struct ssl_key key = {.pid = tid >> 32, .ssl = call->ssl};
        struct ssl_state *state = get_state(&key);
        if (state && bpf_probe_read_user_str(state->hostname, sizeof(state->hostname), (void *)PT_REGS_RC(ctx)) > 1) {
            state->source = 2;
            emit(&key, state);
        }
    }
    bpf_map_delete_elem(&calls, &tid);
    return 0;
}

SEC("uprobe/SSL_connect")
int connect_enter(struct pt_regs *ctx)
{
    if (!in_scope()) return 0;
    __u64 tid = bpf_get_current_pid_tgid();
    struct ssl_key key = {.pid = tid >> 32, .ssl = PT_REGS_PARM1(ctx)};
    emit(&key, bpf_map_lookup_elem(&ssl_states, &key));
    struct active_connect active = {.key = key};
    bpf_map_update_elem(&active_connects, &tid, &active, BPF_ANY);
    return 0;
}

// A custom BIO may hide its fd from OpenSSL. While SSL_connect runs, the
// thread's TCP send identifies the actual socket used for the ClientHello.
SEC("fentry/tcp_sendmsg")
int BPF_PROG(connect_tcp_send, struct sock *sk, void *msg, unsigned long size)
{
    __u64 tid = bpf_get_current_pid_tgid();
    struct active_connect *active = bpf_map_lookup_elem(&active_connects, &tid);
    if (!active || active->emitted) return 0;
    struct ssl_state *state = bpf_map_lookup_elem(&ssl_states, &active->key);
    if (!state || state->fd >= 0 || state->hostname[0] == 0) return 0;
    __u32 zero = 0;
    __u64 *wanted = bpf_map_lookup_elem(&target_netns, &zero);
    if (!wanted) return 0;
    struct task_struct *task = (void *)bpf_get_current_task(); // The _btf variant needs Linux 5.11.
    __u64 netns = BPF_CORE_READ(task, nsproxy, net_ns, ns.inum);
    if (netns != *wanted) return 0;
    if (emit_sock(&active->key, state, sk, netns)) active->emitted = 1;
    return 0;
}

SEC("uretprobe/SSL_connect")
int connect_return(struct pt_regs *ctx)
{
    __u64 tid = bpf_get_current_pid_tgid();
    bpf_map_delete_elem(&active_connects, &tid);
    return 0;
}

SEC("uprobe/SSL_do_handshake")
int handshake_enter(struct pt_regs *ctx)
{
    if (!in_scope()) return 0;
    __u64 tid = bpf_get_current_pid_tgid();
    struct ssl_key key = {.pid = tid >> 32, .ssl = PT_REGS_PARM1(ctx)};
    emit(&key, bpf_map_lookup_elem(&ssl_states, &key));
    return 0;
}

SEC("uprobe/SSL_free")
int free_enter(struct pt_regs *ctx)
{
    if (!in_scope()) return 0;
    __u64 tid = bpf_get_current_pid_tgid();
    struct ssl_key key = {.pid = tid >> 32, .ssl = PT_REGS_PARM1(ctx)};
    bpf_map_delete_elem(&ssl_states, &key);
    return 0;
}
