//go:build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>
#include <stdbool.h>

char LICENSE[] SEC("license") = "Dual MIT/GPL";

#define AF_INET 2
#define AF_INET6 10
#define ROLE_SEND 1
#define ROLE_RECV 2
#define OP_CONNECT 1
#define OP_ACCEPT 2
#define OP_SEND 3
#define OP_RECV 4

struct in_addr { __be32 s_addr; } __attribute__((preserve_access_index));
struct in6_addr {
    union { __u8 u6_addr8[16]; } in6_u;
} __attribute__((preserve_access_index));
struct sockaddr_in {
    unsigned short sin_family;
    __be16 sin_port;
    struct in_addr sin_addr;
} __attribute__((preserve_access_index));
struct sockaddr_in6 {
    unsigned short sin6_family;
    __be16 sin6_port;
    __u32 sin6_flowinfo;
    struct in6_addr sin6_addr;
} __attribute__((preserve_access_index));
struct sockaddr { unsigned short sa_family; } __attribute__((preserve_access_index));
struct iovec { void *iov_base; unsigned long iov_len; };
enum iter_type { ITER_UBUF, ITER_IOVEC };
struct iov_iter {
    __u8 iter_type;
    unsigned long iov_offset;
    union {
        const struct iovec *__iov;
        void *ubuf;
    };
} __attribute__((preserve_access_index));
struct iov_iter___old { const struct iovec *iov; } __attribute__((preserve_access_index));
// Before Linux 5.14 the iterator type is a bit set that also holds the
// transfer direction.
struct iov_iter___v5 { unsigned int type; } __attribute__((preserve_access_index));
struct msghdr {
    void *msg_name;
    struct iov_iter msg_iter;
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
struct ns_common { unsigned int inum; } __attribute__((preserve_access_index));
struct net { struct ns_common ns; } __attribute__((preserve_access_index));
struct nsproxy { struct net *net_ns; } __attribute__((preserve_access_index));
struct task_struct {
    struct task_struct *group_leader;
    __u64 start_boottime;
    struct nsproxy *nsproxy;
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

struct config {
    __u64 netns;
    __u16 port;
};
struct event {
    __u64 start_ns;
    __u64 netns;
    __u64 app_bytes;
    __u32 pid;
    __u16 local_port;
    __u16 remote_port;
    __u8 protocol;
    __u8 role;
    __u8 family;
    __u8 operation;
    __u8 local_ip[16];
    __u8 remote_ip[16];
    char comm[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct config);
} settings SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} lost SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 22);
    __type(value, struct event);
} events SEC(".maps");

// local_port overrides the socket's port when non-negative: an ICMP echo
// flow is keyed by its identifier instead.
static __always_inline int output(struct sock *sk, __u8 protocol, __u8 role,
                                  __u8 operation, __u64 app_bytes,
                                  void *remote_override, __u8 family_hint,
                                  __s32 local_port_override)
{
    __u32 zero = 0;
    struct config *cfg = bpf_map_lookup_elem(&settings, &zero);
    if (!cfg || !cfg->netns) return 0;

    // Not bpf_get_current_task_btf, which needs Linux 5.11.
    struct task_struct *task = (void *)bpf_get_current_task();
    __u64 netns = BPF_CORE_READ(task, nsproxy, net_ns, ns.inum);
    if (netns != cfg->netns) return 0;

    __u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
    if (family_hint && family != family_hint) return 0;
    if (family != AF_INET && family != AF_INET6) return 0;

    __u16 local_port = BPF_CORE_READ(sk, __sk_common.skc_num);
    if (local_port_override >= 0) local_port = local_port_override;
    __u16 remote_port = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
    if (remote_override) {
        if (family == AF_INET) {
            remote_port = bpf_ntohs(BPF_CORE_READ((struct sockaddr_in *)remote_override, sin_port));
        } else {
            remote_port = bpf_ntohs(BPF_CORE_READ((struct sockaddr_in6 *)remote_override, sin6_port));
        }
    }
    // Application I/O belongs to the whole netns PID view. A UDP recvfrom
    // may not expose a peer port at this hook, so do not apply a wire-flow
    // port filter to I/O events.
    if (cfg->port && operation != OP_SEND && operation != OP_RECV &&
        cfg->port != local_port && cfg->port != remote_port) return 0;

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        __u64 *count = bpf_map_lookup_elem(&lost, &zero);
        if (count) __sync_fetch_and_add(count, 1);
        return 0;
    }
    __builtin_memset(e, 0, sizeof(*e));
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->start_ns = process_start(task);
    e->netns = netns;
    e->app_bytes = app_bytes;
    e->local_port = local_port;
    e->remote_port = remote_port;
    e->protocol = protocol;
    e->role = role;
    e->operation = operation;
    e->family = family == AF_INET ? 4 : 6;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    if (family == AF_INET) {
        __be32 local = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
        __be32 remote;
        if (remote_override)
            remote = BPF_CORE_READ((struct sockaddr_in *)remote_override, sin_addr.s_addr);
        else
            remote = BPF_CORE_READ(sk, __sk_common.skc_daddr);
        __builtin_memcpy(e->local_ip, &local, 4);
        __builtin_memcpy(e->remote_ip, &remote, 4);
    } else {
        struct in6_addr local6 = {};
        struct in6_addr remote6 = {};
        BPF_CORE_READ_INTO(&local6, sk, __sk_common.skc_v6_rcv_saddr);
        if (remote_override)
            BPF_CORE_READ_INTO(&remote6, (struct sockaddr_in6 *)remote_override, sin6_addr);
        else
            BPF_CORE_READ_INTO(&remote6, sk, __sk_common.skc_v6_daddr);
        __builtin_memcpy(e->local_ip, local6.in6_u.u6_addr8, 16);
        __builtin_memcpy(e->remote_ip, remote6.in6_u.u6_addr8, 16);
    }
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("fexit/tcp_v4_connect")
int BPF_PROG(tcp_v4_connect_exit, struct sock *sk, struct sockaddr *uaddr,
             int addr_len, int ret)
{
    if (ret == 0) output(sk, 6, ROLE_SEND, OP_CONNECT, 0, 0, AF_INET, -1);
    return 0;
}

SEC("fexit/tcp_v6_connect")
int BPF_PROG(tcp_v6_connect_exit, struct sock *sk, struct sockaddr *uaddr,
             int addr_len, int ret)
{
    if (ret == 0) output(sk, 6, ROLE_SEND, OP_CONNECT, 0, 0, AF_INET6, -1);
    return 0;
}

// Kernels before 6.8. An accept already waiting for a connection when this
// probe attaches returns without passing through it.
SEC("fexit/inet_csk_accept")
int BPF_PROG(tcp_accept_exit, struct sock *sk, int flags, int *err,
             bool kern, struct sock *ret)
{
    if (ret) output(ret, 6, ROLE_RECV, OP_ACCEPT, 0, 0, 0, -1);
    return 0;
}

// From 6.8 every TCP accept finishes in __inet_accept, called after the wait
// for a connection, so a server blocked in accept() is seen as well.
SEC("fentry/__inet_accept")
int BPF_PROG(inet_accept_entry, struct socket *sock, struct socket *newsock,
             struct sock *newsk)
{
    output(newsk, 6, ROLE_RECV, OP_ACCEPT, 0, 0, 0, -1);
    return 0;
}

SEC("fexit/tcp_sendmsg")
int BPF_PROG(tcp_send_exit, struct sock *sk, struct msghdr *msg,
             unsigned long size, int ret)
{
    if (ret > 0) output(sk, 6, ROLE_SEND, OP_SEND, ret, 0, 0, -1);
    return 0;
}

// The recvmsg functions lost their nonblock argument in Linux 5.19. Each has
// a *_old twin for earlier kernels; the loader keeps the one that matches.
SEC("fexit/tcp_recvmsg")
int BPF_PROG(tcp_recv_exit, struct sock *sk, struct msghdr *msg,
             unsigned long len, int flags, int *addr_len, int ret)
{
    if (ret > 0) output(sk, 6, ROLE_RECV, OP_RECV, ret, 0, 0, -1);
    return 0;
}

SEC("fexit/tcp_recvmsg")
int BPF_PROG(tcp_recv_exit_old, struct sock *sk, struct msghdr *msg,
             unsigned long len, int nonblock, int flags, int *addr_len, int ret)
{
    if (ret > 0) output(sk, 6, ROLE_RECV, OP_RECV, ret, 0, 0, -1);
    return 0;
}

SEC("fexit/udp_sendmsg")
int BPF_PROG(udp_send_exit, struct sock *sk, struct msghdr *msg,
             unsigned long len, int ret)
{
    if (ret > 0) {
        void *name = BPF_CORE_READ(msg, msg_name);
        output(sk, 17, ROLE_SEND, OP_SEND, ret, name, AF_INET, -1);
    }
    return 0;
}

SEC("fexit/udpv6_sendmsg")
int BPF_PROG(udpv6_send_exit, struct sock *sk, struct msghdr *msg,
             unsigned long len, int ret)
{
    if (ret > 0) {
        void *name = BPF_CORE_READ(msg, msg_name);
        output(sk, 17, ROLE_SEND, OP_SEND, ret, name, AF_INET6, -1);
    }
    return 0;
}

static __always_inline void udp_received(struct sock *sk, struct msghdr *msg, int ret, __u8 family)
{
    if (ret > 0) output(sk, 17, ROLE_RECV, OP_RECV, ret, BPF_CORE_READ(msg, msg_name), family, -1);
}

SEC("fexit/udp_recvmsg")
int BPF_PROG(udp_recv_exit, struct sock *sk, struct msghdr *msg,
             unsigned long len, int flags, int *addr_len, int ret)
{
    udp_received(sk, msg, ret, AF_INET);
    return 0;
}

SEC("fexit/udp_recvmsg")
int BPF_PROG(udp_recv_exit_old, struct sock *sk, struct msghdr *msg,
             unsigned long len, int nonblock, int flags, int *addr_len, int ret)
{
    udp_received(sk, msg, ret, AF_INET);
    return 0;
}

SEC("fexit/udpv6_recvmsg")
int BPF_PROG(udpv6_recv_exit, struct sock *sk, struct msghdr *msg,
             unsigned long len, int flags, int *addr_len, int ret)
{
    udp_received(sk, msg, ret, AF_INET6);
    return 0;
}

SEC("fexit/udpv6_recvmsg")
int BPF_PROG(udpv6_recv_exit_old, struct sock *sk, struct msghdr *msg,
             unsigned long len, int nonblock, int flags, int *addr_len, int ret)
{
    udp_received(sk, msg, ret, AF_INET6);
    return 0;
}

// first_bytes copies the start of the caller's buffer before the kernel
// consumes it. Only user buffers qualify: a plain one, or an iovec array.
static __always_inline int first_bytes(struct msghdr *msg, void *dst, __u32 size)
{
    __u64 offset = BPF_CORE_READ(msg, msg_iter.iov_offset);
    bool iovec;
    if (bpf_core_field_exists(msg->msg_iter.iter_type)) {
        __u8 type = BPF_CORE_READ(msg, msg_iter.iter_type);
        if (bpf_core_enum_value_exists(enum iter_type, ITER_UBUF) &&
            type == bpf_core_enum_value(enum iter_type, ITER_UBUF))
            return bpf_probe_read_user(dst, size, BPF_CORE_READ(msg, msg_iter.ubuf) + offset);
        iovec = type == bpf_core_enum_value(enum iter_type, ITER_IOVEC);
    } else {
        iovec = BPF_CORE_READ((struct iov_iter___v5 *)&msg->msg_iter, type) &
                bpf_core_enum_value(enum iter_type, ITER_IOVEC);
    }
    if (!iovec) return -1;
    const struct iovec *iov;
    if (bpf_core_field_exists(msg->msg_iter.__iov))
        iov = BPF_CORE_READ(msg, msg_iter.__iov);
    else
        iov = BPF_CORE_READ((struct iov_iter___old *)&msg->msg_iter, iov);
    struct iovec first = {};
    if (bpf_probe_read_kernel(&first, sizeof(first), iov)) return -1;
    return bpf_probe_read_user(dst, size, first.iov_base + offset);
}

// A local ping: an ICMP echo request from a raw socket, whose identifier is in
// the message, or from a ping socket, whose identifier is its local port. The
// identifier stands in for the port so the echo flow finds its process.
static __always_inline void echo_request(struct sock *sk, struct msghdr *msg, __u8 protocol,
                                         __u8 family, bool ping_socket)
{
    __u8 header[8] = {}; // Type, code, checksum, identifier, sequence.
    if (first_bytes(msg, header, sizeof(header))) return;
    if (header[0] != (protocol == 1 ? 8 : 128)) return;
    __s32 id = ping_socket ? BPF_CORE_READ(sk, __sk_common.skc_num) : header[4] << 8 | header[5];
    output(sk, protocol, ROLE_SEND, OP_SEND, 0, BPF_CORE_READ(msg, msg_name), family, id);
}

// A raw socket keeps its IP protocol where other sockets keep the port.
SEC("fentry/raw_sendmsg")
int BPF_PROG(raw_send_enter, struct sock *sk, struct msghdr *msg, unsigned long len)
{
    if (BPF_CORE_READ(sk, __sk_common.skc_num) == 1) echo_request(sk, msg, 1, AF_INET, false);
    return 0;
}

SEC("fentry/rawv6_sendmsg")
int BPF_PROG(rawv6_send_enter, struct sock *sk, struct msghdr *msg, unsigned long len)
{
    if (BPF_CORE_READ(sk, __sk_common.skc_num) == 58) echo_request(sk, msg, 58, AF_INET6, false);
    return 0;
}

SEC("fentry/ping_v4_sendmsg")
int BPF_PROG(ping_send_enter, struct sock *sk, struct msghdr *msg, unsigned long len)
{
    echo_request(sk, msg, 1, AF_INET, true);
    return 0;
}

SEC("fentry/ping_v6_sendmsg")
int BPF_PROG(ping6_send_enter, struct sock *sk, struct msghdr *msg, unsigned long len)
{
    echo_request(sk, msg, 58, AF_INET6, true);
    return 0;
}
