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
#define OP_RETRANSMIT 5
#define OP_CONNECT_RESULT 6
#define TCP_ESTABLISHED 1
#define TCP_SYN_SENT 2
#define TCP_CLOSE 7
#define WAKEUP_BYTES (512 << 10) // Of the 4 MiB event ring; the reader drains it every 100 ms anyway.

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

struct net;
typedef struct { struct net *net; } possible_net_t;
struct sock_common {
    __be32 skc_daddr;
    __be32 skc_rcv_saddr;
    __be16 skc_dport;
    __u16 skc_num;
    unsigned short skc_family;
    possible_net_t skc_net;
    struct in6_addr skc_v6_daddr;
    struct in6_addr skc_v6_rcv_saddr;
} __attribute__((preserve_access_index));
struct sock {
    struct sock_common __sk_common;
    __u16 sk_protocol; // A plain field from Linux 5.6.
    int sk_err;
} __attribute__((preserve_access_index));
struct tcp_sock {
    __u32 srtt_us; // Smoothed RTT, shifted left by 3.
    __u32 mdev_us; // Mean deviation, shifted left by 2.
    __u32 snd_cwnd;
    __u32 total_retrans;
    __u32 data_segs_out;
} __attribute__((preserve_access_index));
struct socket { struct sock *sk; } __attribute__((preserve_access_index));
struct file { void *private_data; } __attribute__((preserve_access_index));
struct pipe_inode_info;
struct ns_common { unsigned int inum; } __attribute__((preserve_access_index));
struct net { struct ns_common ns; } __attribute__((preserve_access_index));
struct nsproxy { struct net *net_ns; } __attribute__((preserve_access_index));
struct task_struct {
    int tgid;
    struct task_struct *group_leader;
    struct task_struct *real_parent;
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
    __u64 cgroup_id;       // The cgroup v2 ID: the inode of the process's cgroup directory.
    __u64 parent_start_ns;
    __u32 pid;
    __u32 ppid;
    // TCP only: the socket's state after the call, as ss -ti shows it.
    __u32 srtt_us;
    __u32 rttvar_us;
    __u32 snd_cwnd;
    __u32 data_segs_out;
    __u32 total_retrans;
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

struct connect_start {
    __u64 start_ns;
    __u64 parent_start_ns;
    __u64 cgroup_id;
    __u64 started_at;
    __u32 pid;
    __u32 ppid;
    __u16 local_port;
    char comm[16];
};
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);
    __type(key, __u64);
    __type(value, struct connect_start);
} connecting SEC(".maps");

SEC("tp_btf/inet_sock_set_state")
int BPF_PROG(tcp_connect_result, const struct sock *sk, int oldstate, int newstate)
{
    if (!sk || (newstate != TCP_SYN_SENT && oldstate != TCP_SYN_SENT)) return 0;
    if (BPF_CORE_READ(sk, sk_protocol) != 6) return 0;
    __u32 zero = 0;
    struct config *cfg = bpf_map_lookup_elem(&settings, &zero);
    if (!cfg || !cfg->netns || BPF_CORE_READ(sk, __sk_common.skc_net.net, ns.inum) != cfg->netns) return 0;
    __u64 key = (__u64)sk;
    if (newstate == TCP_SYN_SENT) {
        struct task_struct *task = (void *)bpf_get_current_task();
        struct task_struct *parent = BPF_CORE_READ(task, real_parent);
        struct connect_start start = {};
        start.pid = bpf_get_current_pid_tgid() >> 32;
        start.start_ns = process_start(task);
        start.ppid = BPF_CORE_READ(parent, tgid);
        start.parent_start_ns = process_start(parent);
        start.cgroup_id = bpf_get_current_cgroup_id();
        start.started_at = bpf_ktime_get_ns();
        start.local_port = BPF_CORE_READ(sk, __sk_common.skc_num);
        bpf_get_current_comm(&start.comm, sizeof(start.comm));
        bpf_map_update_elem(&connecting, &key, &start, BPF_ANY);
        return 0;
    }
    if (newstate != TCP_ESTABLISHED && newstate != TCP_CLOSE) return 0;
    struct connect_start *start = bpf_map_lookup_elem(&connecting, &key);
    if (!start) return 0;
    __u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
    __u16 local_port = BPF_CORE_READ(sk, __sk_common.skc_num);
    if (!local_port) local_port = start->local_port;
    __u16 remote_port = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
    if ((family != AF_INET && family != AF_INET6) ||
        (cfg->port && cfg->port != local_port && cfg->port != remote_port)) goto done;
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        __u64 *count = bpf_map_lookup_elem(&lost, &zero);
        if (count) __sync_fetch_and_add(count, 1);
        goto done;
    }
    __builtin_memset(e, 0, sizeof(*e));
    e->pid = start->pid;
    e->start_ns = start->start_ns;
    e->ppid = start->ppid;
    e->parent_start_ns = start->parent_start_ns;
    e->cgroup_id = start->cgroup_id;
    __builtin_memcpy(e->comm, start->comm, sizeof(e->comm));
    e->netns = cfg->netns;
    e->local_port = local_port;
    e->remote_port = remote_port;
    e->protocol = 6;
    e->role = ROLE_SEND;
    e->operation = OP_CONNECT_RESULT;
    e->family = family == AF_INET ? 4 : 6;
    // These fields are operation-specific, keeping the 128-byte ring event.
    e->srtt_us = newstate == TCP_CLOSE ? BPF_CORE_READ(sk, sk_err) : 0;
    if (newstate == TCP_CLOSE && e->srtt_us == 0) e->srtt_us = 0xffffffff; // Application aborted.
    __u64 elapsed = (bpf_ktime_get_ns() - start->started_at) / 1000;
    if (elapsed == 0) elapsed = 1;
    e->app_bytes = elapsed > 0xffffffff ? 0xffffffff : elapsed;
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
    __u64 flags = bpf_ringbuf_query(&events, BPF_RB_AVAIL_DATA) >= WAKEUP_BYTES ? BPF_RB_FORCE_WAKEUP : BPF_RB_NO_WAKEUP;
    bpf_ringbuf_submit(e, flags);
done:
    bpf_map_delete_elem(&connecting, &key);
    return 0;
}

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
    // A retransmission runs in softirq or timer context on behalf of no
    // particular task: its netns comes from the socket, and it has no PID.
    __u64 netns = operation == OP_RETRANSMIT ? BPF_CORE_READ(sk, __sk_common.skc_net.net, ns.inum)
                                             : BPF_CORE_READ(task, nsproxy, net_ns, ns.inum);
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
    if (operation != OP_RETRANSMIT) {
        e->pid = bpf_get_current_pid_tgid() >> 32;
        e->start_ns = process_start(task);
        bpf_get_current_comm(&e->comm, sizeof(e->comm));
        // The parent and cgroup group processes into trees and services;
        // read here, they survive a process that exits right after.
        struct task_struct *parent = BPF_CORE_READ(task, real_parent);
        e->ppid = BPF_CORE_READ(parent, tgid);
        e->parent_start_ns = process_start(parent);
        e->cgroup_id = bpf_get_current_cgroup_id();
    }
    if (protocol == 6) {
        struct tcp_sock *tp = (void *)sk;
        e->srtt_us = BPF_CORE_READ(tp, srtt_us) >> 3;
        e->rttvar_us = BPF_CORE_READ(tp, mdev_us) >> 2;
        e->snd_cwnd = BPF_CORE_READ(tp, snd_cwnd);
        e->data_segs_out = BPF_CORE_READ(tp, data_segs_out);
        e->total_retrans = BPF_CORE_READ(tp, total_retrans);
    }
    e->netns = netns;
    e->app_bytes = app_bytes;
    e->local_port = local_port;
    e->remote_port = remote_port;
    e->protocol = protocol;
    e->role = role;
    e->operation = operation;
    e->family = family == AF_INET ? 4 : 6;

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
    // Waking the reader costs more than handling an event, and a busy host
    // makes one per socket call: wake it only once events pile up. It also
    // drains the ring on a timer.
    __u64 flags = bpf_ringbuf_query(&events, BPF_RB_AVAIL_DATA) >= WAKEUP_BYTES ? BPF_RB_FORCE_WAKEUP : BPF_RB_NO_WAKEUP;
    bpf_ringbuf_submit(e, flags);
    return 0;
}

SEC("fexit/tcp_v4_connect")
int BPF_PROG(tcp_v4_connect_exit, struct sock *sk, struct sockaddr *uaddr,
             int addr_len, int ret)
{
    if (ret == 0) {
        __u64 key = (__u64)sk;
        struct connect_start *start = bpf_map_lookup_elem(&connecting, &key);
        if (start) start->local_port = BPF_CORE_READ(sk, __sk_common.skc_num);
        output(sk, 6, ROLE_SEND, OP_CONNECT, 0, 0, AF_INET, -1);
    }
    return 0;
}

SEC("fexit/tcp_v6_connect")
int BPF_PROG(tcp_v6_connect_exit, struct sock *sk, struct sockaddr *uaddr,
             int addr_len, int ret)
{
    if (ret == 0) {
        __u64 key = (__u64)sk;
        struct connect_start *start = bpf_map_lookup_elem(&connecting, &key);
        if (start) start->local_port = BPF_CORE_READ(sk, __sk_common.skc_num);
        output(sk, 6, ROLE_SEND, OP_CONNECT, 0, 0, AF_INET6, -1);
    }
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

// Before Linux 6.5, sendfile and splice into a socket bypass tcp_sendmsg:
// they go through generic_splice_sendpage, then tcp_sendpage once per page.
// This hook fires once per pipe of pages instead. Later kernels have no such
// function and splice through tcp_sendmsg; the loader then drops the hook.
SEC("fexit/generic_splice_sendpage")
int BPF_PROG(splice_send_exit, struct pipe_inode_info *pipe, struct file *out, long long *ppos,
             unsigned long len, unsigned int flags, long ret)
{
    if (ret <= 0) return 0;
    struct socket *sock = BPF_CORE_READ(out, private_data);
    struct sock *sk = BPF_CORE_READ(sock, sk);
    __u16 protocol = sk ? BPF_CORE_READ(sk, sk_protocol) : 0;
    if (protocol == 6 || protocol == 17) output(sk, protocol, ROLE_SEND, OP_SEND, ret, 0, 0, -1);
    return 0;
}

// splice(2) out of a TCP socket, which Go uses to copy between connections,
// reads through tcp_splice_read rather than tcp_recvmsg on every kernel.
SEC("fexit/tcp_splice_read")
int BPF_PROG(splice_recv_exit, struct socket *sock, long long *ppos, struct pipe_inode_info *pipe,
             unsigned long len, unsigned int flags, long ret)
{
    if (ret > 0) output(BPF_CORE_READ(sock, sk), 6, ROLE_RECV, OP_RECV, ret, 0, 0, -1);
    return 0;
}

// Retransmissions of local sockets. Like every TCP event, the event carries
// the socket's running total, the figure ss reports as retrans, so a lost
// event costs nothing: the next one brings the count up to date. A tail
// loss probe retransmits without tcp_retransmit_skb, so it has its own
// hook. Both functions are called from other files and cannot be inlined.
SEC("fexit/tcp_retransmit_skb")
int BPF_PROG(tcp_retransmit_exit, struct sock *sk, void *skb, int segs, int ret)
{
    if (ret == 0) output(sk, 6, ROLE_SEND, OP_RETRANSMIT, 0, 0, 0, -1);
    return 0;
}

SEC("fexit/tcp_send_loss_probe")
int BPF_PROG(tcp_loss_probe_exit, struct sock *sk)
{
    output(sk, 6, ROLE_SEND, OP_RETRANSMIT, 0, 0, 0, -1);
    return 0;
}

// A socket with kernel TLS sends and receives through the tls module, not
// tcp_sendmsg and tcp_recvmsg; the loader keeps these hooks only while that
// module is loaded. They count bytes and read nothing. Before Linux 6.5,
// sendfile and splice into such a socket go through tls_sw_sendpage, which
// generic_splice_sendpage above already counts.
SEC("fexit/tls_sw_sendmsg")
int BPF_PROG(ktls_send_exit, struct sock *sk, struct msghdr *msg, unsigned long size, int ret)
{
    if (ret > 0) output(sk, 6, ROLE_SEND, OP_SEND, ret, 0, 0, -1);
    return 0;
}

SEC("fexit/tls_device_sendmsg")
int BPF_PROG(ktls_device_send_exit, struct sock *sk, struct msghdr *msg, unsigned long size, int ret)
{
    if (ret > 0) output(sk, 6, ROLE_SEND, OP_SEND, ret, 0, 0, -1);
    return 0;
}

SEC("fexit/tls_sw_recvmsg")
int BPF_PROG(ktls_recv_exit, struct sock *sk, struct msghdr *msg, unsigned long len,
             int flags, int *addr_len, int ret)
{
    if (ret > 0) output(sk, 6, ROLE_RECV, OP_RECV, ret, 0, 0, -1);
    return 0;
}

SEC("fexit/tls_sw_recvmsg")
int BPF_PROG(ktls_recv_exit_old, struct sock *sk, struct msghdr *msg, unsigned long len,
             int nonblock, int flags, int *addr_len, int ret)
{
    if (ret > 0) output(sk, 6, ROLE_RECV, OP_RECV, ret, 0, 0, -1);
    return 0;
}

SEC("fexit/tls_sw_splice_read")
int BPF_PROG(ktls_splice_recv_exit, struct socket *sock, long long *ppos, struct pipe_inode_info *pipe,
             unsigned long len, unsigned int flags, long ret)
{
    if (ret > 0) output(BPF_CORE_READ(sock, sk), 6, ROLE_RECV, OP_RECV, ret, 0, 0, -1);
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
