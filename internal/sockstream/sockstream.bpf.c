//go:build ignore

// Socket-layer stream capture: the first bytes each local TCP socket sends
// and receives, read from the application's buffer around tcp_sendmsg and
// tcp_recvmsg. The bytes are what the connection carries on the wire, but
// whole and in order, independent of TCP segmentation, offloads and the
// capture interface. TLS payload is already encrypted at this layer.
// UDP sockets contribute the QUIC long-header datagrams they send, whose
// client Initial carries the ClientHello.

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>
#include <stdbool.h>

char LICENSE[] SEC("license") = "Dual MIT/GPL";

#define AF_INET 2
#define AF_INET6 10
#define MSG_PEEK 2
#define CHUNK_SIZE 4096
// Enough for a ClientHello with a post-quantum key share, an HTTP request
// header or a proxy handshake followed by the tunnelled ClientHello.
#define STREAM_BUDGET (16 * 1024)
#define MAX_PIECES 8
#define MAX_IOVECS 4
#define DIR_SENT 1
#define DIR_RECEIVED 2

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
struct iovec { void *iov_base; unsigned long iov_len; };
enum iter_type { ITER_UBUF, ITER_IOVEC };
struct iov_iter {
    __u8 iter_type;
    unsigned long iov_offset;
    union {
        const struct iovec *__iov;
        void *ubuf;
    };
    unsigned long nr_segs;
} __attribute__((preserve_access_index));
struct iov_iter___old { const struct iovec *iov; } __attribute__((preserve_access_index));
// Before Linux 5.14 the iterator type is a bit set that also holds the
// transfer direction.
struct iov_iter___v5 { unsigned int type; } __attribute__((preserve_access_index));
struct msghdr {
    void *msg_name;
    struct iov_iter msg_iter;
} __attribute__((preserve_access_index));
// sockaddr_in and sockaddr_in6 overlaid: the address follows the port in
// the first, and a 4-byte flow label in the second.
struct destination {
    __u16 family;
    __be16 port;
    union {
        __be32 v4;
        struct {
            __u32 flowinfo;
            __u8 v6[16];
        };
    };
};
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
struct stream_key {
    __u64 cookie;
    __u32 direction;
    __u32 reserved; // Explicit so map keys never contain uninitialized padding.
};
struct call {
    __u64 cookie;
    __u64 base;
    __u64 nr_segs;
    __u64 offset;
    __u32 direction;
    __u32 ubuf;
    __u8 remote_ip[16]; // A sendto destination, which an unconnected socket lacks.
    __u16 remote_port;
    __u8 has_remote;
    __u8 protocol;
    __u32 reserved; // Explicit: older verifiers reject map writes of uninitialized padding.
};
struct chunk_header {
    __u64 cookie;
    __u64 start_ns;
    __u64 netns;
    __u32 pid;
    __u32 offset;
    __u16 len;
    __u16 local_port;
    __u16 remote_port;
    __u8 direction;
    __u8 family;
    __u8 local_ip[16];
    __u8 remote_ip[16];
    char comm[16];
    __u8 protocol;
};
// finish's loop position, kept in map memory: the verifier does not track
// values there, so every branch meets at the loop head in one state. Kernels
// before 6.x otherwise walk each combination of branches and reject the
// program as too large.
struct cursor {
    __u64 sent;
    __u64 offset;
    __u64 segment;
};
struct chunk {
    struct chunk_header h;
    __u8 data[CHUNK_SIZE];
    struct cursor cur; // Scratch only; never sent.
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 128);
    __type(key, __u64);
    __type(value, struct config);
} settings SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} lost SEC(".maps");
// Bytes already captured per socket direction. A socket past its budget
// costs a single map lookup per call and nothing more.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct stream_key);
    __type(value, __u32);
} captured SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, __u64);
    __type(value, struct call);
} calls SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct chunk);
} scratch SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 22);
} chunks SEC(".maps");

// Set by the loader. Tracing programs may call bpf_get_socket_cookie from
// Linux 5.12; before that the socket's address stands in for the cookie, and
// socket_freed forgets it so a later socket at that address starts afresh.
// The verifier drops the branch not taken, helper call included.
const volatile bool has_socket_cookie = true;

static __always_inline __u64 socket_id(struct sock *sk)
{
    if (has_socket_cookie) return bpf_get_socket_cookie(sk);
    return (__u64)sk;
}

// begin records where the caller's buffer starts before the kernel consumes
// or fills it. Kernel-internal buffers (kvec, bvec) are not application data.
static __always_inline int begin(struct sock *sk, struct msghdr *msg, __u32 direction, __u8 protocol)
{
    struct task_struct *task = (void *)bpf_get_current_task(); // The _btf variant needs Linux 5.11.
    __u64 netns = BPF_CORE_READ(task, nsproxy, net_ns, ns.inum);
    struct config *cfg = bpf_map_lookup_elem(&settings, &netns);
    if (!cfg) return 0;
    __u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
    if (family != AF_INET && family != AF_INET6) return 0;

    struct stream_key key = {.cookie = socket_id(sk), .direction = direction};
    __u32 *done = bpf_map_lookup_elem(&captured, &key);
    if (done && *done >= STREAM_BUDGET) return 0;

    struct call call = {.cookie = key.cookie, .direction = direction, .protocol = protocol};
    call.remote_port = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
    void *name = protocol == 17 ? BPF_CORE_READ(msg, msg_name) : 0;
    struct destination to = {};
    if (name && !bpf_probe_read_kernel(&to, sizeof(to), name)) {
        if (to.family == AF_INET && family == AF_INET) {
            __builtin_memcpy(call.remote_ip, &to.v4, 4);
        } else if (to.family == AF_INET) { // IPv4 from a dual-stack socket, as a mapped address.
            call.remote_ip[10] = call.remote_ip[11] = 0xff;
            __builtin_memcpy(call.remote_ip + 12, &to.v4, 4);
        } else if (to.family == AF_INET6 && family == AF_INET6) {
            __builtin_memcpy(call.remote_ip, to.v6, 16);
        } else {
            return 0;
        }
        call.remote_port = bpf_ntohs(to.port);
        call.has_remote = 1;
    }
    if (cfg->port && cfg->port != BPF_CORE_READ(sk, __sk_common.skc_num) && cfg->port != call.remote_port)
        return 0;
    call.offset = BPF_CORE_READ(msg, msg_iter.iov_offset);
    bool iovec;
    if (bpf_core_field_exists(msg->msg_iter.iter_type)) {
        __u8 type = BPF_CORE_READ(msg, msg_iter.iter_type);
        call.ubuf = bpf_core_enum_value_exists(enum iter_type, ITER_UBUF) &&
                    type == bpf_core_enum_value(enum iter_type, ITER_UBUF);
        iovec = type == bpf_core_enum_value(enum iter_type, ITER_IOVEC);
    } else {
        iovec = BPF_CORE_READ((struct iov_iter___v5 *)&msg->msg_iter, type) &
                bpf_core_enum_value(enum iter_type, ITER_IOVEC);
    }
    if (call.ubuf) {
        call.base = (__u64)BPF_CORE_READ(msg, msg_iter.ubuf);
    } else if (iovec) {
        if (bpf_core_field_exists(msg->msg_iter.__iov))
            call.base = (__u64)BPF_CORE_READ(msg, msg_iter.__iov);
        else
            call.base = (__u64)BPF_CORE_READ((struct iov_iter___old *)&msg->msg_iter, iov);
        call.nr_segs = BPF_CORE_READ(msg, msg_iter.nr_segs);
    } else {
        return 0;
    }
    __u64 tid = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&calls, &tid, &call, BPF_ANY);
    return 0;
}

static __always_inline void fill_header(struct chunk_header *h, struct sock *sk, struct call *call)
{
    struct task_struct *task = (void *)bpf_get_current_task(); // The _btf variant needs Linux 5.11.
    __u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
    h->cookie = call->cookie;
    h->pid = bpf_get_current_pid_tgid() >> 32;
    h->start_ns = process_start(task);
    h->netns = BPF_CORE_READ(task, nsproxy, net_ns, ns.inum);
    h->direction = call->direction;
    h->family = family == AF_INET ? 4 : 6;
    h->local_port = BPF_CORE_READ(sk, __sk_common.skc_num);
    h->remote_port = call->remote_port;
    h->protocol = call->protocol;
    __builtin_memset(h->local_ip, 0, sizeof(h->local_ip));
    __builtin_memset(h->remote_ip, 0, sizeof(h->remote_ip));
    if (family == AF_INET) {
        __be32 local = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
        __be32 remote = BPF_CORE_READ(sk, __sk_common.skc_daddr);
        __builtin_memcpy(h->local_ip, &local, 4);
        __builtin_memcpy(h->remote_ip, &remote, 4);
    } else {
        BPF_CORE_READ_INTO(&h->local_ip, sk, __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8);
        BPF_CORE_READ_INTO(&h->remote_ip, sk, __sk_common.skc_v6_daddr.in6_u.u6_addr8);
    }
    if (call->has_remote)
        __builtin_memcpy(h->remote_ip, call->remote_ip, sizeof(h->remote_ip));
    bpf_get_current_comm(h->comm, sizeof(h->comm));
}

// finish copies the bytes the call actually transferred, up to the socket
// direction's remaining budget, in ring buffer chunks of at most 4 KiB.
static __always_inline void finish(struct sock *sk, int ret)
{
    __u64 tid = bpf_get_current_pid_tgid();
    struct call *pending = bpf_map_lookup_elem(&calls, &tid);
    if (!pending) return;
    struct call call = *pending;
    bpf_map_delete_elem(&calls, &tid);
    if (ret <= 0) return;

    struct stream_key key = {.cookie = call.cookie, .direction = call.direction};
    __u32 *captured_bytes = bpf_map_lookup_elem(&captured, &key);
    __u32 done = captured_bytes ? *captured_bytes : 0;
    if (done >= STREAM_BUDGET) return;
    __u32 total = (__u32)ret;
    if (total > STREAM_BUDGET - done) total = STREAM_BUDGET - done;

    __u32 zero = 0;
    struct chunk *c = bpf_map_lookup_elem(&scratch, &zero);
    if (!c) return;
    fill_header(&c->h, sk, &call);

    // Volatile, so the compiler keeps the position in map memory as well.
    volatile struct cursor *cur = &c->cur;
    cur->sent = 0;
    cur->offset = call.offset;
    cur->segment = 0;
    for (int i = 0; i < MAX_PIECES; i++) {
        __u64 sent = cur->sent, offset = cur->offset, segment = cur->segment;
        if (sent >= total) break;
        void *src;
        __u64 avail;
        if (call.ubuf) {
            src = (void *)(call.base + offset);
            avail = total - sent;
        } else {
            if (segment >= call.nr_segs || segment >= MAX_IOVECS) break;
            struct iovec iov = {};
            if (bpf_probe_read_kernel(&iov, sizeof(iov), (void *)(call.base + segment * sizeof(struct iovec))))
                break;
            if (offset >= iov.iov_len) {
                cur->segment = segment + 1;
                cur->offset = 0;
                continue;
            }
            src = iov.iov_base + offset;
            avail = iov.iov_len - offset;
        }
        __u64 n = total - sent;
        if (n > avail) n = avail;
        if (n > CHUNK_SIZE) n = CHUNK_SIZE;
        if (n == 0 || n > CHUNK_SIZE) break;
        if (bpf_probe_read_user(c->data, n, src)) break;
        c->h.offset = done + sent;
        c->h.len = n;
        if (bpf_ringbuf_output(&chunks, c, sizeof(c->h) + n, 0)) {
            __u64 *count = bpf_map_lookup_elem(&lost, &zero);
            if (count) __sync_fetch_and_add(count, 1);
            break;
        }
        cur->sent = sent + n;
        cur->offset = offset + n;
    }
    // Count what was offered, not only what was delivered: a lost chunk must
    // not be captured again at the wrong stream offset.
    __u32 next = done + total;
    bpf_map_update_elem(&captured, &key, &next, BPF_ANY);
}

// finish_datagram copies the start of one sent datagram if it opens with a
// QUIC long header; other datagrams do not spend the socket's budget. One
// chunk holds a client Initial, so there is no loop for an older verifier to
// walk once per branch.
static __always_inline void finish_datagram(struct sock *sk, int ret)
{
    __u64 tid = bpf_get_current_pid_tgid();
    struct call *pending = bpf_map_lookup_elem(&calls, &tid);
    if (!pending) return;
    struct call call = *pending;
    bpf_map_delete_elem(&calls, &tid);
    if (ret <= 0) return;

    struct stream_key key = {.cookie = call.cookie, .direction = call.direction};
    __u32 *captured_bytes = bpf_map_lookup_elem(&captured, &key);
    __u32 done = captured_bytes ? *captured_bytes : 0;
    if (done >= STREAM_BUDGET) return;
    __u64 n = (__u32)ret;
    if (n > STREAM_BUDGET - done) n = STREAM_BUDGET - done;
    void *src = (void *)(call.base + call.offset);
    if (!call.ubuf) {
        struct iovec iov = {};
        if (bpf_probe_read_kernel(&iov, sizeof(iov), (void *)call.base) || call.offset >= iov.iov_len) return;
        src = iov.iov_base + call.offset;
        if (n > iov.iov_len - call.offset) n = iov.iov_len - call.offset;
    }
    if (n > CHUNK_SIZE) n = CHUNK_SIZE;
    if (n == 0 || n > CHUNK_SIZE) return;

    __u32 zero = 0;
    struct chunk *c = bpf_map_lookup_elem(&scratch, &zero);
    if (!c || bpf_probe_read_user(c->data, n, src) || (c->data[0] & 0xc0) != 0xc0) return;
    fill_header(&c->h, sk, &call);
    c->h.offset = done;
    c->h.len = n;
    if (bpf_ringbuf_output(&chunks, c, sizeof(c->h) + n, 0)) {
        __u64 *count = bpf_map_lookup_elem(&lost, &zero);
        if (count) __sync_fetch_and_add(count, 1);
    }
    __u32 next = done + n;
    bpf_map_update_elem(&captured, &key, &next, BPF_ANY);
}

SEC("fentry/tcp_sendmsg")
int BPF_PROG(stream_send_enter, struct sock *sk, struct msghdr *msg, unsigned long size)
{
    return begin(sk, msg, DIR_SENT, 6);
}

SEC("fexit/tcp_sendmsg")
int BPF_PROG(stream_send_exit, struct sock *sk, struct msghdr *msg, unsigned long size, int ret)
{
    finish(sk, ret);
    return 0;
}

// tcp_recvmsg lost its nonblock argument in Linux 5.19. The *_old twins take
// the earlier signature; the loader keeps the pair that matches the kernel.
SEC("fentry/tcp_recvmsg")
int BPF_PROG(stream_recv_enter, struct sock *sk, struct msghdr *msg, unsigned long len, int flags)
{
    if (flags & MSG_PEEK) return 0; // Peeked bytes are received again later.
    return begin(sk, msg, DIR_RECEIVED, 6);
}

SEC("fexit/tcp_recvmsg")
int BPF_PROG(stream_recv_exit, struct sock *sk, struct msghdr *msg, unsigned long len, int flags,
             int *addr_len, int ret)
{
    finish(sk, ret);
    return 0;
}

SEC("fentry/tcp_recvmsg")
int BPF_PROG(stream_recv_enter_old, struct sock *sk, struct msghdr *msg, unsigned long len, int nonblock,
             int flags)
{
    if (flags & MSG_PEEK) return 0;
    return begin(sk, msg, DIR_RECEIVED, 6);
}

SEC("fexit/tcp_recvmsg")
int BPF_PROG(stream_recv_exit_old, struct sock *sk, struct msghdr *msg, unsigned long len, int nonblock,
             int flags, int *addr_len, int ret)
{
    finish(sk, ret);
    return 0;
}

SEC("fentry/udp_sendmsg")
int BPF_PROG(datagram_send_enter, struct sock *sk, struct msghdr *msg, unsigned long len)
{
    return begin(sk, msg, DIR_SENT, 17);
}

SEC("fexit/udp_sendmsg")
int BPF_PROG(datagram_send_exit, struct sock *sk, struct msghdr *msg, unsigned long len, int ret)
{
    finish_datagram(sk, ret);
    return 0;
}

SEC("fentry/udpv6_sendmsg")
int BPF_PROG(datagram6_send_enter, struct sock *sk, struct msghdr *msg, unsigned long len)
{
    return begin(sk, msg, DIR_SENT, 17);
}

SEC("fexit/udpv6_sendmsg")
int BPF_PROG(datagram6_send_exit, struct sock *sk, struct msghdr *msg, unsigned long len, int ret)
{
    finish_datagram(sk, ret);
    return 0;
}

// Loaded only where sockets are keyed by address (see has_socket_cookie).
// inet_sock_destruct runs once as an inet socket is destroyed; sk_free would
// not do, as it also drops a write-memory reference after each transmit.
SEC("fentry/inet_sock_destruct")
int BPF_PROG(socket_freed, struct sock *sk)
{
    struct stream_key key = {.cookie = (__u64)sk, .direction = DIR_SENT};
    bpf_map_delete_elem(&captured, &key);
    key.direction = DIR_RECEIVED;
    bpf_map_delete_elem(&captured, &key);
    return 0;
}
