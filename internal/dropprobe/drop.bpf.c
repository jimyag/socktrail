//go:build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "Dual MIT/GPL";

struct ns_common { unsigned int inum; } __attribute__((preserve_access_index));
struct net { struct ns_common ns; } __attribute__((preserve_access_index));
typedef struct { struct net *net; } possible_net_t;
struct net_device { possible_net_t nd_net; } __attribute__((preserve_access_index));
struct sock_common { possible_net_t skc_net; } __attribute__((preserve_access_index));
struct sock { struct sock_common __sk_common; } __attribute__((preserve_access_index));
struct sk_buff {
    struct sock *sk;
    struct net_device *dev;
    unsigned char *head;
    unsigned int tail;
    __u16 network_header;
} __attribute__((preserve_access_index));

// The old tracepoint has only skb and location. CO-RE removes reason access
// when the running kernel predates enum skb_drop_reason.
enum skb_drop_reason { SKB_DROP_REASON_NOT_SPECIFIED = 0 };

struct drop_key {
    __u64 netns;
    __u64 location;
    __u8 source[16];
    __u8 target[16];
    __u32 reason;
    __u16 source_port;
    __u16 target_port;
    __u8 family;
    __u8 protocol;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
    __uint(max_entries, 8192);
    __type(key, struct drop_key);
    __type(value, __u64);
} drops SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, __u64);
    __type(value, __u8);
} namespaces SEC(".maps");

SEC("raw_tracepoint/kfree_skb")
int count_drop(struct bpf_raw_tracepoint_args *ctx)
{
    struct sk_buff *skb = (void *)ctx->args[0];
    if (!skb) return 0;
    struct drop_key key = {};
    if (bpf_core_type_exists(enum skb_drop_reason)) {
        key.reason = (__u32)ctx->args[2];
        if (!key.reason) key.location = ctx->args[1];
    } else {
        key.location = ctx->args[1];
    }

    struct sock *sk = BPF_CORE_READ(skb, sk);
    if (sk) key.netns = BPF_CORE_READ(sk, __sk_common.skc_net.net, ns.inum);
    if (!key.netns) {
        struct net_device *dev = BPF_CORE_READ(skb, dev);
        if (dev) key.netns = BPF_CORE_READ(dev, nd_net.net, ns.inum);
    }
    if (key.netns && !bpf_map_lookup_elem(&namespaces, &key.netns)) return 0;

    unsigned char *head = BPF_CORE_READ(skb, head);
    __u32 tail = BPF_CORE_READ(skb, tail);
    __u16 offset = BPF_CORE_READ(skb, network_header);
    if (head && offset < tail && tail - offset >= 20) {
        __u8 first = 0;
        if (!bpf_probe_read_kernel(&first, 1, head + offset)) {
            __u32 transport = 0;
            if ((first >> 4) == 4 && tail - offset >= 20) {
                __u8 header[20] = {};
                if (!bpf_probe_read_kernel(header, sizeof(header), head + offset)) {
                    __u32 ihl = (first & 15) * 4;
                    if (ihl >= 20 && ihl <= 60 && tail - offset >= ihl) {
                        key.family = 4;
                        key.protocol = header[9];
                        __builtin_memcpy(key.source, header + 12, 4);
                        __builtin_memcpy(key.target, header + 16, 4);
                        transport = offset + ihl;
                    }
                }
            } else if ((first >> 4) == 6 && tail - offset >= 40) {
                __u8 header[40] = {};
                if (!bpf_probe_read_kernel(header, sizeof(header), head + offset)) {
                    key.family = 6;
                    key.protocol = header[6];
                    __builtin_memcpy(key.source, header + 8, 16);
                    __builtin_memcpy(key.target, header + 24, 16);
                    transport = offset + 40;
                }
            }
            if ((key.protocol == 6 || key.protocol == 17) && transport &&
                transport <= tail && tail - transport >= 4) {
                __u16 ports[2] = {};
                if (!bpf_probe_read_kernel(ports, sizeof(ports), head + transport)) {
                    key.source_port = bpf_ntohs(ports[0]);
                    key.target_port = bpf_ntohs(ports[1]);
                }
            }
        }
    }
    __u64 one = 1;
    __u64 *count = bpf_map_lookup_elem(&drops, &key);
    if (count) __sync_fetch_and_add(count, 1);
    else bpf_map_update_elem(&drops, &key, &one, BPF_NOEXIST);
    return 0;
}
