#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>

#define RATE_LIMIT  200
#define WINDOW_NS   2000000000ULL  // 2 secondi

struct rate_val {
    __u64 last_ts;
    __u64 count;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);
    __type(value, struct rate_val);
} rate_map SEC(".maps");

SEC("xdp")
int xdp_firewall(struct xdp_md *ctx) {
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    if (eth->h_proto != __constant_htons(ETH_P_IP)) return XDP_PASS;

    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end) return XDP_PASS;
    if (iph->protocol != IPPROTO_TCP) return XDP_PASS;

    struct tcphdr *tcph = (void *)(iph + 1);
    if ((void *)(tcph + 1) > data_end) return XDP_PASS;

    // Solo pacchetti SYN (non SYN-ACK)
    if (!tcph->syn || tcph->ack) return XDP_PASS;

    __u32 src_ip = iph->saddr;
    __u64 now    = bpf_ktime_get_ns();

    struct rate_val *rv = bpf_map_lookup_elem(&rate_map, &src_ip);
    if (!rv) {
        struct rate_val new_rv = { .last_ts = now, .count = 1 };
        bpf_map_update_elem(&rate_map, &src_ip, &new_rv, BPF_ANY);
        return XDP_PASS;
    }

    if (now - rv->last_ts > WINDOW_NS) {
        rv->last_ts = now;
        rv->count   = 1;
        return XDP_PASS;
    }

    rv->count++;
    if (rv->count > RATE_LIMIT) return XDP_DROP;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
