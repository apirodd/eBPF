#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>

/* Finestra temporale fissa: 2 secondi */
#define WINDOW_NS       2000000000ULL
#define DEFAULT_LIMIT   200
#define CONFIG_KEY      0

struct rate_val {
    __u64 last_ts;
    __u64 count;
};

/* Map per lo stato per-IP */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);
    __type(value, struct rate_val);
} rate_map SEC(".maps");

/* Map di configurazione: key=0 -> soglia corrente */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} config_map SEC(".maps");

SEC("xdp")
int xdp_firewall(struct xdp_md *ctx) {
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    if (eth->h_proto != __constant_htons(ETH_P_IP)) return XDP_PASS;

    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end) return XDP_PASS;
    if (iph->protocol != 6) return XDP_PASS;

    struct tcphdr *tcph = (void *)(iph + 1);
    if ((void *)(tcph + 1) > data_end) return XDP_PASS;

    if (!tcph->syn || tcph->ack) return XDP_PASS;

    /* Leggi soglia dalla config_map (default se non presente) */
    __u32 key   = CONFIG_KEY;
    __u32 limit = DEFAULT_LIMIT;
    __u32 *cfg  = bpf_map_lookup_elem(&config_map, &key);
    if (cfg && *cfg > 0)
        limit = *cfg;

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
    if (rv->count > limit) return XDP_DROP;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
