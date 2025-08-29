#!/usr/bin/env python3
from bcc import BPF
import matplotlib.pyplot as plt
import pandas as pd
import time, psutil

bpf_program = r"""
#include <uapi/linux/bpf.h>
#include <linux/if_ether.h>

// ----------------- SHIM IPv4 -----------------
struct iphdr {
    __u8 ihl:4;
    __u8 version:4;
    __u8 tos;
    __be16 tot_len;
    __be16 id;
    __be16 frag_off;
    __u8 ttl;
    __u8 protocol;
    __sum16 check;
    __be32 saddr;
    __be32 daddr;
};

// ----------------- SHIM TCP -----------------
struct tcphdr {
    __be16 source;
    __be16 dest;
    __be32 seq;
    __be32 ack_seq;
    __u16 res1:4;
    __u16 doff:4;
    __u16 fin:1;
    __u16 syn:1;
    __u16 rst:1;
    __u16 psh:1;
    __u16 ack:1;
    __u16 urg:1;
    __u16 ece:1;
    __u16 cwr:1;
    __be16 window;
    __sum16 check;
    __be16 urg_ptr;
};

// ----------------- RATE LIMIT -----------------
#define ETH_P_IP 0x0800
#define TIME_WINDOW_NS 2000000000ULL
#define THRESHOLD 10
#define NEXTHDR_TCP 6

struct rate_val {
    __u64 last_ts;
    __u64 count;
};

BPF_HASH(rate_limit_map, u32, struct rate_val, 16384);
BPF_ARRAY(stats_map, u64, 2);  // [0] = total SYN, [1] = dropped SYN

static __always_inline int check_rate_limit(u32 src_ip) {
    u64 now = bpf_ktime_get_ns();
    struct rate_val *rv = rate_limit_map.lookup(&src_ip);
    if (!rv) {
        struct rate_val val = { .last_ts = now, .count = 1 };
        rate_limit_map.update(&src_ip, &val);
        return 0;
    }

    if (now - rv->last_ts > TIME_WINDOW_NS) {
        rv->last_ts = now;
        rv->count = 1;
        rate_limit_map.update(&src_ip, rv);
        return 0;
    }

    rv->count++;
    rate_limit_map.update(&src_ip, rv);

    if (rv->count > THRESHOLD)
        return 1;
    return 0;
}

// ----------------- XDP FIREWALL -----------------
int xdp_simple_firewall(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void*)(eth+1) > data_end)
        return XDP_PASS;

    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return XDP_PASS;

    struct iphdr *iph = data + sizeof(*eth);
    if ((void*)(iph+1) > data_end)
        return XDP_PASS;

    if (iph->protocol != NEXTHDR_TCP)
        return XDP_PASS;

    struct tcphdr *tcph = (void*)iph + iph->ihl*4;
    if ((void*)(tcph+1) > data_end)
        return XDP_PASS;

    // Update total SYN counter
    if (tcph->syn && !tcph->ack) {
        u32 key_total = 0;
        u64 *val_total = stats_map.lookup(&key_total);
        if (val_total)
            __sync_fetch_and_add(val_total, 1);
    }

    // Rate limit only SYN packets
    if (tcph->syn && !tcph->ack) {
        u32 src_ip = iph->saddr;
        
        if (check_rate_limit(src_ip)) {
            // Update drop counter
            u32 key_drop = 1;
            u64 *val_drop = stats_map.lookup(&key_drop);
            if (val_drop)
                __sync_fetch_and_add(val_drop, 1);
                
            return XDP_DROP;
        }
    }

    return XDP_PASS;
}
"""

# -----------------------------------------------
# Caricamento su interfaccia
iface = "wlp3s0"  # cambia con la tua interfaccia reale
b = BPF(text=bpf_program)
fn = b.load_func("xdp_simple_firewall", BPF.XDP)
b.attach_xdp(iface, fn, 0)

print(f"XDP-only Firewall attivo su {iface}. Ctrl-C per terminare...")

# Collezione metriche runtime
timestamps = []
syn_totals = []
syn_drops = []
cpu_usages = []
pps_rates = []

prev_total = 0
prev_drop = 0
start_time = time.time()

try:
    while True:
        time.sleep(1)
        now = time.time() - start_time

        # CPU usage
        cpu_usage = psutil.cpu_percent(interval=None)

        # Lettura contatori BPF
        total_syn = b["stats_map"][0].value
        dropped_syn = b["stats_map"][1].value

        # Calcolo PPS
        delta_total = total_syn - prev_total
        prev_total = total_syn
        pps = delta_total

        # Salvataggio serie temporale
        timestamps.append(now)
        syn_totals.append(total_syn)
        syn_drops.append(dropped_syn)
        cpu_usages.append(cpu_usage)
        pps_rates.append(pps)

        print(f"Time: {now:.1f}s | SYN Total: {total_syn} | SYN Drop: {dropped_syn} | CPU: {cpu_usage}% | PPS: {pps}")

except KeyboardInterrupt:
    print("Rimozione XDP...")
    b.remove_xdp(iface, 0)

    # Final statistics
    accepted = syn_totals[-1] - syn_drops[-1]
    success_rate = (accepted / syn_totals[-1] * 100) if syn_totals[-1] > 0 else 0

    df = pd.DataFrame({
        "Metric": ["SYN Total", "SYN Blocked", "SYN Accepted", "Success Rate (%)", "Avg CPU (%)", "Avg PPS"],
        "Value": [syn_totals[-1], syn_drops[-1], accepted, success_rate,
                 sum(cpu_usages)/len(cpu_usages), sum(pps_rates)/len(pps_rates)]
    })

    print("\n=== XDP-only Results ===")
    print(df.to_string(index=False))

    # Grafici
    plt.figure()
    plt.plot(timestamps, syn_totals, label="SYN Total")
    plt.plot(timestamps, syn_drops, label="SYN Blocked")
    plt.xlabel("Time (s)")
    plt.ylabel("Count")
    plt.title("XDP-only: SYN Packets Over Time")
    plt.legend()
    plt.savefig("xdp_only_syn_over_time.png")

    plt.figure()
    plt.plot(timestamps, cpu_usages, label="CPU Usage (%)")
    plt.xlabel("Time (s)")
    plt.ylabel("CPU %")
    plt.title("XDP-only: CPU Usage Over Time")
    plt.legend()
    plt.savefig("xdp_only_cpu_usage.png")

    plt.figure()
    plt.plot(timestamps, pps_rates, label="Packets/s")
    plt.xlabel("Time (s)")
    plt.ylabel("PPS")
    plt.title("XDP-only: Throughput (SYN/sec)")
    plt.legend()
    plt.savefig("xdp_only_throughput.png")

    plt.show()