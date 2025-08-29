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
BPF_HASH(ip_blocked_map, u32, u64, 16384);
BPF_ARRAY(stats_map, u64, 1);

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
int xdp_firewall(struct xdp_md *ctx) {
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

    u32 src_ip = iph->saddr;

    // Log SYN
    if (tcph->syn && !tcph->ack)
        bpf_trace_printk("SYN ricevuto da IP: %x\n", src_ip);

    // Aggiorna contatore globale SYN
    u32 key = 0;
    u64 *val = stats_map.lookup(&key);
    if (val)
        __sync_fetch_and_add(val, 1);

    // Gestione SYN con rate-limit e blocco
    if (tcph->syn && !tcph->ack) {
        u64 *blocked = ip_blocked_map.lookup(&src_ip);
        if (blocked)
            return XDP_DROP;

        if (check_rate_limit(src_ip)) {
            u64 one = 1;
            ip_blocked_map.update(&src_ip, &one);
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
fn = b.load_func("xdp_firewall", BPF.XDP)
b.attach_xdp(iface, fn, 0)

print(f"XDP Firewall attivo su {iface}. Ctrl-C per terminare...")

# Collezione metriche runtime
timestamps = []
syn_counts = []
blocked_counts = []
cpu_usages = []
pps_rates = []

prev_syn = 0
start_time = time.time()

try:
    while True:
        time.sleep(1)  # campionamento ogni secondo
        now = time.time() - start_time

        # CPU usage (process wide)
        cpu_usage = psutil.cpu_percent(interval=None)

        # Lettura contatori BPF
        syn_key = 0
        syn_total = b["stats_map"][syn_key].value
        blocked = len(b["ip_blocked_map"])

        # Calcolo OPS/PPS
        delta_syn = syn_total - prev_syn
        prev_syn = syn_total
        pps = delta_syn  # SYN/sec approx

        # Salvataggio serie temporale
        timestamps.append(now)
        syn_counts.append(syn_total)
        blocked_counts.append(blocked)
        cpu_usages.append(cpu_usage)
        pps_rates.append(pps)

except KeyboardInterrupt:
    print("Rimozione XDP...")
    b.remove_xdp(iface, 0)

    # Tabella finale
    accepted = syn_counts[-1] - blocked_counts[-1]
    success_rate = (accepted / syn_counts[-1] * 100) if syn_counts[-1] > 0 else 0

    df = pd.DataFrame({
        "Metric": ["SYN Total", "SYN Blocked", "SYN Accepted", "Success Rate (%)", "Avg CPU (%)", "Avg PPS"],
        "Value": [syn_counts[-1], blocked_counts[-1], accepted, success_rate,
                  sum(cpu_usages)/len(cpu_usages), sum(pps_rates)/len(pps_rates)]
    })

    print("\n=== Risultati Firewall ===")
    print(df.to_string(index=False))

    # --- Grafici temporali ---
    plt.figure()
    plt.plot(timestamps, syn_counts, label="SYN Total")
    plt.plot(timestamps, blocked_counts, label="SYN Blocked")
    plt.xlabel("Time (s)")
    plt.ylabel("Count")
    plt.title("SYN Packets Over Time")
    plt.legend()
    plt.show()

    plt.figure()
    plt.plot(timestamps, cpu_usages, label="CPU Usage (%)")
    plt.xlabel("Time (s)")
    plt.ylabel("CPU %")
    plt.title("CPU Usage Over Time")
    plt.legend()
    plt.show()

    plt.figure()
    plt.plot(timestamps, pps_rates, label="Packets/s")
    plt.xlabel("Time (s)")
    plt.ylabel("PPS")
    plt.title("Throughput (SYN/sec)")
    plt.legend()
    plt.show()
