# eBPF SYN Flood Firewall: Integrated XDP and SYNPROXY Defense

[![License: GPL-2.0](https://img.shields.io/badge/License-GPL%202.0-blue.svg)](LICENSE)
[![Kernel: 6.17+](https://img.shields.io/badge/Kernel-6.17%2B-green.svg)](https://kernel.org)
[![Platform: Ubuntu 24.04](https://img.shields.io/badge/Platform-Ubuntu%2024.04-orange.svg)](https://ubuntu.com)

> Artifact repository for the paper:  
> **"eBPF SYN Flood Firewall: Integrated XDP and SYNPROXY Defense"**  
> Alessandro Martini, Andrea Piroddi, Roberto Girau, Giovanni Pau, Franco Callegati, Andrea Melis  
> Department of Computer Science and Engineering, University of Bologna, Cesena, Italy  
> *Submitted to Computer Networks, Elsevier, 2026*

---

## Overview

This repository provides the complete implementation, experimental infrastructure,
raw results, and analysis scripts accompanying the paper.

We provide the first systematic, statistically rigorous comparison of **seven
in-kernel SYN flood mitigation mechanisms** for Linux, evaluated across three
attack scenarios (single-source, distributed, spoofed) on both a physical
testbed and a reproducible Mininet-based emulated environment
(63 independent runs, N = 120 measurements per run).

The seven mechanisms evaluated are:

| ID | Mechanism | Type |
|---|---|---|
| `none` | No Firewall (baseline) | — |
| `syn-cookies` | Kernel SYN Cookies | Stateless kernel |
| `iptables-hl` | iptables hashlimit | Stateless rate limiting |
| `iptables` | iptables + SYNPROXY | Stateful validation |
| `nftables` | nftables + SYNPROXY | Stateful validation |
| `xdp` | XDP-only | Stateless eBPF |
| `combined` | XDP + SYNPROXY | Layered (proposed) |

The XDP rate limiting threshold τ (SYN packets per IP per 2-second window) is
**runtime-configurable** via a BPF ARRAY map (`config_map`), enabling threshold
adjustment without recompiling or reloading the XDP program.

### Key Findings

| Scenario | Best Success Rate | Best Latency | Best CPU |
|---|---|---|---|
| Single-source | All equal (1.000) | XDP-only (0.016 s) | XDP+SYNPROXY (43.7%) |
| Distributed | XDP-only (0.966) | XDP+SYNPROXY (0.040 s) | XDP-only (58.7%) |
| Spoofed | SYN Cookies (0.986) | iptables+SYNPROXY (0.058 s) | iptables hashlimit (58.0%) |
| Spoofed (physical) | XDP+SYNPROXY (98.6%) | — | — |

**Three previously unreported behaviors:**
1. Kernel SYN Cookies achieves the highest success rate under spoofed attacks (0.986) without any firewall overhead.
2. iptables+SYNPROXY achieves *lower* latency than XDP-only under spoofed attacks (0.058 s vs. 0.173 s) — a latency inversion explained by connection-level validation.
3. iptables hashlimit matches XDP-only CPU efficiency under distributed attacks (60.1% vs. 58.7%), positioning it as a viable alternative where eBPF is unavailable.

**Optimal threshold**: τ = 200 SYN/IP per 2 s minimizes latency for XDP+SYNPROXY
under spoofed attacks (0.068 s), confirmed across 3 independent runs with N = 120
measurements each.

---

## Repository Structure

```
ebpf-syn-flood-firewall/
├── src/                             # XDP/eBPF source code
│   ├── xdp_firewall.c               # Fixed threshold version (τ = 200)
│   ├── xdp_firewall_adaptive.c      # Runtime-configurable threshold version
│   └── Makefile
├── scripts/                         # Setup and utility scripts
│   ├── setup_iptables_synproxy.sh
│   ├── set_threshold.sh
│   ├── reset_firewall.sh
│   └── check_requirements.sh
├── experiments/                     # Experiment runners
│   ├── mininet/
│   │   ├── run_single_experiment.py # Single run (all 7 configurations)
│   │   └── run_all_extended.sh      # Full matrix: 63 runs (~112 min)
│   └── threshold/
│       ├── run_threshold_experiment.py
│       └── run_threshold_all.sh     # Threshold sensitivity: 36 runs
├── results/                         # Raw CSV data
│   ├── physical/                    # Physical testbed (3 configurations)
│   ├── emulated/                    # Mininet emulated (63 CSV files)
│   └── threshold/                   # Threshold sensitivity (36 CSV files)
├── analysis/                        # Statistical analysis and plotting
│   ├── analyze_extended.py          # Stats + LaTeX tables (7 configurations)
│   ├── analyze_threshold.py         # Threshold sensitivity analysis
│   ├── statistical_analysis.py      # 95% CI and Cohen's d
│   └── regen_fig_latency.py         # Regenerate individual figures
├── figures/                         # Paper figures (PDF + PNG)
└── paper/                           # LaTeX source
    ├── paper_final_v2.tex
    └── references.bib
```

---

## Requirements

### System

| Component | Requirement |
|---|---|
| OS | Ubuntu 24.04 LTS |
| Kernel | ≥ 6.8 (tested on 6.17.0) |
| bpftool | ≥ 7.7 |
| libbpf | ≥ 1.7 |
| clang/llvm | ≥ 14 |
| nftables | ≥ 1.0 (tested on 1.0.9) |

### Packages

```bash
sudo apt install -y \
  clang llvm libelf-dev \
  linux-headers-$(uname -r) \
  linux-tools-$(uname -r) linux-tools-common \
  bpfcc-tools libbpf-dev \
  iproute2 iptables nftables \
  hping3 python3 python3-pip \
  mininet openvswitch-switch

pip3 install matplotlib scipy numpy --break-system-packages
```

### Verify dependencies

```bash
bash scripts/check_requirements.sh
```

---

## Quick Start

### 1. Compile the XDP program

```bash
cd src/

# Runtime-configurable threshold version (recommended)
make adaptive

# Fixed threshold version (τ = 200)
make fixed
```

Or manually:

```bash
clang -O2 -g -target bpf \
  -I/usr/include/$(uname -m)-linux-gnu \
  -c xdp_firewall_adaptive.c -o xdp_firewall_adaptive.o
```

### 2. Deploy XDP-only

```bash
sudo ip link set dev eth0 xdpgeneric \
  obj src/xdp_firewall_adaptive.o sec xdp

ip link show eth0 | grep xdp
```

### 3. Deploy XDP + SYNPROXY (combined, recommended)

```bash
# Load XDP
sudo ip link set dev eth0 xdpgeneric \
  obj src/xdp_firewall_adaptive.o sec xdp

# Configure iptables SYNPROXY
sudo bash scripts/setup_iptables_synproxy.sh

# Set threshold at runtime (no reload required)
sudo bash scripts/set_threshold.sh 200
```

### 4. Deploy other mechanisms

```bash
# SYN Cookies only (kernel tuning, no firewall rules)
sudo sysctl -w net.ipv4.tcp_syncookies=1
sudo sysctl -w net.ipv4.tcp_max_syn_backlog=32768
sudo sysctl -w net.core.somaxconn=32768
sudo sysctl -w net.ipv4.tcp_synack_retries=1

# iptables hashlimit (rate limiting without handshake validation)
sudo iptables -A INPUT -p tcp --syn \
  -m hashlimit --hashlimit-name syn_limit \
  --hashlimit-above 100/second --hashlimit-burst 200 \
  --hashlimit-mode srcip --hashlimit-srcmask 32 -j DROP
```

### 5. Reset

```bash
sudo bash scripts/reset_firewall.sh
```

---

## Runtime Threshold Configuration

The adaptive XDP program exposes the rate limiting threshold via a pinned
BPF map, allowing runtime updates without reloading:

```bash
# Set threshold (SYN/IP per 2-second window)
sudo bash scripts/set_threshold.sh 200

# Verify
sudo bpftool map dump pinned /sys/fs/bpf/xdp_thresh/config_map
```

Threshold values evaluated in the paper: τ ∈ {50, 100, 200, 500}.  
**Recommended default**: τ = 200 for XDP+SYNPROXY under mixed/unknown traffic.

---

## Reproducing the Experiments

### Physical testbed

Configure the firewall on the victim machine using the scripts above.
Generate attack traffic from the attacker:

```bash
# Single-source
hping3 -S -p 80 --faster -c 100000 <victim-ip>

# Distributed (run on multiple attackers simultaneously)
hping3 -S -p 80 --faster -c 50000 <victim-ip>

# Spoofed
hping3 -S -p 80 --rand-source --faster -c 100000 <victim-ip>
```

### Emulated testbed (Mininet)

All experiments use `172.16.50.0/24` for server/client and
`172.16.51.0/24` for attackers to avoid routing conflicts with
the host network.

```bash
# Single test run: XDP-only, single-source, 1 attacker, 50 kpps, 60 s
sudo mn -c 2>/dev/null
sudo python3 experiments/mininet/run_single_experiment.py \
  xdp single 1 50000 60
cat last_result.txt
```

Supported `fw` values: `none`, `syn-cookies`, `iptables-hl`,
`iptables`, `nftables`, `xdp`, `combined`.

#### Full experimental matrix (63 runs, ~112 min)

```bash
sudo mn -c 2>/dev/null
bash experiments/mininet/run_all_extended.sh 2>&1 | \
  tee run_extended.log
```

The script automatically skips runs with existing valid results,
allowing safe restart after interruption.

#### Threshold sensitivity analysis (36 runs, ~90 min)

```bash
sudo mn -c 2>/dev/null
bash experiments/threshold/run_threshold_all.sh 2>&1 | \
  tee run_threshold.log
```

**Experimental parameters:**

| Parameter | Value |
|---|---|
| Attack rate | 50 kpps total |
| Run duration | 60 s |
| HTTP sampling | 1 request / 500 ms → N = 120 per run |
| Repetitions | 3 independent runs per configuration |
| Configurations (emulated) | 7 |
| Configurations (physical) | 3 |
| Scenarios | single-source (1 atk), distributed (5 atk), spoofed (5 atk) |
| Total emulated runs | 63 (7 × 3 × 3) |
| Total threshold runs | 36 (4τ × 3 configs × 3 reps) |

---

## Analysis and Figures

```bash
cd analysis/

# Full statistical analysis: mean ± std, CI 95%, LaTeX tables, figures
python3 analyze_extended.py

# Threshold sensitivity analysis
python3 analyze_threshold.py

# Cohen's d effect size
python3 statistical_analysis.py

# Regenerate individual figures with custom layout
python3 regen_fig_latency.py
```

Output figures are saved as both PDF (for the paper) and PNG in `figures/`.

---

## Raw Results

### CSV format — emulated testbed

```
fw, scenario, n_attackers, rep, success, avg_lat_s, std_lat_s, n_req, cpu_pct
```

### CSV format — threshold analysis

```
fw, scenario, n_attackers, threshold, rep, success, avg_lat_s, std_lat_s, n_req, cpu_pct
```

### Summary

| Testbed | Configurations | Scenarios | Runs | N/run | Total measurements |
|---|---|---|---|---|---|
| Physical | 3 | 3 | 1 | — | — |
| Emulated | 7 | 3 | 3 | 120 | 7,560 |
| Threshold | 2 configs × 4τ | 2 | 3 | 120 | 5,760 |

---

## Operational Configuration

Kernel parameters required on the protected server:

```bash
sudo sysctl -w net.ipv4.tcp_syncookies=1
sudo sysctl -w net.netfilter.nf_conntrack_tcp_loose=0
sudo sysctl -w net.core.somaxconn=32768
sudo sysctl -w net.ipv4.tcp_max_syn_backlog=32768
```

---

## Citation

If you use this code or data in your research, please cite:

```bibtex
@article{martini2026ebpf,
  author  = {Martini, Alessandro and Piroddi, Andrea and Girau, Roberto
             and Pau, Giovanni and Callegati, Franco and Melis, Andrea},
  title   = {{eBPF SYN Flood Firewall: Integrated XDP and SYNPROXY Defense}},
  journal = {Computer Networks},
  year    = {2026},
  note    = {Under review}
}
```

---

## License

The XDP/eBPF source code is released under the **GPL-2.0** license,
consistent with the Linux kernel licensing requirements.  
All scripts, analysis code, and experimental data are released under **MIT**.

---

## Authors

- Alessandro Martini — `alessandro.martini10@studio.unibo.it`
- Andrea Piroddi — `andrea.piroddi@unibo.it`
- Roberto Girau — `roberto.girau@unibo.it`
- Giovanni Pau — `giovanni.pau@unibo.it`
- Franco Callegati — `franco.callegati@unibo.it`
- Andrea Melis — `a.melis@unibo.it`

Department of Computer Science and Engineering  
University of Bologna, Cesena, Italy
