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

The system integrates two complementary in-kernel Linux mechanisms for SYN flood mitigation:

- **XDP (eXpress Data Path)**: stateless per-IP rate limiting at the earliest
  stage of packet processing, before the kernel networking stack.
- **SYNPROXY**: stateful TCP handshake validation using SYN cookies, preventing
  illegitimate connections from consuming server resources.

The rate limiting threshold τ (SYN packets per IP per 2-second window) is
**runtime-configurable** via a BPF ARRAY map (`config_map`), enabling threshold
adjustment without recompiling or reloading the XDP program.

### Key Findings

| Scenario | Best Config | Metric |
|---|---|---|
| Single-source | XDP-only | CPU 43.8% (−35% vs iptables+SYNPROXY) |
| Distributed | XDP+SYNPROXY | Latency 0.038 s (6.6× better than XDP-only) |
| Spoofed | iptables+SYNPROXY | Latency 0.049 s (latency inversion vs XDP-only) |
| Spoofed (physical) | XDP+SYNPROXY | Success rate 98.6% |

**Optimal threshold**: τ = 200 SYN/IP per 2 s minimizes latency for XDP+SYNPROXY
under spoofed attacks (0.068 s), confirmed across 3 independent runs with N = 120
measurements each.

---

## Repository Structure

```
ebpf-syn-flood-firewall/
├── src/                    # XDP/eBPF source code
├── scripts/                # Setup and utility scripts
├── experiments/            # Mininet topology and experiment runners
├── results/                # Raw CSV data (physical + emulated testbeds)
├── analysis/               # Statistical analysis and plotting scripts
├── figures/                # Paper figures (PDF + PNG)
└── paper/                  # LaTeX source
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

### Packages

```bash
sudo apt install -y \
  clang llvm libelf-dev \
  linux-headers-$(uname -r) \
  linux-tools-$(uname -r) linux-tools-common \
  bpfcc-tools libbpf-dev \
  iproute2 iptables \
  hping3 python3 python3-pip

pip3 install mininet matplotlib scipy numpy --break-system-packages
```

### Verify kernel support

```bash
grep -E "CONFIG_XDP|CONFIG_BPF_SYSCALL" /boot/config-$(uname -r)
sudo bpftool version
```

---

## Quick Start

### 1. Compile the XDP program

```bash
cd src/

# Fixed threshold version (τ = 200, default)
clang -O2 -g -target bpf \
  -I/usr/include/$(uname -m)-linux-gnu \
  -c xdp_firewall.c -o xdp_firewall.o

# Runtime-configurable threshold version
clang -O2 -g -target bpf \
  -I/usr/include/$(uname -m)-linux-gnu \
  -c xdp_firewall_adaptive.c -o xdp_firewall_adaptive.o
```

### 2. Check dependencies

```bash
bash scripts/check_requirements.sh
```

### 3. Deploy XDP-only

```bash
# Load XDP on interface eth0 (xdpgeneric for virtual interfaces)
sudo ip link set dev eth0 xdpgeneric obj src/xdp_firewall.o sec xdp

# Verify
ip link show eth0 | grep xdp
```

### 4. Deploy XDP + SYNPROXY (combined)

```bash
# Load XDP with runtime-configurable threshold
sudo ip link set dev eth0 xdpgeneric \
  obj src/xdp_firewall_adaptive.o sec xdp

# Configure SYNPROXY
sudo bash scripts/setup_iptables_synproxy.sh

# Set threshold at runtime (no reload required)
sudo bash scripts/set_threshold.sh 200
```

### 5. Reset

```bash
sudo bash scripts/reset_firewall.sh
```

---

## Runtime Threshold Configuration

The adaptive version exposes the rate limiting threshold via a pinned BPF map:

```bash
# Set threshold to 100 SYN/IP per 2-second window
sudo bash scripts/set_threshold.sh 100

# Verify current threshold
sudo bpftool map dump pinned /sys/fs/bpf/xdp_thresh/config_map
```

Threshold values evaluated in the paper: τ ∈ {50, 100, 200, 500}.  
**Recommended default**: τ = 200 for XDP+SYNPROXY under mixed traffic.

---

## Reproducing the Experiments

### Physical testbed

The physical testbed uses two machines connected via a switch.
See Table I in the paper for hardware specifications.
Configure the firewall on the victim machine using the scripts above,
and generate traffic from the attacker using hping3:

```bash
# Single-source attack
hping3 -S -p 80 --faster -c 100000 <victim-ip>

# Spoofed attack
hping3 -S -p 80 --rand-source --faster -c 100000 <victim-ip>
```

### Emulated testbed (Mininet)

All experiments use the subnet `172.16.50.0/24` for the server/client
and `172.16.51.0/24` for attackers to avoid conflicts with local networks.

```bash
# Single run: no firewall, single-source, 1 attacker, 50 kpps, 60 s
sudo mn -c 2>/dev/null
sudo python3 experiments/mininet/run_single_experiment.py \
  none single 1 50000 60

# View result
cat last_result.txt
```

#### Full experimental matrix (36 runs, ~90 min)

```bash
sudo mn -c 2>/dev/null
bash experiments/mininet/run_all.sh 2>&1 | tee run_all.log
```

#### Threshold sensitivity analysis (36 runs, ~90 min)

```bash
sudo mn -c 2>/dev/null
bash experiments/threshold/run_threshold_all.sh 2>&1 | tee run_threshold.log
```

**Parameter summary:**

| Parameter | Value |
|---|---|
| Attack rate | 50 kpps total |
| Run duration | 60 s |
| HTTP sampling | 1 request / 500 ms → N = 120 per run |
| Repetitions | 3 independent runs per configuration |
| Configurations | none, xdp, iptables, combined |
| Scenarios | single-source, distributed, spoofed |
| Attackers | 1 (single), 5 (distributed/spoofed) |

---

## Analysis and Figures

After collecting results, run the analysis scripts:

```bash
cd analysis/

# Compute mean ± std and generate LaTeX tables
python3 analyze_results.py

# Threshold sensitivity analysis
python3 analyze_threshold.py

# 95% CI and Cohen's d effect size
python3 statistical_analysis.py

# Generate paper figures with error bars
python3 plot_results_final.py
```

Output figures are saved in `figures/` as both PDF (for the paper) and PNG.

---

## Raw Results

The `results/` directory contains all raw CSV files from the experiments
reported in the paper.

### Format — emulated testbed

```
fw, scenario, n_attackers, rep, success, avg_lat_s, std_lat_s, n_req, cpu_pct
```

### Format — threshold analysis

```
fw, scenario, n_attackers, threshold, rep, success, avg_lat_s, std_lat_s, n_req, cpu_pct
```

### Summary statistics

| Testbed | Configurations | Scenarios | Runs | N/run | Total measurements |
|---|---|---|---|---|---|
| Physical | 3 | 3 | 1 | — | — |
| Emulated | 4 | 3 | 3 | 120 | 4,320 |
| Threshold | 4×4 | 2 | 3 | 120 | 5,760 |

---

## Operational Configuration

Kernel parameters required for correct SYNPROXY behavior:

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
