# eBPF SYN Flood Firewall: Integrated XDP and SYNPROXY Defense

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![eBPF](https://img.shields.io/badge/eBPF-Linux%20Kernel-blue)](https://ebpf.io/)
[![XDP](https://img.shields.io/badge/XDP-High%20Performance-orange)](https://www.iovisor.org/technology/xdp)

A high-performance DDoS mitigation solution combining XDP-based early packet filtering with kernel-level SYNPROXY validation to defend against SYN flood attacks while preserving legitimate traffic.

## 📖 Overview

This project presents an integrated firewall architecture that addresses the fundamental limitations of existing SYN flood mitigation approaches. By combining the performance benefits of XDP with the intelligent validation of SYNPROXY, our solution achieves:

- **61.5% HTTP service availability** during sustained SYN floods (1.8× improvement over XDP-only)
- **99.99% filtering accuracy** while processing 4.07 million SYN packets
- **4.41% CPU utilization** under attack conditions
- **20.1K PPS throughput** with precise traffic discrimination

## 🏗️ Architecture

### Multi-Layered Defense Strategy

┌─────────────────────────────────────────────────────┐
│ Integrated Defense │
├─────────────────────────────────────────────────────┤
│ Layer 3: XDP Early Filtering │
│ • Per-IP rate limiting │
│ • Blacklist management │
│ • Packet validation │
│ │
│ Layer 2: SYNPROXY Validation │
│ • Stateless SYN cookie validation │
│ • TCP option preservation │
│ • Connection handshake offloading │
│ │
│ Layer 1: Kernel Connection Tracking │
│ • Established connection handling │
│ • Legacy traffic support │
└─────────────────────────────────────────────────────┘


## ⚡ Key Features

- **XDP Native Mode**: Packet processing at driver level for maximum performance
- **LRU Hash Maps**: Scalable state management with automatic eviction
- **Adaptive Rate Limiting**: Time-window based throttling per source IP
- **SYN Cookie Validation**: Cryptographic client intention verification
- **Zero-Copy Processing**: Minimal memory overhead and CPU utilization
- **Production-Ready**: Battle-tested configuration for real deployments

## 📊 Performance Results

### Comparative Analysis
| Metric | iptables-only | XDP-only | Our Solution |
|--------|---------------|----------|-------------|
| SYN Processed | 73.5K | 5.27M | 4.07M |
| Success Rate | 18.9% | 34.1% | 61.5% |
| Throughput | 387 PPS | 27.2K PPS | 20.1K PPS |
| CPU Usage | 6.69% | 4.38% | 4.41% |

## 🚀 Quick Start

### Prerequisites
- Linux kernel ≥ 5.4
- libbpf and BPF compiler collection
- Python 3.8+ for monitoring scripts
- Mellanox ConnectX-5+ NIC (recommended)

### Installation
```bash
# Clone repository
git clone https://github.com/apirodd/eBPF.git
cd eBPF

# Install dependencies
sudo apt install build-essential libbpf-dev bpftool clang llvm

# Build eBPF programs
make

# Load XDP program
sudo ./load_xdp.sh -i eth0 --mode native

# Configure SYNPROXY rules
sudo ./configure_synproxy.sh -i eth0

# Start firewall
sudo python3 firewall_controller.py --interface eth0 --mode integrated

# Monitor performance
sudo python3 metrics_monitor.py --interface eth0 --duration 300

# Test with hping3 (simulate attack)
sudo hping3 -S -p 80 --flood target_ip

eBPF/
├── src/
│   ├── xdp_firewall.c          # Main XDP eBPF program
│   ├── rate_limit.c            # Rate limiting implementation
│   └── maps_definitions.h      # BPF map definitions
├── config/
│   ├── synproxy_rules.sh       # SYNPROXY iptables configuration
│   └── kernel_parameters.conf  # Kernel optimization settings
├── scripts/
│   ├── load_xdp.sh             # XDP program loader
│   ├── metrics_monitor.py      # Performance monitoring
│   └── attack_simulator.py     # Test traffic generator
├── results/
│   └── experimental_data/      # Performance datasets
└── docs/
    └── technical_guide.md      # Detailed implementation guide

# Enable SYN cookies and timestamps
echo 1 > /proc/sys/net/ipv4/tcp_syncookies
echo 1 > /proc/sys/net/ipv4/tcp_timestamps

# Disable loose TCP tracking for SYNPROXY
echo 0 > /proc/sys/net/netfilter/nf_conntrack_tcp_loose

# Increase connection tracking capacity
echo 524288 > /proc/sys/net/netfilter/nf_conntrack_max

#define TIME_WINDOW_NS 2000000000ULL  // 2-second window
#define THRESHOLD 10                  // 10 SYN packets threshold
#define MAX_ENTRIES 16384             // LRU map capacity

# Real-time metrics
sudo python3 metrics_monitor.py --interface eth0 --metrics all

# Export data for analysis
sudo python3 metrics_monitor.py --interface eth0 --csv output.csv

# Live dashboard
sudo python3 dashboard.py --interface eth0

Available metrics:

Packet processing rate (PPS)
CPU and memory utilization
Success/block rate percentages
Connection establishment latency
HTTP service availability

# Create test network
sudo ./setup_testlab.sh --attackers 3 --clients 5 --duration 180

# Run comprehensive test suite
sudo python3 run_tests.py --scenario syn_flood --intensity high

# Generate performance report
python3 generate_report.py --format pdf --output results.pdf


Reproducing Research Results

All experimental results from the paper can be reproduced using the scripts in the testing/ directory. Refer to docs/reproducibility.md for detailed instructions.

🎯 Use Cases

Web Server Protection: Mitigate SYN floods against HTTP/HTTPS services
Network Infrastructure: Protect routers and network equipment
Cloud Deployment: Scalable DDoS protection for cloud environments
Research Platform: Extensible framework for networking research
🤝 Contributing

We welcome contributions! Please see our Contributing Guidelines for details.

Fork the repository
Create a feature branch (git checkout -b feature/amazing-feature)
Commit your changes (git commit -m 'Add amazing feature')
Push to the branch (git push origin feature/amazing-feature)
Open a Pull Request

If you use this work in your research, please cite:
@inproceedings{piroddi2025ebpf,
  title={Integrated XDP and SYNPROXY Firewall for SYN Flood Mitigation},
  author={Piroddi, A.},
  booktitle={Proceedings of the ACM SIGCOMM Conference},
  year={2025},
  publisher={ACM}
}





