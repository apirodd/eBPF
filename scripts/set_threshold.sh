#!/bin/bash
# set_threshold.sh
# Updates the XDP rate limiting threshold at runtime via BPF map.
# Does NOT require reloading or recompiling the XDP program.
#
# Usage: sudo bash set_threshold.sh <threshold> [pin_dir]
#   threshold : SYN packets per IP per 2-second window (e.g. 50, 100, 200, 500)
#   pin_dir   : BPF filesystem pin directory (default: /sys/fs/bpf/xdp_thresh)
#
# Example: sudo bash set_threshold.sh 200
#
# Recommended values (from paper threshold sensitivity analysis):
#   50   : aggressive filtering, lower latency, higher false positive rate
#   100  : balanced
#   200  : optimal for XDP+SYNPROXY under spoofed attacks (lowest latency)
#   500  : permissive, minimal false positives, higher latency under spoofing

set -e

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

# ── Arguments ─────────────────────────────────────────────────────────────────
THRESHOLD=${1:-200}
PIN_DIR=${2:-/sys/fs/bpf/xdp_thresh}
CONFIG_MAP="${PIN_DIR}/config_map"

# ── Validate ──────────────────────────────────────────────────────────────────
[[ $EUID -ne 0 ]] && error "This script must be run as root (sudo)."

if ! [[ "$THRESHOLD" =~ ^[0-9]+$ ]] || [ "$THRESHOLD" -lt 1 ]; then
    error "Threshold must be a positive integer. Got: '$THRESHOLD'"
fi

if [ ! -f "$CONFIG_MAP" ]; then
    error "config_map not found at $CONFIG_MAP.
Make sure the XDP adaptive program is loaded and maps are pinned.
Run: sudo ip link set dev <iface> xdpgeneric obj src/xdp_firewall_adaptive.o sec xdp
Then pin maps manually or use experiments/mininet/run_threshold_experiment.py"
fi

if ! command -v bpftool &>/dev/null; then
    error "bpftool not found. Install: sudo apt install linux-tools-\$(uname -r)"
fi

# ── Convert threshold to 4-byte little-endian ─────────────────────────────────
B0=$(( THRESHOLD        & 0xFF ))
B1=$(( (THRESHOLD >> 8) & 0xFF ))
B2=$(( (THRESHOLD >> 16) & 0xFF ))
B3=$(( (THRESHOLD >> 24) & 0xFF ))

# ── Update map ────────────────────────────────────────────────────────────────
info "Setting XDP threshold to ${THRESHOLD} SYN/IP per 2-second window..."

bpftool map update \
    pinned "$CONFIG_MAP" \
    key  0  0  0  0 \
    value "$B0" "$B1" "$B2" "$B3"

# ── Verify ────────────────────────────────────────────────────────────────────
CURRENT=$(bpftool map dump pinned "$CONFIG_MAP" 2>/dev/null | \
          grep -o '"value": [0-9]*' | awk '{print $2}')

if [ "$CURRENT" = "$THRESHOLD" ]; then
    echo -e "${GREEN}✓ Threshold updated: ${THRESHOLD} SYN/IP per 2s window${NC}"
    echo "  No XDP program reload required."
else
    warn "Map updated but verification returned: $CURRENT (expected $THRESHOLD)"
    warn "This may be a display format issue — check with:"
    warn "  sudo bpftool map dump pinned $CONFIG_MAP"
fi
