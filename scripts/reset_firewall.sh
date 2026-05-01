#!/bin/bash
# reset_firewall.sh
# Completely removes XDP programs and iptables rules.
# Safe to run multiple times (idempotent).
#
# Usage: sudo bash reset_firewall.sh [INTERFACE]
#   INTERFACE: specific interface to reset XDP on (default: all interfaces)
#
# Example: sudo bash reset_firewall.sh eth0

set -e

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }

[[ $EUID -ne 0 ]] && { echo -e "${RED}[ERROR]${NC} Run as root (sudo)."; exit 1; }

IFACE=${1:-}

# ── Remove XDP programs ───────────────────────────────────────────────────────
info "Removing XDP programs..."

if [ -n "$IFACE" ]; then
    # Specific interface
    ip link set dev "$IFACE" xdpgeneric off 2>/dev/null \
        && info "XDP removed from $IFACE" \
        || warn "No XDP program on $IFACE (or interface not found)"
    ip link set dev "$IFACE" xdp off 2>/dev/null || true
else
    # All interfaces
    for iface in $(ip link show | awk -F': ' '/^[0-9]+:/{print $2}' | tr -d '@.*'); do
        if ip link show "$iface" 2>/dev/null | grep -q xdp; then
            ip link set dev "$iface" xdpgeneric off 2>/dev/null || true
            ip link set dev "$iface" xdp off 2>/dev/null || true
            info "XDP removed from $iface"
        fi
    done
fi

# ── Remove pinned BPF maps ────────────────────────────────────────────────────
info "Removing pinned BPF maps..."
PIN_DIR="/sys/fs/bpf/xdp_thresh"
if [ -d "$PIN_DIR" ]; then
    rm -f "${PIN_DIR}/config_map" "${PIN_DIR}/rate_map" "${PIN_DIR}/prog"
    rmdir "$PIN_DIR" 2>/dev/null || true
    info "Pinned maps removed from $PIN_DIR"
else
    warn "No pinned maps found at $PIN_DIR"
fi

# Also clean legacy pin locations
rm -f /sys/fs/bpf/xdp_test /sys/fs/bpf/xdp_adaptive_test 2>/dev/null || true

# ── Flush iptables rules ──────────────────────────────────────────────────────
info "Flushing iptables rules..."
iptables -F              2>/dev/null || warn "iptables -F failed"
iptables -t raw -F       2>/dev/null || warn "iptables -t raw -F failed"
iptables -t mangle -F    2>/dev/null || warn "iptables -t mangle -F failed"
iptables -t nat -F       2>/dev/null || warn "iptables -t nat -F failed"

# Reset default policies to ACCEPT
iptables -P INPUT   ACCEPT 2>/dev/null || true
iptables -P FORWARD ACCEPT 2>/dev/null || true
iptables -P OUTPUT  ACCEPT 2>/dev/null || true

info "iptables rules flushed."

# ── Restore default kernel parameters ────────────────────────────────────────
info "Restoring kernel parameters to defaults..."
sysctl -w net.ipv4.tcp_syncookies=1    -q  # keep enabled (good practice)
sysctl -w net.core.somaxconn=4096      -q
sysctl -w net.ipv4.tcp_max_syn_backlog=512 -q

echo ""
echo -e "${GREEN}✓ Firewall reset complete. System is in baseline (no-firewall) state.${NC}"
