#!/bin/bash
# setup_iptables_synproxy.sh
# Configures iptables+SYNPROXY for SYN flood mitigation.
# Must be run as root.
#
# Usage: sudo bash setup_iptables_synproxy.sh [INTERFACE]
#   INTERFACE: optional, network interface to protect (default: auto-detect)
#
# Example: sudo bash setup_iptables_synproxy.sh eth0

set -e

# ── Colour output ─────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

# ── Root check ────────────────────────────────────────────────────────────────
[[ $EUID -ne 0 ]] && error "This script must be run as root (sudo)."

# ── Load required kernel modules ──────────────────────────────────────────────
info "Loading kernel modules..."
modprobe nf_conntrack      2>/dev/null || warn "nf_conntrack may be built-in"
modprobe nf_synproxy_core  2>/dev/null || warn "nf_synproxy_core may be built-in"
modprobe xt_SYNPROXY       2>/dev/null || warn "xt_SYNPROXY may be built-in"

# Verify conntrack is available
if ! lsmod | grep -q nf_conntrack && \
   ! grep -q "CONFIG_NF_CONNTRACK=y" /boot/config-$(uname -r) 2>/dev/null; then
    error "nf_conntrack not available. Check kernel configuration."
fi

# ── Kernel parameters ─────────────────────────────────────────────────────────
info "Configuring kernel parameters..."
sysctl -w net.ipv4.tcp_syncookies=1               -q
sysctl -w net.netfilter.nf_conntrack_tcp_loose=0  -q
sysctl -w net.core.somaxconn=32768                -q
sysctl -w net.ipv4.tcp_max_syn_backlog=32768      -q
info "Kernel parameters set."

# ── Flush existing rules ──────────────────────────────────────────────────────
info "Flushing existing iptables rules..."
iptables -F
iptables -t raw -F
iptables -t mangle -F

# ── SYNPROXY rules ────────────────────────────────────────────────────────────
info "Applying SYNPROXY rules..."

# Mark incoming SYN packets as untracked (bypass conntrack for initial SYN)
iptables -t raw -I PREROUTING -p tcp --syn -j CT --notrack

# Apply SYNPROXY to untracked/invalid TCP connections
iptables -A INPUT -p tcp -m conntrack \
    --ctstate UNTRACKED,INVALID \
    -j SYNPROXY \
    --sack-perm --timestamp --wscale 7 --mss 1460

# Drop invalid packets after SYNPROXY validation
iptables -A INPUT -m conntrack --ctstate INVALID -j DROP

# Accept established and related connections
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# ── Verify ────────────────────────────────────────────────────────────────────
info "Current INPUT chain:"
iptables -L INPUT -n --line-numbers

info "Current raw PREROUTING chain:"
iptables -t raw -L PREROUTING -n --line-numbers

echo ""
echo -e "${GREEN}✓ iptables+SYNPROXY configured successfully.${NC}"
echo "  To remove: sudo bash scripts/reset_firewall.sh"
