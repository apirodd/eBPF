#!/bin/bash
# check_requirements.sh
# Verifies all dependencies required to build and run the XDP+SYNPROXY
# firewall and reproduce the Mininet experiments.
#
# Usage: bash scripts/check_requirements.sh
#
# Exit codes:
#   0 : all requirements met
#   1 : one or more requirements missing

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; NC='\033[0m'

ok()   { echo -e "  ${GREEN}✓${NC}  $*"; }
fail() { echo -e "  ${RED}✗${NC}  $*"; FAILED=$((FAILED+1)); }
warn() { echo -e "  ${YELLOW}!${NC}  $*"; WARNINGS=$((WARNINGS+1)); }
section() { echo -e "\n${BLUE}── $* ──────────────────────────────────${NC}"; }

FAILED=0
WARNINGS=0

# ── OS & Kernel ───────────────────────────────────────────────────────────────
section "Operating System & Kernel"

KERNEL=$(uname -r)
KERNEL_MAJOR=$(echo "$KERNEL" | cut -d. -f1)
KERNEL_MINOR=$(echo "$KERNEL" | cut -d. -f2)

echo "  Kernel: $KERNEL"
if [ "$KERNEL_MAJOR" -gt 6 ] || \
   ([ "$KERNEL_MAJOR" -eq 6 ] && [ "$KERNEL_MINOR" -ge 8 ]); then
    ok "Kernel >= 6.8 (tested on 6.17)"
else
    warn "Kernel $KERNEL may work but 6.8+ is recommended"
fi

if grep -q "Ubuntu" /etc/os-release 2>/dev/null; then
    UBUNTU_VER=$(grep VERSION_ID /etc/os-release | cut -d'"' -f2)
    ok "Ubuntu $UBUNTU_VER detected"
else
    warn "Non-Ubuntu system detected — scripts may need adaptation"
fi

# ── Kernel BPF/XDP configuration ─────────────────────────────────────────────
section "Kernel BPF/XDP Configuration"

CONFIG=/boot/config-$(uname -r)
check_kconfig() {
    local key=$1 label=$2
    if grep -q "${key}=y" "$CONFIG" 2>/dev/null; then
        ok "$label (built-in)"
    elif grep -q "${key}=m" "$CONFIG" 2>/dev/null; then
        ok "$label (module)"
    else
        fail "$label not found in kernel config"
    fi
}

check_kconfig CONFIG_BPF            "BPF"
check_kconfig CONFIG_BPF_SYSCALL    "BPF syscall"
check_kconfig CONFIG_XDP_SOCKETS    "XDP sockets"
check_kconfig CONFIG_NF_CONNTRACK   "Netfilter conntrack"
check_kconfig CONFIG_NETFILTER_SYNPROXY "SYNPROXY"

# ── Build tools ───────────────────────────────────────────────────────────────
section "Build Tools"

check_cmd() {
    local cmd=$1 label=${2:-$1}
    if command -v "$cmd" &>/dev/null; then
        local ver
        ver=$("$cmd" --version 2>&1 | head -1)
        ok "$label — $ver"
    else
        fail "$label not found (install: sudo apt install ${3:-$cmd})"
    fi
}

check_cmd clang  "clang"  "clang"
check_cmd llvm-strip "llvm-strip" "llvm"
check_cmd bpftool "bpftool" "linux-tools-$(uname -r)"

# Check bpftool version
if command -v bpftool &>/dev/null; then
    BPFTOOL_VER=$(bpftool version 2>&1 | grep -oP 'v\d+\.\d+' | head -1)
    ok "bpftool $BPFTOOL_VER"
fi

# Check libbpf headers
if [ -f /usr/include/bpf/bpf_helpers.h ]; then
    ok "libbpf headers found (/usr/include/bpf/)"
else
    fail "libbpf headers not found (install: sudo apt install libbpf-dev)"
fi

# ── Runtime tools ─────────────────────────────────────────────────────────────
section "Runtime Tools"

check_cmd ip     "iproute2 (ip)"   "iproute2"
check_cmd iptables "iptables"      "iptables"
check_cmd hping3 "hping3"          "hping3"
check_cmd vmstat "vmstat (sysstat)" "sysstat"

# Check kernel modules loadable
for mod in nf_conntrack nf_synproxy_core; do
    if modinfo "$mod" &>/dev/null 2>&1 || \
       grep -q "${mod^^}=y" "$CONFIG" 2>/dev/null; then
        ok "Kernel module: $mod"
    else
        warn "Kernel module $mod not found — may be built-in or named differently"
    fi
done

# ── BPF filesystem ────────────────────────────────────────────────────────────
section "BPF Filesystem"

if mount | grep -q "type bpf"; then
    ok "BPF filesystem mounted at /sys/fs/bpf"
else
    warn "BPF filesystem not mounted — mounting now..."
    if sudo mount -t bpf bpf /sys/fs/bpf/ 2>/dev/null; then
        ok "BPF filesystem mounted successfully"
    else
        fail "Could not mount BPF filesystem"
    fi
fi

# ── Python & Mininet ──────────────────────────────────────────────────────────
section "Python & Mininet (for emulated experiments)"

check_cmd python3 "Python 3" "python3"

PYTHON_VER=$(python3 --version 2>&1 | grep -oP '\d+\.\d+')
PYTHON_MAJOR=$(echo "$PYTHON_VER" | cut -d. -f1)
PYTHON_MINOR=$(echo "$PYTHON_VER" | cut -d. -f2)
if [ "$PYTHON_MAJOR" -ge 3 ] && [ "$PYTHON_MINOR" -ge 8 ]; then
    ok "Python $PYTHON_VER >= 3.8"
else
    warn "Python $PYTHON_VER detected — 3.8+ recommended"
fi

# Check Python packages
for pkg in mininet matplotlib scipy numpy; do
    if python3 -c "import $pkg" 2>/dev/null; then
        VER=$(python3 -c "import $pkg; print(getattr($pkg,'__version__','?'))" 2>/dev/null)
        ok "Python package: $pkg ($VER)"
    else
        fail "Python package '$pkg' not found (install: pip3 install $pkg)"
    fi
done

# Check Mininet executable
if command -v mn &>/dev/null; then
    MN_VER=$(mn --version 2>&1)
    ok "Mininet CLI (mn) — $MN_VER"
else
    fail "Mininet CLI 'mn' not found (install: sudo apt install mininet)"
fi

# Check Open vSwitch
if command -v ovs-vsctl &>/dev/null; then
    OVS_VER=$(ovs-vsctl --version 2>&1 | head -1)
    ok "Open vSwitch — $OVS_VER"
else
    fail "Open vSwitch not found (install: sudo apt install openvswitch-switch)"
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "────────────────────────────────────────────────────"
if [ $FAILED -eq 0 ] && [ $WARNINGS -eq 0 ]; then
    echo -e "${GREEN}✓ All requirements met. Ready to run experiments.${NC}"
elif [ $FAILED -eq 0 ]; then
    echo -e "${YELLOW}✓ Requirements met with $WARNINGS warning(s).${NC}"
    echo "  Warnings are non-blocking but may affect results."
else
    echo -e "${RED}✗ $FAILED requirement(s) missing, $WARNINGS warning(s).${NC}"
    echo "  Please install missing dependencies before proceeding."
fi
echo ""

exit $FAILED
