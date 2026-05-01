# Makefile — eBPF SYN Flood Firewall
# Compiles XDP/eBPF programs using clang/llvm.
#
# Usage:
#   make              — build both XDP programs
#   make fixed        — build fixed-threshold version only
#   make adaptive     — build runtime-configurable version only
#   make clean        — remove compiled objects
#   make verify       — verify compiled objects with bpftool
#   make install      — load XDP on IFACE (default: eth0, override with IFACE=)
#   make uninstall    — remove XDP from IFACE
#
# Examples:
#   make
#   make install IFACE=eth0
#   make install IFACE=ens3 MODE=xdpgeneric

# ── Configuration ─────────────────────────────────────────────────────────────
CC      := clang
ARCH    := $(shell uname -m)
INCLUDE := /usr/include/$(ARCH)-linux-gnu

CFLAGS  := -O2 -g -target bpf -I$(INCLUDE)

IFACE   ?= eth0
MODE    ?= xdpgeneric   # xdpgeneric (virtual/compat) or xdp (native)

# ── Targets ───────────────────────────────────────────────────────────────────
.PHONY: all fixed adaptive clean verify install uninstall help

all: fixed adaptive

fixed: xdp_firewall.o

adaptive: xdp_firewall_adaptive.o

xdp_firewall.o: xdp_firewall.c
	@echo "[CC]  Compiling $< -> $@"
	$(CC) $(CFLAGS) -c $< -o $@
	@echo "[OK]  $@ compiled successfully"

xdp_firewall_adaptive.o: xdp_firewall_adaptive.c
	@echo "[CC]  Compiling $< -> $@"
	$(CC) $(CFLAGS) -c $< -o $@
	@echo "[OK]  $@ compiled successfully"

clean:
	@echo "[RM]  Removing compiled objects..."
	rm -f xdp_firewall.o xdp_firewall_adaptive.o
	@echo "[OK]  Clean complete"

verify: xdp_firewall.o xdp_firewall_adaptive.o
	@echo "[VFY] Verifying xdp_firewall.o..."
	sudo bpftool prog load xdp_firewall.o /sys/fs/bpf/xdp_verify_test
	sudo rm -f /sys/fs/bpf/xdp_verify_test
	@echo "[OK]  xdp_firewall.o is valid"
	@echo "[VFY] Verifying xdp_firewall_adaptive.o..."
	sudo bpftool prog load xdp_firewall_adaptive.o /sys/fs/bpf/xdp_verify_test
	sudo rm -f /sys/fs/bpf/xdp_verify_test
	@echo "[OK]  xdp_firewall_adaptive.o is valid"

install: xdp_firewall.o
	@echo "[LOAD] Loading XDP (fixed threshold) on $(IFACE) [mode=$(MODE)]..."
	sudo ip link set dev $(IFACE) $(MODE) obj xdp_firewall.o sec xdp
	@echo "[OK]  XDP loaded on $(IFACE)"
	@ip link show $(IFACE) | grep -E "xdp|state"

install-adaptive: xdp_firewall_adaptive.o
	@echo "[LOAD] Loading XDP (adaptive threshold) on $(IFACE) [mode=$(MODE)]..."
	sudo ip link set dev $(IFACE) $(MODE) obj xdp_firewall_adaptive.o sec xdp
	@echo "[OK]  XDP adaptive loaded on $(IFACE)"
	@echo "      Set threshold with: sudo bash ../scripts/set_threshold.sh <value>"

uninstall:
	@echo "[RM]  Removing XDP from $(IFACE)..."
	sudo ip link set dev $(IFACE) $(MODE) off 2>/dev/null || \
	sudo ip link set dev $(IFACE) xdp off 2>/dev/null || \
	echo "      No XDP program found on $(IFACE)"
	@echo "[OK]  XDP removed from $(IFACE)"

help:
	@echo ""
	@echo "eBPF SYN Flood Firewall — Build System"
	@echo "======================================="
	@echo ""
	@echo "Targets:"
	@echo "  make              Build both XDP programs"
	@echo "  make fixed        Build xdp_firewall.o (fixed threshold τ=200)"
	@echo "  make adaptive     Build xdp_firewall_adaptive.o (runtime-configurable τ)"
	@echo "  make clean        Remove compiled .o files"
	@echo "  make verify       Verify .o files with bpftool (requires root)"
	@echo "  make install      Load xdp_firewall.o on IFACE (requires root)"
	@echo "  make install-adaptive  Load adaptive version on IFACE (requires root)"
	@echo "  make uninstall    Remove XDP from IFACE (requires root)"
	@echo ""
	@echo "Variables:"
	@echo "  IFACE=<iface>   Network interface (default: eth0)"
	@echo "  MODE=<mode>     XDP mode: xdpgeneric (default) or xdp (native)"
	@echo ""
	@echo "Examples:"
	@echo "  make"
	@echo "  make install IFACE=ens3"
	@echo "  make install IFACE=eth0 MODE=xdp"
	@echo "  make install-adaptive IFACE=eth0"
	@echo "  make uninstall IFACE=eth0"
	@echo ""
	@echo "Requirements:"
	@echo "  clang, llvm, libbpf-dev, linux-headers-\$$(uname -r)"
	@echo "  Run: bash ../scripts/check_requirements.sh"
	@echo ""
