#!/usr/bin/env python3
"""
run_single_experiment.py
========================
Esegue un singolo esperimento Mininet con una configurazione firewall.
Misura HTTP success rate, latenza e CPU sul server.

Uso:
    sudo python3 run_single_experiment.py <fw> <scenario> <n_attackers> <rate> <duration>

Argomenti:
    fw          : none | syn-cookies | iptables-hl | iptables | nftables | xdp | combined
    scenario    : single | distributed | spoofed
    n_attackers : numero di host attacker (es. 1, 5)
    rate        : SYN pps totali (es. 50000)
    duration    : secondi per run (es. 60)

Configurazioni firewall:
    none          Baseline: solo tcp_syncookies kernel
    syn-cookies   SYN cookies esplicito + backlog tuning, nessuna regola firewall
    iptables-hl   iptables hashlimit per-IP (rate limiting senza SYNPROXY)
    iptables      iptables + SYNPROXY (configurazione originale paper)
    nftables      nftables + SYNPROXY (successore iptables)
    xdp           XDP-only rate limiting (xdp_firewall_adaptive.o)
    combined      XDP + iptables SYNPROXY

Output:
    /home/apirodd/last_result.txt   risultato CSV: succ,lat,std,N,cpu
    stdout                          progress e RESULT line

Dipendenze:
    - Mininet 2.3+, Open vSwitch
    - hping3, iptables, nftables (nft)
    - xdp_firewall_adaptive.o compilato nella stessa directory
    - Subnet 172.16.50.0/24 (server/client), 172.16.51.0/24 (attackers)
      NON deve essere in conflitto con la rete locale
"""

import sys
import os
import time
import subprocess
import statistics
import urllib.request

from mininet.net import Mininet
from mininet.node import OVSSwitch
from mininet.link import TCLink
from mininet.log import setLogLevel

# ── Costanti ──────────────────────────────────────────────────────────────────
BASE_DIR    = os.path.dirname(os.path.abspath(__file__))
XDP_OBJ     = os.path.join(BASE_DIR, 'xdp_firewall_adaptive.o')
RESULT_FILE = os.path.join(BASE_DIR, 'last_result.txt')
VMSTAT_LOG  = os.path.join(BASE_DIR, 'vmstat.log')

SERVER_IP   = '172.16.50.1'
CLIENT_IP   = '172.16.50.100'
ATK_NET     = '172.16.51'
HOST_IP     = '172.16.50.254'   # IP host per raggiungere Mininet via s1

# ── Argomenti ─────────────────────────────────────────────────────────────────
if len(sys.argv) < 6:
    print('Uso: sudo python3 run_single_experiment.py '
          '<fw> <scenario> <n_attackers> <rate> <duration>')
    print('fw: none | syn-cookies | iptables-hl | iptables | nftables | xdp | combined')
    sys.exit(1)

fw          = sys.argv[1]
scenario    = sys.argv[2]
n_attackers = int(sys.argv[3])
rate        = int(sys.argv[4])
duration    = int(sys.argv[5])
N_SAMPLES   = duration * 2      # 1 campione ogni 0.5s -> 120 con duration=60

VALID_FW = ('none', 'syn-cookies', 'iptables-hl',
            'iptables', 'nftables', 'xdp', 'combined')
if fw not in VALID_FW:
    print(f'Errore: fw deve essere uno di {VALID_FW}')
    sys.exit(1)

# ── Classe switch standalone (no controller esterno) ─────────────────────────
class StandaloneSwitch(OVSSwitch):
    def start(self, controllers):
        super().start([])

# ── Funzioni di configurazione firewall ───────────────────────────────────────

def setup_none(server):
    """Baseline: solo tcp_syncookies kernel attivo."""
    server.cmd('sysctl -w net.ipv4.tcp_syncookies=1 -q')

def setup_syn_cookies(server):
    """
    SYN cookies esplicito con tuning backlog.
    Nessuna regola firewall aggiuntiva.
    Differisce da 'none' per il tuning esplicito dei parametri kernel.
    """
    server.cmd('sysctl -w net.ipv4.tcp_syncookies=1 -q')
    server.cmd('sysctl -w net.core.somaxconn=32768 -q')
    server.cmd('sysctl -w net.ipv4.tcp_max_syn_backlog=32768 -q')
    server.cmd('sysctl -w net.ipv4.tcp_synack_retries=1 -q')

def setup_iptables_hashlimit(server):
    """
    iptables hashlimit: rate limiting per-IP senza validazione handshake.
    Soglia: 100 SYN/s per IP con burst 200 (equivalente a tau=200 in 2s).
    Differisce da iptables+SYNPROXY: non valida il handshake TCP.
    """
    server.cmd('sysctl -w net.ipv4.tcp_syncookies=1 -q')
    # DROP pacchetti SYN che superano la soglia per-IP
    server.cmd(
        'iptables -A INPUT -p tcp --syn '
        '-m hashlimit '
        '--hashlimit-name syn_rate_limit '
        '--hashlimit-above 100/second '
        '--hashlimit-burst 200 '
        '--hashlimit-mode srcip '
        '--hashlimit-srcmask 32 '
        '-j DROP'
    )
    # Accept SYN entro soglia
    server.cmd('iptables -A INPUT -p tcp --syn -j ACCEPT')

def setup_iptables_synproxy(server):
    """
    iptables + SYNPROXY: configurazione originale del paper.
    Valida il TCP handshake via SYN cookies prima di allocare stato.
    """
    server.cmd('modprobe nf_conntrack 2>/dev/null')
    server.cmd('modprobe nf_synproxy_core 2>/dev/null')
    server.cmd('sysctl -w net.ipv4.tcp_syncookies=1 -q')
    server.cmd('sysctl -w net.netfilter.nf_conntrack_tcp_loose=0 -q')
    server.cmd(
        'iptables -t raw -I PREROUTING -p tcp --syn -j CT --notrack'
    )
    server.cmd(
        'iptables -A INPUT -p tcp -m conntrack '
        '--ctstate UNTRACKED,INVALID -j SYNPROXY '
        '--sack-perm --timestamp --wscale 7 --mss 1460'
    )
    server.cmd(
        'iptables -A INPUT -m conntrack --ctstate INVALID -j DROP'
    )
    server.cmd(
        'iptables -A INPUT -m conntrack '
        '--ctstate ESTABLISHED,RELATED -j ACCEPT'
    )

def setup_nftables_synproxy(server):
    """
    nftables + SYNPROXY: successore ufficiale di iptables.
    SYNPROXY applicato solo al traffico attacker (172.16.51.0/24).
    Il client misuratore (172.16.50.254) bypassa SYNPROXY per evitare
    interferenze con la misura HTTP dall'host.
    """
    server.cmd('modprobe nf_conntrack 2>/dev/null')
    server.cmd('modprobe nf_synproxy_core 2>/dev/null')
    server.cmd('sysctl -w net.ipv4.tcp_syncookies=1 -q')
    server.cmd('sysctl -w net.ipv4.tcp_timestamps=1 -q')
    server.cmd('sysctl -w net.netfilter.nf_conntrack_tcp_loose=0 -q')
    server.cmd('nft flush ruleset 2>/dev/null')
    server.cmd('nft add table ip filter')
    # Prerouting: notrack SOLO traffico attacker (172.16.51.0/24)
    # Il client misuratore 172.16.50.254 NON viene notracked
    server.cmd(
        'nft add chain ip filter prerouting '
        '{ type filter hook prerouting priority raw\\; }'
    )
    server.cmd(
        'nft add rule ip filter prerouting '
        'ip saddr 172.16.51.0/24 tcp flags syn notrack'
    )
    # Input: policy accept, SYNPROXY solo su traffico attacker untracked
    server.cmd(
        'nft add chain ip filter input '
        '{ type filter hook input priority filter\\; policy accept\\; }'
    )
    server.cmd(
        'nft add rule ip filter input '
        'ip saddr 172.16.51.0/24 '
        'ct state { untracked, invalid } tcp flags syn '
        'synproxy mss 1460 wscale 7 timestamp sack-perm'
    )
    # Drop pacchetti invalid post-SYNPROXY
    server.cmd('nft add rule ip filter input ct state invalid drop')

def setup_xdp(server, iface='server-eth0'):
    """XDP-only rate limiting (xdpgeneric mode per interfacce virtuali)."""
    server.cmd('mount -t bpf bpf /sys/fs/bpf/ 2>/dev/null')
    server.cmd('mkdir -p /sys/fs/bpf/tc/globals 2>/dev/null')
    out = server.cmd(
        f'ip link set dev {iface} xdpgeneric obj {XDP_OBJ} sec xdp 2>&1'
    )
    if 'error' in out.lower():
        print(f'  WARN XDP: {out.strip()}', flush=True)

def setup_fw(server, fw_mode):
    """Configura il firewall sul server Mininet."""
    iface = 'server-eth0'
    # Reset completo prima di ogni configurazione
    server.cmd(f'ip link set dev {iface} xdpgeneric off 2>/dev/null')
    server.cmd('iptables -F 2>/dev/null')
    server.cmd('iptables -t raw -F 2>/dev/null')
    server.cmd('nft flush ruleset 2>/dev/null')

    if fw_mode == 'none':
        setup_none(server)

    elif fw_mode == 'syn-cookies':
        setup_syn_cookies(server)

    elif fw_mode == 'iptables-hl':
        setup_iptables_hashlimit(server)

    elif fw_mode == 'iptables':
        setup_iptables_synproxy(server)

    elif fw_mode == 'nftables':
        setup_nftables_synproxy(server)

    elif fw_mode == 'xdp':
        setup_xdp(server, iface)

    elif fw_mode == 'combined':
        setup_xdp(server, iface)
        setup_iptables_synproxy(server)

# ── Build topology ─────────────────────────────────────────────────────────────
try:
    os.remove(RESULT_FILE)
except FileNotFoundError:
    pass

setLogLevel('warning')

net = Mininet(switch=StandaloneSwitch, link=TCLink,
              controller=None, waitConnected=False)
s1 = net.addSwitch('s1', failMode='standalone')

attackers = []
for i in range(1, n_attackers + 1):
    a = net.addHost(f'a{i}', ip=f'{ATK_NET}.{i}/24')
    attackers.append(a)
    net.addLink(a, s1, bw=10, delay='1ms', loss=0)

server = net.addHost('server', ip=f'{SERVER_IP}/24')
net.addLink(server, s1, bw=10, delay='1ms', loss=0)

client = net.addHost('client', ip=f'{CLIENT_IP}/24')
net.addLink(client, s1, bw=10, delay='5ms', loss=0)

net.start()

# ── Rotte interne Mininet ─────────────────────────────────────────────────────
server.cmd(f'ip route add {ATK_NET}.0/24 dev server-eth0 2>/dev/null')
for a in attackers:
    a.cmd(f'ip route add 172.16.50.0/24 dev {a.name}-eth0 2>/dev/null')
client.cmd(f'ip route add {ATK_NET}.0/24 dev client-eth0 2>/dev/null')

# ── Rotta host -> Mininet via interfaccia OVS s1 ──────────────────────────────
subprocess.run(['ip', 'link', 'set', 's1', 'up'], capture_output=True)
subprocess.run(['ip', 'addr', 'del', f'{HOST_IP}/24', 'dev', 's1'],
               capture_output=True)
subprocess.run(['ip', 'addr', 'add', f'{HOST_IP}/24', 'dev', 's1'],
               capture_output=True)
time.sleep(1)

# ── Configura firewall ────────────────────────────────────────────────────────
setup_fw(server, fw)

# ── Avvia HTTP server sul nodo Mininet ────────────────────────────────────────
server.cmd('python3 -m http.server 80 &>/dev/null &')
time.sleep(2)

# ── Verifica raggiungibilità HTTP dall'host ───────────────────────────────────
try:
    urllib.request.urlopen(f'http://{SERVER_IP}:80/', timeout=4)
    print(f'HTTP OK | fw={fw} scenario={scenario} '
          f'n_atk={n_attackers} rate={rate} N={N_SAMPLES}', flush=True)
except Exception as e:
    print(f'HTTP FAIL: {e} — uscita', flush=True)
    net.stop()
    subprocess.run(['mn', '-c'], capture_output=True)
    subprocess.run(['ip', 'addr', 'del', f'{HOST_IP}/24', 'dev', 's1'],
                   capture_output=True)
    with open(RESULT_FILE, 'w') as f:
        f.write('0.000,0.0000,0.0000,0,0.0\n')
    sys.exit(1)

# ── vmstat sul server ─────────────────────────────────────────────────────────
server.cmd(f'vmstat 1 {duration + 10} > {VMSTAT_LOG} &')

# ── Lancia attacco ────────────────────────────────────────────────────────────
rate_per  = rate // n_attackers
pkt_count = rate_per * duration
active    = [attackers[0]] if scenario == 'single' else attackers

for a in active:
    if scenario == 'spoofed':
        a.cmd(f'hping3 -S -p 80 --rand-source --faster '
              f'-c {pkt_count} {SERVER_IP} &')
    else:
        a.cmd(f'hping3 -S -p 80 --faster '
              f'-c {pkt_count} {SERVER_IP} &')

# ── Loop misura HTTP (dall'host, numero fisso di campioni) ────────────────────
url     = f'http://{SERVER_IP}:80/'
results = []

for i in range(N_SAMPLES):
    t0 = time.time()
    try:
        urllib.request.urlopen(url, timeout=4)
        success = 1
    except Exception:
        success = 0
    results.append((success, time.time() - t0))

    if (i + 1) % 20 == 0:
        ok = sum(r[0] for r in results)
        print(f'  ... N={i+1} succ={ok/(i+1):.3f}', flush=True)

    time.sleep(0.5)

# ── Stop attaccanti e Mininet ─────────────────────────────────────────────────
for a in active:
    a.cmd('kill %hping3 2>/dev/null')

net.stop()
subprocess.run(['mn', '-c'], capture_output=True)
subprocess.run(['ip', 'addr', 'del', f'{HOST_IP}/24', 'dev', 's1'],
               capture_output=True)

# ── Calcola statistiche ───────────────────────────────────────────────────────
total   = len(results)
succ    = sum(r[0] for r in results)
lats    = [r[1] for r in results if r[0]]
avg_lat = statistics.mean(lats)  if lats       else 0.0
std_lat = statistics.stdev(lats) if len(lats) > 1 else 0.0
succ_r  = succ / total           if total > 0  else 0.0

# ── CPU media dal log vmstat ──────────────────────────────────────────────────
try:
    r2 = subprocess.run(
        ['awk', 'NR>2{sum+=(100-$15);n++}'
         'END{if(n>0)printf "%.1f",sum/n}',
         VMSTAT_LOG],
        capture_output=True, text=True
    )
    cpu = float(r2.stdout.strip().replace(',', '.'))
except Exception:
    cpu = 0.0

# ── Scrivi risultato ──────────────────────────────────────────────────────────
line = f'{succ_r:.3f},{avg_lat:.4f},{std_lat:.4f},{total},{cpu:.1f}'
with open(RESULT_FILE, 'w') as f:
    f.write(line + '\n')

print(f'RESULT: {line}', flush=True)
