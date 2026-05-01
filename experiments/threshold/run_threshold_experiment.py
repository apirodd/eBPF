#!/usr/bin/env python3
import sys, os, time, subprocess, statistics, urllib.request
from mininet.net import Mininet
from mininet.node import OVSSwitch
from mininet.link import TCLink
from mininet.log import setLogLevel

XDP_OBJ     = '/home/apirodd/xdp_firewall_adaptive.o'
RESULT_FILE = '/home/apirodd/last_result.txt'
VMSTAT_LOG  = '/home/apirodd/vmstat.log'
SERVER_IP   = '172.16.50.1'
ATK_NET     = '172.16.51'
HOST_IP     = '172.16.50.254'
PIN_DIR     = '/sys/fs/bpf/xdp_thresh'

fw          = sys.argv[1]
scenario    = sys.argv[2]
n_attackers = int(sys.argv[3])
rate        = int(sys.argv[4])
duration    = int(sys.argv[5])
threshold   = int(sys.argv[6]) if len(sys.argv) > 6 else 200
N_SAMPLES   = duration * 2

class S(OVSSwitch):
    def start(self, c): super().start([])

def pin_maps_and_set_threshold(threshold_val):
    """Trova le map per nome e pinna, poi imposta soglia."""
    # Rimuovi pin precedenti
    subprocess.run(['rm', '-f',
                    f'{PIN_DIR}/config_map',
                    f'{PIN_DIR}/rate_map'],
                   capture_output=True)
    subprocess.run(['mkdir', '-p', PIN_DIR], capture_output=True)

    # Trova ID delle map appena caricate
    r = subprocess.run(['bpftool', 'map', 'list', '--json'],
                       capture_output=True, text=True)
    import json
    try:
        maps = json.loads(r.stdout)
    except Exception:
        print('WARN: bpftool map list fallito', flush=True)
        return False

    config_id = None
    rate_id   = None
    # Prendi gli ID più recenti (ultimi nella lista)
    for m in reversed(maps):
        if m.get('name') == 'config_map' and config_id is None:
            config_id = m['id']
        if m.get('name') == 'rate_map' and rate_id is None:
            rate_id = m['id']
        if config_id and rate_id:
            break

    if not config_id or not rate_id:
        print(f'WARN: map non trovate '
              f'(config={config_id} rate={rate_id})', flush=True)
        return False

    # Pinna
    subprocess.run(['bpftool', 'map', 'pin', 'id', str(config_id),
                    f'{PIN_DIR}/config_map'], capture_output=True)
    subprocess.run(['bpftool', 'map', 'pin', 'id', str(rate_id),
                    f'{PIN_DIR}/rate_map'], capture_output=True)

    # Imposta soglia
    b0 =  threshold_val        & 0xFF
    b1 = (threshold_val >>  8) & 0xFF
    b2 = (threshold_val >> 16) & 0xFF
    b3 = (threshold_val >> 24) & 0xFF
    r2 = subprocess.run(
        ['bpftool', 'map', 'update',
         'pinned', f'{PIN_DIR}/config_map',
         'key', '0', '0', '0', '0',
         'value', str(b0), str(b1), str(b2), str(b3)],
        capture_output=True, text=True
    )
    if r2.returncode == 0:
        print(f'Soglia impostata: {threshold_val} SYN/IP/2s', flush=True)
        return True
    else:
        print(f'WARN soglia: {r2.stderr.strip()}', flush=True)
        return False

def load_synproxy(server):
    server.cmd('modprobe nf_conntrack 2>/dev/null')
    server.cmd('modprobe nf_synproxy_core 2>/dev/null')
    server.cmd('sysctl -w net.ipv4.tcp_syncookies=1 -q')
    server.cmd('sysctl -w net.netfilter.nf_conntrack_tcp_loose=0 -q')
    server.cmd('iptables -t raw -I PREROUTING -p tcp --syn -j CT --notrack')
    server.cmd('iptables -A INPUT -p tcp -m conntrack '
               '--ctstate UNTRACKED,INVALID -j SYNPROXY '
               '--sack-perm --timestamp --wscale 7 --mss 1460')
    server.cmd('iptables -A INPUT -m conntrack --ctstate INVALID -j DROP')
    server.cmd('iptables -A INPUT -m conntrack '
               '--ctstate ESTABLISHED,RELATED -j ACCEPT')

def setup_fw(server, fw_mode):
    iface = 'server-eth0'
    server.cmd(f'ip link set dev {iface} xdpgeneric off 2>/dev/null')
    server.cmd('iptables -F 2>/dev/null; iptables -t raw -F 2>/dev/null')

    if fw_mode in ('xdp_t', 'combined_t'):
        server.cmd('mount -t bpf bpf /sys/fs/bpf/ 2>/dev/null')
        server.cmd('mkdir -p /sys/fs/bpf/tc/globals 2>/dev/null')
        out = server.cmd(
            f'ip link set dev {iface} xdpgeneric '
            f'obj {XDP_OBJ} sec xdp 2>&1'
        )
        if 'error' in out.lower():
            print(f'WARN XDP: {out.strip()}', flush=True)
        time.sleep(1)
        # Pinna map e imposta soglia dall'host
        pin_maps_and_set_threshold(threshold)

        if fw_mode == 'combined_t':
            load_synproxy(server)
    elif fw_mode == 'iptables':
        load_synproxy(server)

# ── Build topology ─────────────────────────────────────────────────────────────
try: os.remove(RESULT_FILE)
except: pass

setLogLevel('warning')
net = Mininet(switch=S, link=TCLink, controller=None, waitConnected=False)
s1  = net.addSwitch('s1', failMode='standalone')
attackers = []
for i in range(1, n_attackers + 1):
    a = net.addHost(f'a{i}', ip=f'{ATK_NET}.{i}/24')
    attackers.append(a)
    net.addLink(a, s1, bw=10, delay='1ms', loss=0)
server = net.addHost('server', ip=f'{SERVER_IP}/24')
net.addLink(server, s1, bw=10, delay='1ms', loss=0)
client = net.addHost('client', ip='172.16.50.100/24')
net.addLink(client, s1, bw=10, delay='5ms', loss=0)
net.start()

server.cmd(f'ip route add {ATK_NET}.0/24 dev server-eth0 2>/dev/null')
for a in attackers:
    a.cmd(f'ip route add 172.16.50.0/24 dev {a.name}-eth0 2>/dev/null')
client.cmd(f'ip route add {ATK_NET}.0/24 dev client-eth0 2>/dev/null')

subprocess.run(['ip','link','set','s1','up'], capture_output=True)
subprocess.run(['ip','addr','del',f'{HOST_IP}/24','dev','s1'],
               capture_output=True)
subprocess.run(['ip','addr','add',f'{HOST_IP}/24','dev','s1'],
               capture_output=True)
time.sleep(1)

setup_fw(server, fw)
server.cmd('python3 -m http.server 80 &>/dev/null &')
time.sleep(2)

# Verifica HTTP
try:
    urllib.request.urlopen(f'http://{SERVER_IP}:80/', timeout=4)
    print(f'HTTP OK | fw={fw} thr={threshold} '
          f'scenario={scenario} N={N_SAMPLES}', flush=True)
except Exception as e:
    print(f'HTTP FAIL: {e}', flush=True)
    net.stop()
    subprocess.run(['mn','-c'], capture_output=True)
    subprocess.run(['ip','addr','del',f'{HOST_IP}/24','dev','s1'],
                   capture_output=True)
    with open(RESULT_FILE,'w') as f:
        f.write('0.000,0.0000,0.0000,0,0.0\n')
    sys.exit(1)

server.cmd(f'vmstat 1 {duration+10} > {VMSTAT_LOG} &')

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

url     = f'http://{SERVER_IP}:80/'
results = []
for i in range(N_SAMPLES):
    t0 = time.time()
    try:
        urllib.request.urlopen(url, timeout=4)
        success = 1
    except Exception:
        success = 0
    results.append((success, time.time()-t0))
    if (i+1) % 20 == 0:
        ok = sum(r[0] for r in results)
        print(f'  N={i+1} succ={ok/(i+1):.3f}', flush=True)
    time.sleep(0.5)

for a in active:
    a.cmd('kill %hping3 2>/dev/null')
net.stop()
subprocess.run(['mn','-c'], capture_output=True)
subprocess.run(['ip','addr','del',f'{HOST_IP}/24','dev','s1'],
               capture_output=True)

total   = len(results)
succ    = sum(r[0] for r in results)
lats    = [r[1] for r in results if r[0]]
avg_lat = statistics.mean(lats)  if lats else 0.0
std_lat = statistics.stdev(lats) if len(lats) > 1 else 0.0
succ_r  = succ/total if total > 0 else 0.0

try:
    r2  = subprocess.run(
        ['awk','NR>2{sum+=(100-$15);n++}'
         'END{if(n>0)printf "%.1f",sum/n}', VMSTAT_LOG],
        capture_output=True, text=True)
    cpu = float(r2.stdout.strip().replace(',','.'))
except:
    cpu = 0.0

line = f'{succ_r:.3f},{avg_lat:.4f},{std_lat:.4f},{total},{cpu:.1f}'
with open(RESULT_FILE,'w') as f:
    f.write(line+'\n')
print(f'RESULT: {line}', flush=True)
