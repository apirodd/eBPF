import sys, time, subprocess, statistics, urllib.request, os
from mininet.net import Mininet
from mininet.node import OVSSwitch
from mininet.link import TCLink
from mininet.log import setLogLevel

fw          = sys.argv[1]
scenario    = sys.argv[2]
n_attackers = int(sys.argv[3])
rate        = int(sys.argv[4])
duration    = int(sys.argv[5])
N_SAMPLES   = duration * 2

XDP_OBJ    = '/home/apirodd/xdp_firewall.o'
RESULT_FILE= '/home/apirodd/last_result.txt'
VMSTAT_LOG = '/home/apirodd/vmstat.log'
SERVER_IP  = '172.16.50.1'
ATK_NET    = '172.16.51'
HOST_IP    = '172.16.50.254'

class S(OVSSwitch):
    def start(self, c): super().start([])

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

def setup_fw(server, fw):
    server.cmd('ip link set dev server-eth0 xdpgeneric off 2>/dev/null')
    server.cmd('iptables -F 2>/dev/null; iptables -t raw -F 2>/dev/null')
    if fw in ('xdp', 'combined'):
        server.cmd('mount -t bpf bpf /sys/fs/bpf/ 2>/dev/null')
        server.cmd('mkdir -p /sys/fs/bpf/tc/globals 2>/dev/null')
        server.cmd(f'ip link set dev server-eth0 xdpgeneric '
                   f'obj {XDP_OBJ} sec xdp 2>/dev/null')
        if fw == 'combined':
            load_synproxy(server)
    elif fw == 'iptables':
        load_synproxy(server)

setLogLevel('warning')
net = Mininet(switch=S, link=TCLink, controller=None, waitConnected=False)
s1 = net.addSwitch('s1', failMode='standalone')
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
subprocess.run(['ip','addr','del',f'{HOST_IP}/24','dev','s1'], capture_output=True)
subprocess.run(['ip','addr','add',f'{HOST_IP}/24','dev','s1'], capture_output=True)
time.sleep(1)

setup_fw(server, fw)
server.cmd('python3 -m http.server 80 &>/dev/null &')
time.sleep(2)
server.cmd(f'vmstat 1 {duration+10} > {VMSTAT_LOG} &')

rate_per  = rate // n_attackers
pkt_count = rate_per * duration
active    = [attackers[0]] if scenario == 'single' else attackers
for a in active:
    if scenario == 'spoofed':
        a.cmd(f'hping3 -S -p 80 --rand-source --faster '
              f'-c {pkt_count} {SERVER_IP} &')
    else:
        a.cmd(f'hping3 -S -p 80 --faster -c {pkt_count} {SERVER_IP} &')

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
        print(f'N={i+1} succ={ok/(i+1):.3f}', flush=True)
    time.sleep(0.5)

for a in active:
    a.cmd('kill %hping3 2>/dev/null')
net.stop()
subprocess.run(['mn','-c'], capture_output=True)
subprocess.run(['ip','addr','del',f'{HOST_IP}/24','dev','s1'], capture_output=True)

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
print(f'RESULT: {line}', flush=True)
with open(RESULT_FILE,'w') as f:
    f.write(line+'\n')
