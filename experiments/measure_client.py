#!/usr/bin/env python3
import sys, time, urllib.request, csv, statistics

host     = sys.argv[1]
port     = int(sys.argv[2])
duration = int(sys.argv[3])
outfile  = sys.argv[4] if len(sys.argv) > 4 else '/home/apirodd/client_out.txt'

url      = f'http://{host}:{port}/'
end_time = time.time() + duration
results  = []

while time.time() < end_time:
    t0 = time.time()
    try:
        urllib.request.urlopen(url, timeout=5)
        success = 1
    except Exception:
        success = 0
    latency = time.time() - t0
    results.append((success, latency))
    time.sleep(0.5)

csvfile = outfile.replace('.txt', '.csv')
with open(csvfile, 'w', newline='') as f:
    w = csv.writer(f)
    w.writerow(['success', 'latency_s'])
    w.writerows(results)

total   = len(results)
succ    = sum(r[0] for r in results)
lats    = [r[1] for r in results if r[0]]
avg_lat = statistics.mean(lats) if lats else 0.0
std_lat = statistics.stdev(lats) if len(lats) > 1 else 0.0

summary = (f"Success: {succ/total:.3f} | "
           f"AvgLat: {avg_lat:.4f} | "
           f"StdLat: {std_lat:.4f} | "
           f"N: {total}")

with open(outfile, 'w') as f:
    f.write(summary + '\n')

print(summary)
