#!/usr/bin/env python3
import subprocess
import time
import psutil
import matplotlib.pyplot as plt
import pandas as pd

# Configurazione iptables
def setup_iptables():
    """Configura le regole iptables per il rate limiting SYN"""
    # Pulizia regole esistenti
    subprocess.run(["sudo", "iptables", "-F"], check=True)
    subprocess.run(["sudo", "iptables", "-X"], check=True)
    
    # Regola per rate limiting SYN
    subprocess.run([
        "sudo", "iptables", "-A", "INPUT", "-p", "tcp", "--syn",
        "-m", "limit", "--limit", "10/second", "--limit-burst", "10",
        "-j", "ACCEPT"
    ], check=True)
    
    # Drop per SYN oltre il limite
    subprocess.run([
        "sudo", "iptables", "-A", "INPUT", "-p", "tcp", "--syn",
        "-j", "DROP"
    ], check=True)
    
    # Accetta tutto il resto (per mantenere la connettività)
    subprocess.run(["sudo", "iptables", "-A", "INPUT", "-j", "ACCEPT"], check=True)

def cleanup_iptables():
    """Ripulisce le regole iptables"""
    subprocess.run(["sudo", "iptables", "-F"], check=True)
    subprocess.run(["sudo", "iptables", "-X"], check=True)

# Monitoraggio statistiche iptables
def get_iptables_stats():
    """Legge le statistiche dalle regole iptables"""
    try:
        # Conta SYN accettati
        result_accept = subprocess.run([
            "sudo", "iptables", "-L", "INPUT", "-v", "-n", "-x"
        ], capture_output=True, text=True, check=True)
        
        # Conta SYN droppati
        result_drop = subprocess.run([
            "sudo", "iptables", "-L", "INPUT", "-v", "-n", "-x"
        ], capture_output=True, text=True, check=True)
        
        # Parsing output (semplificato)
        lines = result_accept.stdout.split('\n')
        syn_accept = 0
        syn_drop = 0
        
        for line in lines:
            if "limit" in line and "ACCEPT" in line and "tcp" in line:
                parts = line.split()
                if len(parts) > 1:
                    syn_accept = int(parts[1])
            elif "SYN" in line and "DROP" in line:
                parts = line.split()
                if len(parts) > 1:
                    syn_drop = int(parts[1])
        
        return syn_accept, syn_drop
        
    except subprocess.CalledProcessError:
        return 0, 0

# Main monitoring
def monitor_iptables():
    timestamps = []
    syn_accepts = []
    syn_drops = []
    cpu_usages = []
    pps_rates = []
    
    prev_accept = 0
    prev_drop = 0
    start_time = time.time()
    
    try:
        print("Monitoring iptables firewall... Ctrl-C to stop")
        
        while True:
            time.sleep(1)
            now = time.time() - start_time
            
            # CPU usage
            cpu_usage = psutil.cpu_percent(interval=None)
            
            # Get statistics
            syn_accept, syn_drop = get_iptables_stats()
            total_syn = syn_accept + syn_drop
            
            # Calculate PPS
            delta_accept = syn_accept - prev_accept
            delta_drop = syn_drop - prev_drop
            pps = delta_accept + delta_drop
            
            prev_accept = syn_accept
            prev_drop = syn_drop
            
            # Store data
            timestamps.append(now)
            syn_accepts.append(syn_accept)
            syn_drops.append(syn_drop)
            cpu_usages.append(cpu_usage)
            pps_rates.append(pps)
            
            print(f"Time: {now:.1f}s | SYN Accept: {syn_accept} | SYN Drop: {syn_drop} | CPU: {cpu_usage}% | PPS: {pps}")
            
    except KeyboardInterrupt:
        print("\nStopping monitoring...")
        
        # Final statistics
        total_syn = syn_accepts[-1] + syn_drops[-1] if syn_accepts and syn_drops else 0
        success_rate = (syn_accepts[-1] / total_syn * 100) if total_syn > 0 else 0
        
        df = pd.DataFrame({
            "Metric": ["SYN Total", "SYN Blocked", "SYN Accepted", "Success Rate (%)", "Avg CPU (%)", "Avg PPS"],
            "Value": [total_syn, syn_drops[-1], syn_accepts[-1], success_rate,
                     sum(cpu_usages)/len(cpu_usages) if cpu_usages else 0,
                     sum(pps_rates)/len(pps_rates) if pps_rates else 0]
        })
        
        print("\n=== iptables-only Results ===")
        print(df.to_string(index=False))
        
        # Plots
        plt.figure()
        plt.plot(timestamps, [a+d for a,d in zip(syn_accepts, syn_drops)], label="SYN Total")
        plt.plot(timestamps, syn_drops, label="SYN Blocked")
        plt.xlabel("Time (s)")
        plt.ylabel("Count")
        plt.title("iptables-only: SYN Packets Over Time")
        plt.legend()
        plt.savefig("iptables_syn_over_time.png")
        
        plt.figure()
        plt.plot(timestamps, cpu_usages, label="CPU Usage (%)")
        plt.xlabel("Time (s)")
        plt.ylabel("CPU %")
        plt.title("iptables-only: CPU Usage Over Time")
        plt.legend()
        plt.savefig("iptables_cpu_usage.png")
        
        plt.figure()
        plt.plot(timestamps, pps_rates, label="Packets/s")
        plt.xlabel("Time (s)")
        plt.ylabel("PPS")
        plt.title("iptables-only: Throughput (SYN/sec)")
        plt.legend()
        plt.savefig("iptables_throughput.png")
        
        plt.show()

if __name__ == "__main__":
    try:
        setup_iptables()
        monitor_iptables()
    finally:
        cleanup_iptables()