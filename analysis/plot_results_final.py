#!/usr/bin/env python3
"""
plot_results_final.py
=====================
Genera i tre grafici con error bar per il paper revisionato.
Usa i dati statistici (mean +/- std) dai 36 run completati.

Uso:
    python3 plot_results_final.py

Output (in /home/apirodd/results/):
    fig_success_rate.png / .pdf
    fig_latency.png      / .pdf
    fig_cpu.png          / .pdf
"""

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import numpy as np
import os

OUTPUT_DIR = '/home/apirodd/results'
os.makedirs(OUTPUT_DIR, exist_ok=True)

# ── Dati statistici (mean, std) dai 36 run ────────────────────────────────────
# Formato: data[scenario][config] = (succ_mean, succ_std, lat_mean, lat_std,
#                                    cpu_mean,  cpu_std)

data = {
    'single': {
        'none':     (1.000, 0.000, 0.0359, 0.0010, 66.7, 0.5),
        'xdp':      (1.000, 0.000, 0.0179, 0.0004, 43.8, 0.5),
        'iptables': (1.000, 0.000, 0.0544, 0.0005, 69.9, 0.9),
        'combined': (1.000, 0.000, 0.0247, 0.0003, 44.8, 0.3),
    },
    'distributed': {
        'none':     (0.944, 0.020, 0.2493, 0.0538, 98.2, 0.4),
        'xdp':      (0.958, 0.009, 0.1006, 0.0289, 58.8, 0.6),
        'iptables': (0.930, 0.021, 0.1803, 0.0701, 96.7, 0.6),
        'combined': (0.950, 0.008, 0.0380, 0.0391, 58.3, 0.8),
    },
    'spoofed': {
        'none':     (0.967, 0.009, 0.1495, 0.0284, 59.0, 0.2),
        'xdp':      (0.964, 0.005, 0.1427, 0.0307, 61.9, 0.1),
        'iptables': (0.947, 0.005, 0.0488, 0.0219, 59.8, 0.4),
        'combined': (0.955, 0.005, 0.0949, 0.0181, 62.8, 0.3),
    },
}

SCENARIOS     = ['single', 'distributed', 'spoofed']
SCENARIO_LABELS = ['Single-Source', 'Distributed', 'Spoofed']
CONFIGS       = ['none', 'xdp', 'iptables', 'combined']
CONFIG_LABELS = ['No Firewall', 'XDP-only', 'iptables+SYNPROXY', 'XDP+SYNPROXY']

# Palette IEEE-friendly (distinguishable anche in B&W con hatch)
COLORS  = ['#95a5a6', '#2980b9', '#e74c3c', '#27ae60']
HATCHES = ['', '///', '...', 'xxx']

x     = np.arange(len(SCENARIOS))
width = 0.19
offsets = [-1.5, -0.5, 0.5, 1.5]  # offset per 4 barre centrate

# ── Stile globale ─────────────────────────────────────────────────────────────
plt.rcParams.update({
    'font.family':     'serif',
    'font.size':       10,
    'axes.titlesize':  11,
    'axes.labelsize':  10,
    'legend.fontsize': 8.5,
    'xtick.labelsize': 10,
    'ytick.labelsize': 9,
    'figure.dpi':      150,
})

def save_fig(fig, name):
    for ext in ('png', 'pdf'):
        path = os.path.join(OUTPUT_DIR, f'{name}.{ext}')
        fig.savefig(path, dpi=300 if ext == 'pdf' else 150,
                    bbox_inches='tight')
    print(f'Salvato: {name}.png / .pdf')


def add_value_labels(ax, bars, values, fmt='{:.3f}', offset=0.002,
                     fontsize=7, color='black'):
    """Aggiunge etichette sopra le barre."""
    for bar, val in zip(bars, values):
        if val > 0:
            ax.text(
                bar.get_x() + bar.get_width() / 2,
                bar.get_height() + offset,
                fmt.format(val),
                ha='center', va='bottom',
                fontsize=fontsize, color=color,
                rotation=0
            )


# ── Figura 1: Success Rate ────────────────────────────────────────────────────
fig1, ax1 = plt.subplots(figsize=(8.5, 4.2))

for i, (cfg, lab, col, hat) in enumerate(
        zip(CONFIGS, CONFIG_LABELS, COLORS, HATCHES)):
    means  = [data[s][cfg][0] for s in SCENARIOS]
    stds   = [data[s][cfg][1] for s in SCENARIOS]
    bars = ax1.bar(
        x + offsets[i] * width, means, width,
        yerr=stds, capsize=3.5,
        label=lab, color=col, hatch=hat,
        edgecolor='white', linewidth=0.6,
        error_kw={'elinewidth': 1.2, 'ecolor': '#333333',
                  'capthick': 1.2}
    )
    # Etichette solo se il valore non è 1.000 (evita affollamento)
    for bar, m, s in zip(bars, means, stds):
        if m < 0.999:
            ax1.text(
                bar.get_x() + bar.get_width() / 2,
                bar.get_height() + s + 0.003,
                f'{m:.3f}',
                ha='center', va='bottom', fontsize=6.5
            )

ax1.set_ylabel('Success Rate', fontsize=11)
ax1.set_title(
    'Service Success Rate — Emulated Testbed\n'
    '(50 kpps, mean $\\pm$ std, 3 runs, $N=120$ per run)',
    fontsize=10
)
ax1.set_xticks(x)
ax1.set_xticklabels(SCENARIO_LABELS, fontsize=10)
ax1.set_ylim(0.88, 1.035)
ax1.axhline(1.0, color='gray', linestyle='--', linewidth=0.7, alpha=0.5)
ax1.legend(loc='lower left', framealpha=0.9, ncol=2)
ax1.grid(axis='y', alpha=0.3, linestyle=':')
ax1.spines['top'].set_visible(False)
ax1.spines['right'].set_visible(False)
plt.tight_layout()
save_fig(fig1, 'fig_success_rate')
plt.close(fig1)


# ── Figura 2: Latency ─────────────────────────────────────────────────────────
fig2, ax2 = plt.subplots(figsize=(8.5, 4.5))

for i, (cfg, lab, col, hat) in enumerate(
        zip(CONFIGS, CONFIG_LABELS, COLORS, HATCHES)):
    means = [data[s][cfg][2] for s in SCENARIOS]
    stds  = [data[s][cfg][3] for s in SCENARIOS]
    bars = ax2.bar(
        x + offsets[i] * width, means, width,
        yerr=stds, capsize=3.5,
        label=lab, color=col, hatch=hat,
        edgecolor='white', linewidth=0.6,
        error_kw={'elinewidth': 1.2, 'ecolor': '#333333',
                  'capthick': 1.2}
    )
    for bar, m in zip(bars, means):
        if m > 0.015:
            ax2.text(
                bar.get_x() + bar.get_width() / 2,
                bar.get_height() + 0.003,
                f'{m:.3f}',
                ha='center', va='bottom', fontsize=6.5
            )

ax2.set_ylabel('Average Latency (s)', fontsize=11)
ax2.set_title(
    'Average Latency — Emulated Testbed\n'
    '(50 kpps, mean $\\pm$ std, 3 runs, $N=120$ per run)',
    fontsize=10
)
ax2.set_xticks(x)
ax2.set_xticklabels(SCENARIO_LABELS, fontsize=10)
ax2.legend(loc='upper right', framealpha=0.9, ncol=2)
ax2.grid(axis='y', alpha=0.3, linestyle=':')
ax2.spines['top'].set_visible(False)
ax2.spines['right'].set_visible(False)

# Annotazione latency inversion
ax2.annotate(
    'Latency inversion:\niptables < XDP-only',
    xy=(2 + offsets[2] * width, data['spoofed']['iptables'][2]),
    xytext=(1.55, 0.20),
    fontsize=7.5, color='#c0392b',
    arrowprops=dict(arrowstyle='->', color='#c0392b', lw=1.2),
    ha='center'
)

plt.tight_layout()
save_fig(fig2, 'fig_latency')
plt.close(fig2)


# ── Figura 3: CPU ─────────────────────────────────────────────────────────────
fig3, ax3 = plt.subplots(figsize=(8.5, 4.5))

for i, (cfg, lab, col, hat) in enumerate(
        zip(CONFIGS, CONFIG_LABELS, COLORS, HATCHES)):
    means = [data[s][cfg][4] for s in SCENARIOS]
    stds  = [data[s][cfg][5] for s in SCENARIOS]
    bars = ax3.bar(
        x + offsets[i] * width, means, width,
        yerr=stds, capsize=3.5,
        label=lab, color=col, hatch=hat,
        edgecolor='white', linewidth=0.6,
        error_kw={'elinewidth': 1.2, 'ecolor': '#333333',
                  'capthick': 1.2}
    )
    for bar, m in zip(bars, means):
        ax3.text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height() + 0.8,
            f'{m:.0f}',
            ha='center', va='bottom', fontsize=6.5
        )

ax3.set_ylabel('CPU Utilization (%)', fontsize=11)
ax3.set_title(
    'CPU Utilization — Emulated Testbed\n'
    '(50 kpps, mean $\\pm$ std, 3 runs, $N=120$ per run)',
    fontsize=10
)
ax3.set_xticks(x)
ax3.set_xticklabels(SCENARIO_LABELS, fontsize=10)
ax3.set_ylim(0, 115)
ax3.axhline(100, color='red', linestyle='--', linewidth=0.8,
            alpha=0.6, label='100% saturation')
ax3.legend(loc='upper right', framealpha=0.9, ncol=2)
ax3.grid(axis='y', alpha=0.3, linestyle=':')
ax3.spines['top'].set_visible(False)
ax3.spines['right'].set_visible(False)

# Annotazione CPU saturation
ax3.annotate(
    'Near saturation\n(96.7%)',
    xy=(1 + offsets[2] * width, data['distributed']['iptables'][4]),
    xytext=(0.6, 108),
    fontsize=7.5, color='#c0392b',
    arrowprops=dict(arrowstyle='->', color='#c0392b', lw=1.2),
    ha='center'
)

plt.tight_layout()
save_fig(fig3, 'fig_cpu')
plt.close(fig3)

print('\nTutti i grafici generati in:', OUTPUT_DIR)
print('File prodotti:')
for f in sorted(os.listdir(OUTPUT_DIR)):
    if f.startswith('fig_'):
        print(f'  {f}')
