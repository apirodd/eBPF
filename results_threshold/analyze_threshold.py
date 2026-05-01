#!/usr/bin/env python3
"""
Analisi risultati threshold — Step 3
Produce tabella LaTeX e grafici threshold vs performance.
"""
import os, csv, glob, statistics
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np

RESULTS_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DIR  = RESULTS_DIR


THRESHOLDS  = [50, 100, 200, 500]
SCENARIOS   = ['single', 'spoofed']
FWS         = ['xdp_t', 'combined_t']
FW_LABELS   = {'xdp_t': 'XDP-only', 'combined_t': 'XDP+SYNPROXY'}
COLORS      = {'xdp_t': '#2980b9', 'combined_t': '#27ae60'}
MARKERS     = {'xdp_t': 'o', 'combined_t': 's'}

# Carica dati
data = {}
for filepath in sorted(glob.glob(f'{RESULTS_DIR}/*.csv')):
    with open(filepath) as f:
        row = f.read().strip().split(',')
    if len(row) < 10:
        continue
    fw      = row[0]
    scenario= row[1]
    thr     = int(row[3])
    rep     = row[4]
    succ    = float(row[5])
    lat     = float(row[6])
    cpu     = float(row[9])

    key = (scenario, fw, thr)
    if key not in data:
        data[key] = []
    data[key].append((succ, lat, cpu))

# Calcola statistiche
stats = {}
for key, runs in data.items():
    succs = [r[0] for r in runs]
    lats  = [r[1] for r in runs]
    cpus  = [r[2] for r in runs]
    stats[key] = {
        'succ_mean': statistics.mean(succs),
        'succ_std':  statistics.stdev(succs) if len(succs)>1 else 0,
        'lat_mean':  statistics.mean(lats),
        'lat_std':   statistics.stdev(lats) if len(lats)>1 else 0,
        'cpu_mean':  statistics.mean(cpus),
        'cpu_std':   statistics.stdev(cpus) if len(cpus)>1 else 0,
        'n_reps':    len(runs),
    }

# ── Stampa tabella ────────────────────────────────────────────────────────────
print('\n=== RISULTATI THRESHOLD ===\n')
print(f'{"Scenario":<12} {"FW":<12} {"Thr":>5} '
      f'{"Succ":>8} {"±":>2} {"std":>6} '
      f'{"Lat(s)":>8} {"±":>2} {"std":>6} '
      f'{"CPU%":>7} {"Reps":>5}')
print('-'*80)

for scenario in SCENARIOS:
    for fw in FWS:
        if fw == 'combined_t' and scenario == 'single':
            continue
        for thr in THRESHOLDS:
            key = (scenario, fw, thr)
            if key not in stats:
                print(f'{scenario:<12} {fw:<12} {thr:>5} --- no data ---')
                continue
            s = stats[key]
            print(f'{scenario:<12} {FW_LABELS[fw]:<12} {thr:>5} '
                  f'{s["succ_mean"]:>8.3f} {"±":>2} {s["succ_std"]:>6.3f} '
                  f'{s["lat_mean"]:>8.4f} {"±":>2} {s["lat_std"]:>6.4f} '
                  f'{s["cpu_mean"]:>7.1f} {s["n_reps"]:>5}')

# ── Grafici ───────────────────────────────────────────────────────────────────
plt.rcParams.update({
    'font.family': 'serif', 'font.size': 10,
    'axes.titlesize': 11, 'axes.labelsize': 10,
    'legend.fontsize': 9,
})

fig, axes = plt.subplots(2, 3, figsize=(12, 7))
fig.suptitle('XDP Rate Limiting: Threshold vs Performance\n'
             '(50 kpps, mean ± std, 3 runs, N=120 per run)',
             fontsize=11)

metrics = [
    ('succ_mean', 'succ_std', 'Success Rate', 0, 1.05),
    ('lat_mean',  'lat_std',  'Avg Latency (s)', None, None),
    ('cpu_mean',  'cpu_std',  'CPU (%)', 0, 105),
]

for row_idx, scenario in enumerate(SCENARIOS):
    for col_idx, (mean_key, std_key, ylabel, ymin, ymax) in \
            enumerate(metrics):
        ax = axes[row_idx][col_idx]

        for fw in FWS:
            if fw == 'combined_t' and scenario == 'single':
                continue
            means, stds = [], []
            for thr in THRESHOLDS:
                key = (scenario, fw, thr)
                if key in stats:
                    means.append(stats[key][mean_key])
                    stds.append(stats[key][std_key])
                else:
                    means.append(0)
                    stds.append(0)

            ax.errorbar(
                THRESHOLDS, means, yerr=stds,
                label=FW_LABELS[fw],
                color=COLORS[fw],
                marker=MARKERS[fw],
                linewidth=1.8, markersize=6,
                capsize=4, capthick=1.2,
                elinewidth=1.2
            )

        ax.set_xlabel('Threshold (SYN/IP/2s)')
        ax.set_ylabel(ylabel)
        ax.set_title(f'{scenario.capitalize()} — {ylabel}')
        ax.set_xticks(THRESHOLDS)
        ax.grid(alpha=0.3, linestyle=':')
        ax.spines['top'].set_visible(False)
        ax.spines['right'].set_visible(False)
        if ymin is not None:
            ax.set_ylim(ymin, ymax)
        if col_idx == 0:
            ax.legend()

plt.tight_layout()
for ext in ('png', 'pdf'):
    path = os.path.join(OUTPUT_DIR, f'fig_threshold.{ext}')
    plt.savefig(path, dpi=300 if ext=='pdf' else 150,
                bbox_inches='tight')
    print(f'Salvato: {path}')
plt.close()

# ── Tabella LaTeX ─────────────────────────────────────────────────────────────
print('\n=== TABELLA LATEX ===\n')
latex = []
latex.append('\\begin{table}[h]')
latex.append('\\centering')
latex.append('\\caption{Effect of XDP rate limiting threshold on service')
latex.append('availability and latency (50\\,kpps, mean$\\pm$std, 3 runs,')
latex.append('$N$=120/run; Thr = SYN/IP per 2\\,s window)}')
latex.append('\\label{tab:threshold}')
latex.append('\\footnotesize')
latex.append('\\setlength{\\tabcolsep}{3pt}')
latex.append('\\begin{tabular}{|l|c|c|c|c|}')
latex.append('\\hline')
latex.append('\\textbf{Config} & \\textbf{Thr} & '
             '\\textbf{Success} & \\textbf{Lat.\\ (s)} & '
             '\\textbf{CPU (\\%)} \\\\')
latex.append('\\hline')

for scenario in SCENARIOS:
    latex.append(f'\\multicolumn{{5}}{{|l|}}'
                 f'{{\\textit{{{scenario.capitalize()}}}}} \\\\')
    latex.append('\\hline')
    for fw in FWS:
        if fw == 'combined_t' and scenario == 'single':
            continue
        for thr in THRESHOLDS:
            key = (scenario, fw, thr)
            lab = FW_LABELS[fw]
            if key not in stats:
                latex.append(f'{lab} & {thr} & --- & --- & --- \\\\')
                continue
            s = stats[key]
            succ_s = f'${s["succ_mean"]:.3f}{{\\pm}}{s["succ_std"]:.3f}$'
            lat_s  = f'${s["lat_mean"]:.4f}{{\\pm}}{s["lat_std"]:.4f}$'
            cpu_s  = f'${s["cpu_mean"]:.1f}{{\\pm}}{s["cpu_std"]:.1f}$'
            latex.append(f'{lab} & {thr} & {succ_s} & {lat_s} & {cpu_s} \\\\')
    latex.append('\\hline')

latex.append('\\end{tabular}')
latex.append('\\end{table}')

result = '\n'.join(latex)
print(result)

latex_path = os.path.join(OUTPUT_DIR, 'table_threshold.tex')
with open(latex_path, 'w') as f:
    f.write(result)
print(f'\nTabella salvata: {latex_path}')
