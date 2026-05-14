#!/usr/bin/env python3
"""
analyze_extended.py
====================
Analisi statistica completa dei risultati con 7 configurazioni.
Produce tabelle LaTeX, grafici con error bar, e report CSV.

Uso:
    python3 analyze_extended.py

Input:
    results_extended/*.csv   (generati da run_all_extended.sh)

Output:
    results_extended/summary_stats.csv      medie e std per configurazione
    results_extended/table_comparison.tex   tabella LaTeX confronto 7 config
    results_extended/fig_comparison_*.pdf/png  grafici comparativi
"""

import os
import csv
import glob
import statistics

# Matplotlib opzionale per i grafici
try:
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    import numpy as np
    HAS_MATPLOTLIB = True
except ImportError:
    HAS_MATPLOTLIB = False
    print("WARN: matplotlib non disponibile, grafici non generati.")
    print("      Installa con: pip3 install matplotlib numpy")

# ── Configurazione ─────────────────────────────────────────────────────────────
SCRIPT_DIR  = os.path.dirname(os.path.abspath(__file__))
RESULTS_DIR = os.path.join(SCRIPT_DIR, 'results_extended')
OUTPUT_DIR  = RESULTS_DIR

CONFIGS = ['none', 'syn-cookies', 'iptables-hl',
           'iptables', 'nftables', 'xdp', 'combined']

CONFIG_LABELS = {
    'none':         'No Firewall',
    'syn-cookies':  'SYN Cookies',
    'iptables-hl':  'iptables hashlimit',
    'iptables':     'iptables+SYNPROXY',
    'nftables':     'nftables+SYNPROXY',
    'xdp':          'XDP-only',
    'combined':     'XDP+SYNPROXY',
}

SCENARIOS = ['single', 'distributed', 'spoofed']
SCENARIO_LABELS = {
    'single':      'Single-Source',
    'distributed': 'Distributed',
    'spoofed':     'Spoofed',
}

ATK_COUNT = {'single': 1, 'distributed': 5, 'spoofed': 5}

# Colori e marker per i grafici
COLORS = {
    'none':        '#95a5a6',
    'syn-cookies': '#f39c12',
    'iptables-hl': '#8e44ad',
    'iptables':    '#e74c3c',
    'nftables':    '#e67e22',
    'xdp':         '#2980b9',
    'combined':    '#27ae60',
}
HATCHES = {
    'none':        '',
    'syn-cookies': '...',
    'iptables-hl': '\\\\',
    'iptables':    '---',
    'nftables':    '///',
    'xdp':         'xxx',
    'combined':    '+++',
}


def mean_std(values):
    if not values:
        return 0.0, 0.0
    m = statistics.mean(values)
    s = statistics.stdev(values) if len(values) > 1 else 0.0
    return m, s


# ── Carica dati CSV ────────────────────────────────────────────────────────────
print(f"Carico dati da: {RESULTS_DIR}")
raw = {}   # raw[(scenario, fw)] = [(succ, lat, cpu), ...]

pattern = os.path.join(RESULTS_DIR, '*.csv')
files   = sorted(glob.glob(pattern))

if not files:
    print(f"ERRORE: nessun file CSV trovato in {RESULTS_DIR}")
    print("Esegui prima: bash run_all_extended.sh")
    exit(1)

loaded = 0
skipped = 0
for filepath in files:
    fname = os.path.basename(filepath)
    try:
        with open(filepath) as f:
            line = f.read().strip()
        if not line:
            skipped += 1
            continue
        parts = line.split(',')
        if len(parts) < 9:
            skipped += 1
            continue
        fw       = parts[0]
        scenario = parts[1]
        # parts[2]=atk, parts[3]=rep
        succ = float(parts[4])
        lat  = float(parts[5])
        # parts[6]=std, parts[7]=N
        cpu  = float(parts[8])

        key = (scenario, fw)
        if key not in raw:
            raw[key] = []
        raw[key].append((succ, lat, cpu))
        loaded += 1
    except Exception as e:
        print(f"  WARN: {fname} — {e}")
        skipped += 1

print(f"  Caricati: {loaded} run validi, {skipped} saltati")

# ── Calcola statistiche ────────────────────────────────────────────────────────
stats = {}
for scenario in SCENARIOS:
    for fw in CONFIGS:
        key = (scenario, fw)
        runs = raw.get(key, [])
        if not runs:
            continue
        succs = [r[0] for r in runs]
        lats  = [r[1] for r in runs]
        cpus  = [r[2] for r in runs]
        sm, ss = mean_std(succs)
        lm, ls = mean_std(lats)
        cm, cs = mean_std(cpus)
        stats[key] = {
            'succ_mean': sm, 'succ_std': ss,
            'lat_mean':  lm, 'lat_std':  ls,
            'cpu_mean':  cm, 'cpu_std':  cs,
            'n_reps':    len(runs),
        }

# ── Stampa tabella a schermo ──────────────────────────────────────────────────
print('\n' + '='*90)
print(' RISULTATI STATISTICI — 7 CONFIGURAZIONI')
print('='*90)
hdr = (f"{'Scenario':<13} {'Config':<20} {'Succ':>8} {'±':>2} {'std':>6} "
       f"{'Lat(s)':>8} {'±':>2} {'std':>6} {'CPU%':>7} {'Reps':>5}")
print(hdr)
print('-'*90)

for scenario in SCENARIOS:
    for fw in CONFIGS:
        key = (scenario, fw)
        if key not in stats:
            print(f"{scenario:<13} {CONFIG_LABELS[fw]:<20} --- no data ---")
            continue
        s = stats[key]
        print(
            f"{scenario:<13} {CONFIG_LABELS[fw]:<20} "
            f"{s['succ_mean']:>8.3f} {'±':>2} {s['succ_std']:>6.3f} "
            f"{s['lat_mean']:>8.4f} {'±':>2} {s['lat_std']:>6.4f} "
            f"{s['cpu_mean']:>7.1f} {s['n_reps']:>5}"
        )

# ── Salva CSV statistiche ─────────────────────────────────────────────────────
csv_path = os.path.join(OUTPUT_DIR, 'summary_stats.csv')
with open(csv_path, 'w', newline='') as f:
    w = csv.writer(f)
    w.writerow(['scenario', 'config', 'n_reps',
                'succ_mean', 'succ_std',
                'lat_mean',  'lat_std',
                'cpu_mean',  'cpu_std'])
    for scenario in SCENARIOS:
        for fw in CONFIGS:
            key = (scenario, fw)
            if key not in stats:
                continue
            s = stats[key]
            w.writerow([
                scenario, fw, s['n_reps'],
                round(s['succ_mean'], 4), round(s['succ_std'], 4),
                round(s['lat_mean'],  4), round(s['lat_std'],  4),
                round(s['cpu_mean'],  1), round(s['cpu_std'],  1),
            ])
print(f"\nCSV statistiche salvato: {csv_path}")

# ── Genera tabelle LaTeX ──────────────────────────────────────────────────────
def fmt_pm(mean, std, dec=3):
    if mean == 0 and std == 0:
        return '---'
    fmt = f'{{:.{dec}f}}'
    return f'${fmt.format(mean)}{{\\pm}}{fmt.format(std)}$'

latex_lines = []
latex_lines.append('% Tabella comparativa 7 configurazioni')
latex_lines.append('% Generata da analyze_extended.py')
latex_lines.append('')

for scenario in SCENARIOS:
    slabel = SCENARIO_LABELS[scenario]
    atk    = ATK_COUNT[scenario]
    alabel = f'{atk} attacker{"s" if atk > 1 else ""}'

    latex_lines.append(f'\\begin{{table}}[h]')
    latex_lines.append(f'\\centering')
    latex_lines.append(
        f'\\caption{{Comparison of seven mitigation mechanisms: '
        f'{slabel} attack (50\\,kpps, {alabel}; '
        f'mean$\\pm$std, 3 runs, $N$=120/run)}}'
    )
    latex_lines.append(f'\\label{{tab:comp_{scenario}}}')
    latex_lines.append(f'\\footnotesize')
    latex_lines.append(f'\\setlength{{\\tabcolsep}}{{3pt}}')
    latex_lines.append(f'\\begin{{tabular}}{{|l|c|c|c|}}')
    latex_lines.append(f'\\hline')
    latex_lines.append(
        f'\\textbf{{Mechanism}} & '
        f'\\textbf{{Success}} & '
        f'\\textbf{{Latency (s)}} & '
        f'\\textbf{{CPU (\\%)}} \\\\'
    )
    latex_lines.append(f'\\hline')

    for fw in CONFIGS:
        key = (scenario, fw)
        lab = CONFIG_LABELS[fw]
        if key not in stats:
            latex_lines.append(f'{lab} & --- & --- & --- \\\\')
            continue
        s = stats[key]
        succ_s = fmt_pm(s['succ_mean'], s['succ_std'], 3)
        lat_s  = fmt_pm(s['lat_mean'],  s['lat_std'],  4)
        cpu_s  = fmt_pm(s['cpu_mean'],  s['cpu_std'],  1)
        latex_lines.append(f'{lab} & {succ_s} & {lat_s} & {cpu_s} \\\\')

    latex_lines.append(f'\\hline')
    latex_lines.append(f'\\end{{tabular}}')
    latex_lines.append(f'\\end{{table}}')
    latex_lines.append(f'')

tex_path = os.path.join(OUTPUT_DIR, 'table_comparison.tex')
with open(tex_path, 'w') as f:
    f.write('\n'.join(latex_lines))
print(f"Tabelle LaTeX salvate: {tex_path}")

# ── Grafici ────────────────────────────────────────────────────────────────────
if not HAS_MATPLOTLIB:
    print("\nGrafici non generati (matplotlib mancante).")
    exit(0)

plt.rcParams.update({
    'font.family':    'serif',
    'font.size':      9,
    'axes.titlesize': 10,
    'axes.labelsize': 9,
    'legend.fontsize': 7,
})

x      = np.arange(len(SCENARIOS))
n_cfg  = len(CONFIGS)
width  = 0.11
# Offset centrati per n_cfg barre
offsets = [(i - (n_cfg - 1) / 2) * width for i in range(n_cfg)]

scenario_labels = [SCENARIO_LABELS[s] for s in SCENARIOS]

for metric, ylabel, fname, dec, ymin, ymax in [
    ('succ', 'Success Rate',        'fig_comparison_success', 3, 0.88, 1.02),
    ('lat',  'Average Latency (s)', 'fig_comparison_latency', 4, None, None),
    ('cpu',  'CPU Utilization (%)', 'fig_comparison_cpu',     1, 0,    110),
]:
    fig, ax = plt.subplots(figsize=(11, 5))

    for i, fw in enumerate(CONFIGS):
        means, stds = [], []
        for scenario in SCENARIOS:
            key = (scenario, fw)
            if key in stats:
                means.append(stats[key][f'{metric}_mean'])
                stds.append( stats[key][f'{metric}_std'])
            else:
                means.append(0)
                stds.append(0)

        bars = ax.bar(
            x + offsets[i], means, width,
            yerr=stds, capsize=2.5,
            label=CONFIG_LABELS[fw],
            color=COLORS[fw],
            hatch=HATCHES[fw],
            edgecolor='white', linewidth=0.5,
            error_kw={'elinewidth': 1.0, 'ecolor': '#333',
                      'capthick': 1.0}
        )

        # Etichette valori (solo per success rate dove lo spazio lo permette)
        if metric == 'succ':
            for bar, m in zip(bars, means):
                if m > 0 and m < 0.999:
                    ax.text(
                        bar.get_x() + bar.get_width() / 2,
                        bar.get_height() + max(stds) * 0.1 + 0.002,
                        f'{m:.3f}',
                        ha='center', va='bottom', fontsize=6, rotation=90
                    )

    ax.set_ylabel(ylabel, fontsize=10)
    ax.set_title(
        f'{ylabel} — 7 Mitigation Mechanisms\n'
        f'(50 kpps, mean ± std, 3 runs, N=120/run)',
        fontsize=9
    )
    ax.set_xticks(x)
    ax.set_xticklabels(scenario_labels, fontsize=10)
    if ymin is not None:
        ax.set_ylim(ymin, ymax)
    if metric == 'cpu':
        ax.axhline(100, color='red', linestyle='--',
                   linewidth=0.8, alpha=0.5, label='100% saturation')
    ax.legend(loc='lower left', framealpha=0.9,
              ncol=2, fontsize=7)
    ax.grid(axis='y', alpha=0.3, linestyle=':')
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    plt.tight_layout()

    for ext in ('png', 'pdf'):
        path = os.path.join(OUTPUT_DIR, f'{fname}.{ext}')
        fig.savefig(path,
                    dpi=150 if ext == 'png' else 300,
                    bbox_inches='tight')
        print(f"Grafico salvato: {path}")
    plt.close(fig)

print('\nAnalisi completata.')
print(f'File in: {OUTPUT_DIR}')
