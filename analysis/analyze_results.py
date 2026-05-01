#!/usr/bin/env python3
import os, csv, statistics, glob

RESULTS_DIR = '/home/apirodd/results'

# Carica tutti i file CSV
data = {}
for filepath in sorted(glob.glob(f'{RESULTS_DIR}/*.csv')):
    with open(filepath) as f:
        row = f.read().strip().split(',')
    if len(row) < 9:
        continue
    fw       = row[0]
    scenario = row[1]
    atk      = row[2]
    rep      = row[3]
    succ     = float(row[4])
    avg_lat  = float(row[5])
    std_lat  = float(row[6])
    n_req    = int(row[7])
    cpu      = float(row[8])

    key = (scenario, fw, atk)
    if key not in data:
        data[key] = []
    data[key].append((succ, avg_lat, cpu, n_req))

# Calcola statistiche
print('\n=== RISULTATI STATISTICI ===\n')
print(f'{"Scenario":<14} {"Config":<12} {"Atk":<5} '
      f'{"Succ mean":>10} {"±":>2} {"std":>6} '
      f'{"Lat mean":>10} {"±":>2} {"std":>6} '
      f'{"CPU mean":>9} {"±":>2} {"std":>5} '
      f'{"N":>5} {"Reps":>5}')
print('-' * 100)

scenarios = [('single','1'), ('distributed','5'), ('spoofed','5')]
configs   = ['none', 'xdp', 'iptables', 'combined']

latex_rows = {}
for scenario, atk in scenarios:
    for fw in configs:
        key = (scenario, fw, atk)
        if key not in data:
            print(f'{scenario:<14} {fw:<12} {atk:<5} --- no data ---')
            continue
        runs = data[key]
        succs = [r[0] for r in runs]
        lats  = [r[1] for r in runs]
        cpus  = [r[2] for r in runs]
        nreqs = [r[3] for r in runs]

        sm = statistics.mean(succs)
        ss = statistics.stdev(succs) if len(succs)>1 else 0
        lm = statistics.mean(lats)
        ls = statistics.stdev(lats) if len(lats)>1 else 0
        cm = statistics.mean(cpus)
        cs = statistics.stdev(cpus) if len(cpus)>1 else 0
        nm = int(statistics.mean(nreqs))

        print(f'{scenario:<14} {fw:<12} {atk:<5} '
              f'{sm:>10.3f} {"±":>2} {ss:>6.3f} '
              f'{lm:>10.4f} {"±":>2} {ls:>6.4f} '
              f'{cm:>9.1f} {"±":>2} {cs:>5.1f} '
              f'{nm:>5} {len(runs):>5}')

        latex_rows[key] = (sm, ss, lm, ls, cm, cs, nm, len(runs))

# Genera LaTeX
print('\n\n=== TABELLE LATEX ===\n')

scenario_labels = {
    'single':      ('Single-Source', '1 attacker'),
    'distributed': ('Distributed',   '5 attackers'),
    'spoofed':     ('Spoofed',       '5 attackers'),
}
config_labels = {
    'none':     'No Firewall',
    'xdp':      'XDP-only',
    'iptables': 'iptables+SYNPROXY',
    'combined': 'XDP+SYNPROXY',
}

for scenario, atk in scenarios:
    slabel, alabel = scenario_labels[scenario]
    print(f'\\begin{{table}}[h]')
    print(f'\\centering')
    print(f'\\caption{{Emulated testbed: {slabel} attack '
          f'(rate~=~50\\,kpps, {alabel}; '
          f'mean~$\\pm$~std over 3 runs; Latency in s, CPU in \\%)}}')
    print(f'\\label{{tab:{scenario}_emu_stats}}')
    print(f'\\small')
    print(f'\\begin{{tabular}}{{|l|r|r|r|r|}}')
    print(f'\\hline')
    print(f'\\textbf{{Config}} & \\textbf{{Success}} & '
          f'\\textbf{{Latency (s)}} & \\textbf{{CPU (\\%)}} & '
          f'\\textbf{{N}} \\\\')
    print(f'\\hline')

    for fw in configs:
        key = (scenario, fw, atk)
        lab = config_labels[fw]
        if key not in latex_rows:
            print(f'{lab} & --- & --- & --- & --- \\\\')
            continue
        sm,ss,lm,ls,cm,cs,nm,nr = latex_rows[key]
        succ_str = f'${sm:.3f} \\pm {ss:.3f}$'
        lat_str  = f'${lm:.4f} \\pm {ls:.4f}$'
        cpu_str  = f'${cm:.1f} \\pm {cs:.1f}$'
        print(f'{lab} & {succ_str} & {lat_str} & {cpu_str} & {nm} \\\\')

    print(f'\\hline')
    print(f'\\end{{tabular}}')
    print(f'\\end{{table}}')
    print()

# Salva LaTeX su file
latex_file = '/home/apirodd/results/table_latex.tex'
with open(latex_file, 'w') as f:
    f.write('% Tabelle generate automaticamente\n')
    for scenario, atk in scenarios:
        slabel, alabel = scenario_labels[scenario]
        f.write(f'\\begin{{table}}[h]\n\\centering\n')
        f.write(f'\\caption{{Emulated testbed: {slabel} attack '
                f'(rate~=~50\\,kpps, {alabel}; '
                f'mean~$\\pm$~std over 3 runs; Latency in s, CPU in \\%)}}\n')
        f.write(f'\\label{{tab:{scenario}_emu_stats}}\n\\small\n')
        f.write(f'\\begin{{tabular}}{{|l|r|r|r|r|}}\n\\hline\n')
        f.write(f'\\textbf{{Config}} & \\textbf{{Success}} & '
                f'\\textbf{{Latency (s)}} & \\textbf{{CPU (\\%)}} & '
                f'\\textbf{{N}} \\\\\n\\hline\n')
        for fw in configs:
            key = (scenario, fw, atk)
            lab = config_labels[fw]
            if key not in latex_rows:
                f.write(f'{lab} & --- & --- & --- & --- \\\\\n')
                continue
            sm,ss,lm,ls,cm,cs,nm,nr = latex_rows[key]
            f.write(f'{lab} & ${sm:.3f} \\pm {ss:.3f}$ & '
                    f'${lm:.4f} \\pm {ls:.4f}$ & '
                    f'${cm:.1f} \\pm {cs:.1f}$ & {nm} \\\\\n')
        f.write(f'\\hline\n\\end{{tabular}}\n\\end{{table}}\n\n')

print(f'Tabelle LaTeX salvate in: {latex_file}')
