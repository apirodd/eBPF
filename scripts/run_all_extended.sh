#!/bin/bash
# run_all_extended.sh
# ====================
# Matrice completa: 7 configurazioni × 3 scenari × 3 ripetizioni = 63 run
#
# Configurazioni:
#   none          Baseline (tcp_syncookies kernel)
#   syn-cookies   SYN cookies esplicito + backlog tuning
#   iptables-hl   iptables hashlimit per-IP
#   iptables      iptables + SYNPROXY (originale paper)
#   nftables      nftables + SYNPROXY
#   xdp           XDP-only
#   combined      XDP + iptables SYNPROXY
#
# Scenari:
#   single        1 attacker, IP fisso
#   distributed   5 attackers, IP fissi diversi
#   spoofed       5 attackers, IP casuali (--rand-source)
#
# Uso:
#   sudo mn -c 2>/dev/null
#   bash /home/apirodd/run_all_extended.sh 2>&1 | tee /home/apirodd/run_extended.log
#
# Output:
#   /home/apirodd/results_extended/   un CSV per ogni run
#   /home/apirodd/run_extended.log    log completo

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RATE=50000
DURATION=60
REPS=3
RESULTS_DIR="${SCRIPT_DIR}/results_extended"
EXPERIMENT_SCRIPT="${SCRIPT_DIR}/run_single_experiment.py"

mkdir -p "$RESULTS_DIR"

# ── Configurazioni e scenari ──────────────────────────────────────────────────
CONFIGS=(none syn-cookies iptables-hl iptables nftables xdp combined)
SCENARIOS=(single distributed spoofed)

declare -A ATK_COUNT
ATK_COUNT[single]=1
ATK_COUNT[distributed]=5
ATK_COUNT[spoofed]=5

# ── Calcola totale run ────────────────────────────────────────────────────────
TOTAL=$(( ${#CONFIGS[@]} * ${#SCENARIOS[@]} * REPS ))
ETA_MIN=$(( TOTAL * 80 / 60 ))

echo "================================================================"
echo " run_all_extended.sh — Matrice esperimenti estesa"
echo "================================================================"
echo " Configurazioni : ${CONFIGS[*]}"
echo " Scenari        : ${SCENARIOS[*]}"
echo " Ripetizioni    : $REPS"
echo " Run totali     : $TOTAL"
echo " Rate           : $RATE pps"
echo " Durata/run     : ${DURATION}s"
echo " Tempo stimato  : ~${ETA_MIN} minuti"
echo " Output dir     : $RESULTS_DIR"
echo "================================================================"
echo ""

# ── Verifica prerequisiti ─────────────────────────────────────────────────────
if [ ! -f "$EXPERIMENT_SCRIPT" ]; then
    echo "ERRORE: $EXPERIMENT_SCRIPT non trovato."
    exit 1
fi

XDP_OBJ="${SCRIPT_DIR}/xdp_firewall_adaptive.o"
if [ ! -f "$XDP_OBJ" ]; then
    echo "ERRORE: $XDP_OBJ non trovato. Compila prima con:"
    echo "  clang -O2 -g -target bpf -I/usr/include/\$(uname -m)-linux-gnu \\"
    echo "    -c xdp_firewall.c -o xdp_firewall_adaptive.o"
    exit 1
fi

if ! command -v nft &>/dev/null; then
    echo "ERRORE: nftables (nft) non trovato. Installa con:"
    echo "  sudo apt install nftables"
    exit 1
fi

echo "[OK] Prerequisiti verificati."
echo ""

# ── Funzione singolo run ──────────────────────────────────────────────────────
run_one() {
    local fw=$1
    local scenario=$2
    local atk=$3
    local rep=$4
    local count=$5

    local outfile="${RESULTS_DIR}/${scenario}_${fw}_a${atk}_r${rep}.csv"

    # Salta se già esiste (utile per riprendere dopo interruzione)
    if [ -f "$outfile" ]; then
        local existing
        existing=$(cat "$outfile" 2>/dev/null)
        if [[ "$existing" != *"0.000,0.0000"* ]]; then
            echo ">>> [$count/$TOTAL] SKIP (già presente): fw=$fw scenario=$scenario rep=$rep"
            echo "    -> $existing"
            return 0
        fi
    fi

    echo ""
    echo ">>> [$count/$TOTAL] fw=$fw scenario=$scenario atk=$atk rep=$rep"
    echo "    $(date '+%H:%M:%S')"

    # Pulizia Mininet
    sudo mn -c 2>/dev/null || true
    sleep 3

    # Esegui esperimento
    sudo python3 "$EXPERIMENT_SCRIPT" \
        "$fw" "$scenario" "$atk" "$RATE" "$DURATION"

    # Leggi risultato
    local result
    result=$(cat /home/apirodd/last_result.txt 2>/dev/null || echo "0.000,0.0000,0.0000,0,0.0")

    # Salva CSV
    echo "$fw,$scenario,$atk,$rep,$result" > "$outfile"
    echo "    -> $result"
    echo "    -> Salvato: $outfile"

    # Pausa tra run per lasciare stabilizzare il sistema
    sleep 8
}

# ── Esecuzione matrice ────────────────────────────────────────────────────────
COUNT=0
FAILED=0
START_TIME=$(date +%s)

for cfg in "${CONFIGS[@]}"; do
    for scenario in "${SCENARIOS[@]}"; do
        ATK=${ATK_COUNT[$scenario]}
        for rep in $(seq 1 $REPS); do
            COUNT=$((COUNT + 1))
            run_one "$cfg" "$scenario" "$ATK" "$rep" "$COUNT" \
                || { FAILED=$((FAILED + 1)); echo "    WARN: run fallito, continuo"; }
        done
    done
done

# ── Riepilogo finale ──────────────────────────────────────────────────────────
END_TIME=$(date +%s)
ELAPSED=$(( (END_TIME - START_TIME) / 60 ))

echo ""
echo "================================================================"
echo " COMPLETATO"
echo "================================================================"
echo " Run eseguiti  : $COUNT / $TOTAL"
echo " Run falliti   : $FAILED"
echo " Tempo elapsed : ${ELAPSED} minuti"
echo ""

SAVED=$(ls "$RESULTS_DIR"/*.csv 2>/dev/null | wc -l)
echo " File CSV salvati: $SAVED / $TOTAL"
echo ""

# Mostra sommario per configurazione
echo " Sommario risultati:"
printf " %-14s %-12s %6s %8s %8s\n" "Config" "Scenario" "Succ" "Lat(s)" "CPU%"
echo " $(printf '%0.s-' {1..55})"

for cfg in "${CONFIGS[@]}"; do
    for scenario in "${SCENARIOS[@]}"; do
        # Media delle 3 ripetizioni
        succs=(); lats=(); cpus=()
        for rep in $(seq 1 $REPS); do
            ATK=${ATK_COUNT[$scenario]}
            f="${RESULTS_DIR}/${scenario}_${cfg}_a${ATK}_r${rep}.csv"
            if [ -f "$f" ]; then
                line=$(cat "$f")
                # Formato: fw,scenario,atk,rep,succ,lat,std,N,cpu
                succ=$(echo "$line" | cut -d',' -f5)
                lat=$(echo  "$line" | cut -d',' -f6)
                cpu=$(echo  "$line" | cut -d',' -f9)
                succs+=("$succ"); lats+=("$lat"); cpus+=("$cpu")
            fi
        done
        if [ ${#succs[@]} -gt 0 ]; then
            # Media semplice con awk
            succ_mean=$(printf '%s\n' "${succs[@]}" | \
                awk '{s+=$1;n++}END{printf "%.3f",s/n}')
            lat_mean=$(printf '%s\n' "${lats[@]}" | \
                awk '{s+=$1;n++}END{printf "%.4f",s/n}')
            cpu_mean=$(printf '%s\n' "${cpus[@]}" | \
                awk '{s+=$1;n++}END{printf "%.1f",s/n}')
            printf " %-14s %-12s %6s %8s %8s\n" \
                "$cfg" "$scenario" "$succ_mean" "$lat_mean" "$cpu_mean"
        fi
    done
done

echo ""
echo " Prossimo passo: python3 analyze_extended.py"
echo "================================================================"
