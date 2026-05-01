#!/bin/bash
RATE=50000
DURATION=60
RESULTS_DIR="/home/apirodd/results_threshold"
mkdir -p $RESULTS_DIR

run_one() {
    FW=$1 SCENARIO=$2 ATK=$3 THR=$4 REP=$5
    echo ""
    echo ">>> fw=$FW scenario=$SCENARIO thr=$THR rep=$REP"
    sudo mn -c 2>/dev/null
    sudo python3 /home/apirodd/run_threshold_experiment.py \
      $FW $SCENARIO $ATK $RATE $DURATION $THR
    RESULT=$(cat /home/apirodd/last_result.txt 2>/dev/null)
    echo "$FW,$SCENARIO,$ATK,$THR,$REP,$RESULT" \
      > $RESULTS_DIR/${SCENARIO}_${FW}_t${THR}_r${REP}.csv
    echo "    -> $RESULT"
    sleep 5
}

# XDP-only con soglie diverse
# Scenario single (1 attacker) — soglie 50,100,200,500
for THR in 50 100 200 500; do
  for REP in 1 2 3; do
    run_one xdp_t single 1 $THR $REP
  done
done

# Scenario spoofed (5 attackers) — soglie 50,100,200,500
for THR in 50 100 200 500; do
  for REP in 1 2 3; do
    run_one xdp_t spoofed 5 $THR $REP
  done
done

# XDP+SYNPROXY con soglie diverse — solo spoofed
# (il più interessante per la combinazione)
for THR in 50 100 200 500; do
  for REP in 1 2 3; do
    run_one combined_t spoofed 5 $THR $REP
  done
done

echo ""
echo "=== COMPLETATO ==="
ls $RESULTS_DIR/*.csv | wc -l
echo "file salvati"
