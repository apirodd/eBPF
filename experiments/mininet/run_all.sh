#!/bin/bash
RATE=50000
DURATION=60
RESULTS_DIR="/home/apirodd/results"
mkdir -p $RESULTS_DIR

run_one() {
    FW=$1 SCENARIO=$2 ATK=$3 REP=$4
    echo ""
    echo ">>> [$(($(ls $RESULTS_DIR/*.csv 2>/dev/null | wc -l)+1))/36] fw=$FW scenario=$SCENARIO attackers=$ATK rep=$REP"
    sudo mn -c 2>/dev/null
    sudo python3 /home/apirodd/run_single_experiment.py \
      $FW $SCENARIO $ATK $RATE $DURATION
    RESULT=$(cat /home/apirodd/last_result.txt 2>/dev/null)
    echo "$FW,$SCENARIO,$ATK,$REP,$RESULT" \
      > $RESULTS_DIR/${SCENARIO}_${FW}_a${ATK}_r${REP}.csv
    echo "    -> $RESULT"
    sleep 5
}

# SINGLE SOURCE (1 attacker)
for REP in 1 2 3; do run_one none     single 1 $REP; done
for REP in 1 2 3; do run_one xdp      single 1 $REP; done
for REP in 1 2 3; do run_one iptables single 1 $REP; done
for REP in 1 2 3; do run_one combined single 1 $REP; done

# DISTRIBUTED (5 attackers)
for REP in 1 2 3; do run_one none     distributed 5 $REP; done
for REP in 1 2 3; do run_one xdp      distributed 5 $REP; done
for REP in 1 2 3; do run_one iptables distributed 5 $REP; done
for REP in 1 2 3; do run_one combined distributed 5 $REP; done

# SPOOFED (5 attackers)
for REP in 1 2 3; do run_one none     spoofed 5 $REP; done
for REP in 1 2 3; do run_one xdp      spoofed 5 $REP; done
for REP in 1 2 3; do run_one iptables spoofed 5 $REP; done
for REP in 1 2 3; do run_one combined spoofed 5 $REP; done

echo ""
echo "=== COMPLETATO ==="
ls $RESULTS_DIR/*.csv | wc -l
echo "file salvati"
