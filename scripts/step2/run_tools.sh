#!/bin/bash
# Step 2: run Quarant, Zeek and Suricata (ET Open) on one capture.
# usage: run_tools.sh QUARANT_BIN RULES_DIR PCAP OUTDIR
#   RULES_DIR holds suricata.rules and classification.config from suricata-update.
# Nothing is sent to any device; Zeek runs without the scripts that query
# external services (see quarant-compare.zeek).
set -u
Q=$1; RULES=$2; pcap=$3; out=$4
here=$(cd "$(dirname "$0")" && pwd)
mkdir -p "$out/quarant" "$out/zeek" "$out/suricata"
t0=$(date +%s)
"$Q" analyze "$pcap" --out "$out/quarant/events.jsonl" > /dev/null 2>&1
t1=$(date +%s)
( cd "$out/zeek" && zeek -C -r "$pcap" "$here/quarant-compare.zeek" LogAscii::use_json=T > zeek.stdout 2> zeek.stderr )
t2=$(date +%s)
suricata -r "$pcap" -S "$RULES/suricata.rules" -l "$out/suricata" -k none \
  --set classification-file="$RULES/classification.config" > "$out/suricata/suricata.stdout" 2>&1
t3=$(date +%s)
echo "quarant $((t1-t0))s zeek $((t2-t1))s suricata $((t3-t2))s" > "$out/timing.txt"
cat "$out/timing.txt"
