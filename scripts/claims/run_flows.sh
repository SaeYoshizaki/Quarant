#!/bin/bash
# Re-read one YourThings day for the claims check: every flow labelled by
# flowscan.py, and Zeek's conn, ssl and x509 logs (certificate key lengths)
# with tls_records.log (application-data records per side, tls_records.zeek).
# The day's 5-minute files are read as one stream in time order.
# usage: run_flows.sh DAY_DIR OUT_DIR
set -euo pipefail
DAY=$1; OUT=$2
here=$(cd "$(dirname "$0")" && pwd)
acc=$here/../accuracy
files=$(find "$DAY" -type f -name 'eth*' ! -name '._*' | awk -F/ '{print $NF"\t"$0}' | sort -t. -k3,3n | cut -f2)
[ -n "$files" ] || { echo "no capture files under $DAY" >&2; exit 1; }
mkdir -p "$OUT"
cat_day() { python3 -I "$acc/pcapcat.py" $files; }
# read the files once and feed both readers
rm -f "$OUT/zeek.fifo"; mkfifo "$OUT/zeek.fifo"
( cd "$OUT" && zeek -C -r - policy/protocols/conn/mac-logging "$here/tls_records.zeek" LogAscii::use_json=T < zeek.fifo > zeek.stderr 2>&1
  ls *.log | grep -vE '^(conn|ssl|x509|tls_records)\.log$' | xargs rm -f ) &
cat_day | tee "$OUT/zeek.fifo" | python3 -I "$here/flowscan.py" "$here/../../docs/claims/devices.tsv" yourthings - "$OUT/flows.jsonl"
wait
rm -f "$OUT/zeek.fifo"
[ -s "$OUT/flows.jsonl" ] && [ -s "$OUT/ssl.log" ] || { echo "$OUT: missing output" >&2; exit 1; }
echo "$(echo "$files" | wc -l | tr -d ' ') files" > "$OUT/done"
